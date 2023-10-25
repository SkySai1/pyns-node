from asyncio.selector_events import _SelectorSocketTransport as TCP
import logging
from multiprocessing.managers import DictProxy, ListProxy
import random
import re
from backend.accessdb import AccessDB, enginer
from backend.functions import echo
from backend.transfer import Transfer
from backend.recursive import Recursive, Depth, _ROOT
from backend.objects import Query
import time
import dns.message
import dns.rrset
import dns.flags
import dns.name
import dns.rcode
import dns.zone
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring
import dns.query
import dns.renderer
import dns.tsig
import dns.dnssec


class Authority:
    db = None

    def __init__(self, _CONF, _rec:Recursive, auth:DictProxy, zones:ListProxy):
        try:
            self.CONF = _CONF
            self.recursive = _rec
            self.auth = auth
            self.zones = zones
        except:
            logging.critical('initialization of authority module is fail', exc_info=(logging.DEBUG >= logging.root.level))
    
    def connect(self, db:AccessDB):
        self.db = db

    def get_zone(self, name:str|dns.message.Message):
        if isinstance(name, dns.name.Name):
            name = name.to_text().lower()
        else:
            name = name.lower()
        zones = {}
        sign = zone = None
        rawzones = self.db.GetZones(name.split("."))
        if rawzones:
            for obj in rawzones: zones[obj[0].name] = obj[0].signed
            zonelist = list(zones.keys())
            zonelist.sort()
            zonelist.reverse()
            for e in zones:
                if e in name:
                    sign = zones[e]
                    zone = e
        return zone, sign
                        
    def get_node(self, qname:dns.name.Name|str, rdclass:str=None):
        node = []
        sign = zone = None
        if isinstance(qname, dns.name.Name):
            name = qname.to_text().lower()
        else:
            name = qname.lower()
        zone, sign = self.get_zone(name)
        rawdata = self.db.GetFromDomains(qname=name,rdclass=rdclass, zone=zone, sign=sign)
        if rawdata: node = [obj[0] for obj in rawdata]
        return node, zone, sign

    def fakezone(self, r:dns.message.Message, zone):
            r.set_rcode(dns.rcode.NXDOMAIN)
            rawdata = self.db.GetFromDomains(qname=zone,rdclass='IN', rdtype='SOA',zone=zone)
            if rawdata:
                soa = rawdata[0][0].data[-1]
                ttl = rawdata[0][0].ttl
                record = dns.rrset.from_text(zone,int(ttl),'IN','SOA', soa)
                r.authority.append(record)

    def check_auth(self, qname:dns.name.Name|str, zone, result:dns.message.Message, sign:bool=False):
        if isinstance(qname, dns.name.Name):
            name = qname.to_text().lower()
        else:
            name = qname.lower()
        rdtype = 'NS'
        rawdata = self.db.GetFromDomains(qname=name,rdtype=rdtype,zone=zone, decomposition=True, sign=sign)
        auth=[]
        high = ''
        state = True
        if rawdata:
            for obj in rawdata:
                if len(obj[0].name) >= len(high):
                    high = obj[0].name
            for obj in rawdata:
                if obj[0].name == high or (obj[0].name == name):
                    auth.append(obj[0])
        if sign:
            keys = []
            for a in auth:
                rawdata = self.db.GetFromDomains(qname=a.name, rdtype='NSEC', sign=sign)
                if rawdata: [keys.append(obj[0]) for obj in rawdata]
            auth += keys
        if high != zone: 
            state = False
            if sign: qtype = ['NS', 'NSEC']
            else: qtype = 'NS'
            result.authority = self.filling(auth,qtype=qtype)
            targets = [ns for a in auth for ns in a.data]
            if targets:
                add = self.additional(targets)
                result.additional = self.filling(add)
        return state

    def filling(self, data, qname:dns.name.Name=None, qtype:str|list=None):

        if isinstance(qtype,str): qtype = [qtype]
        content = []
        for a in data:
            if not qtype or a.type in qtype:
                if not qname: qname = dns.name.from_text(a.name)
                content.append(
                    dns.rrset.from_text_list(qname, a.ttl, a.cls, a.type, a.data)
                )       
        return content
    
    def additional(self, targets:list):
        rawdata = self.db.GetFromDomains(qname=targets,rdtype='A')
        if rawdata:
            add = []
            for obj in rawdata:
                add.append(obj[0])
        return add    
    
    def cname_lookup(self, Q:Query, result:dns.message.Message, qname, qtype, qclass, DO:bool): 
        if Q.check.recursive():
            if DO: DO = dns.flags.DO
            q = dns.message.make_query(qname,qtype,qclass,ednsflags=DO)
            for i in range(3):
                try:
                    D = Depth()
                    res, _ = self.recursive.resolve(q, random.choice(_ROOT), Q.transport, D)
                    break
                except:
                    pass
            if res:
                result.answer += res.answer

    def signer(self, data):
        types = {}
        for rrset in data:
            name = rrset.name.to_text()
            if name not in types: types[name] = set()
            types[name].add(dns.rdatatype.to_text(rrset.rdtype))
        for name in list(types.keys()):
            zone, sign = self.get_zone(name)
            if zone and sign:
                rawdata = self.db.GetFromDomains(name,rdtype='RRSIG',zone=zone, sign=True)
                for obj in rawdata:
                    a = obj[0]
                    rdata = str(a.data[0]).split(' ')
                    if rdata[0] in types[name]:
                        data.append(
                            dns.rrset.from_text_list(a.name, a.ttl, a.cls, a.type, a.data)
                        )

    def get(self, Q:Query):
        try:
            result = None
            keys = {}
            keyname = None
            qname = Q.name
            qtype = dns.rdatatype.to_text(Q.qtype)
            qclass = dns.rdataclass.to_text(Q.qclass)
            for i in range(2):
                try:
                    Q.query = q = dns.message.from_wire(Q.data, ignore_trailing=True, keyring=keys)              
                    break
                except dns.message.UnknownTSIGKey:
                    keys = dns.tsigkeyring.from_text(self.db.GetTsig(qname.lower()))
                    if i > 0:
                        result = echo(Q.data, dns.rcode.REFUSED)
                        return result.to_wire(), result
                except:
                    logging.error('Query is malformed', exc_info=(logging.DEBUG >= logging.root.level))
                    return None, None
         
            if qtype == 'AXFR':
                if isinstance(Q.transport, TCP):
                    T = Transfer(self.CONF, qname, tsig=keys, keyname=keyname)
                    result = T.sendaxfr(q, Q.transport)
            else:
                if q.ednsflags == dns.flags.DO: DO = True
                else: DO = False
                result = self.authority(Q, qname, qtype, qclass, dns.message.make_response(q), DO)
                if DO and result:
                    self.signer(result.answer)
                    self.signer(result.authority)
                    self.signer(result.additional)   
                    result.use_edns(0,dns.flags.DO)            
        except:
            logging.error('Get data from local zones is fail.', exc_info=(logging.DEBUG >= logging.root.level))
            result = echo(Q.data, dns.rcode.SERVFAIL)
        finally:
            if isinstance(result, dns.message.Message):
                return result.to_wire(max_size=65535), result
            elif isinstance(result, bytes):
                return result, None
            else:
                return None, None


    def authority(self, Q:Query, qname:dns.name.Name, qtype, qclass, result:dns.message.Message, DO:bool=False):
        
        node, zone, sign = self.get_node(qname, qclass)
        if zone:
            if not dns.flags.AA in result.flags:
                result.flags = dns.flags.Flag(sum([result.flags, dns.flags.AA]))
            if node:
                if self.check_auth(qname, zone, result, (DO and sign)) is False:
                    pass
                elif 'CNAME' in [rr.type for rr in node]:
                    for rr in node:
                        if rr.type == 'CNAME' and type(rr.data) is list:
                            canonical = dns.name.from_text(rr.data[-1])
                            [result.answer.append(rr) for rr in self.filling(node, qname, 'CNAME')]
                            czone, _ = self.get_zone(canonical)
                            if czone:
                                self.authority(Q, canonical, qtype, qclass, result, DO)
                            else:
                                self.cname_lookup(Q, result, canonical, qtype, qclass, DO)
                else:
                    [result.answer.append(rr) for rr in self.filling(node, qname, qtype)]
            else:
                self.fakezone(result, zone)
            return result
        else:
            return None
        
    '''def download(self, db:AccessDB):
        # --Getting all records from cache tatble
        try:
            [self.zones.pop(0) for i in range(self.zones.__len__())]
            [self.zones.append(obj[0].name) for obj in db.getZones()]
            self.zones.sort()
            self.zones.reverse()
        except:
            logging.error('making local zones data is fail', exc_info=True)'''