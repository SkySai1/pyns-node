import asyncio
import logging
from multiprocessing.managers import DictProxy, ListProxy
import random
from backend.accessdb import AccessDB, enginer
from backend.functions import echo
from backend.transfer import Transfer
from backend.recursive import Recursive, Depth, _ROOT
from backend.packet import Packet
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

    def __init__(self, conf, _rec:Recursive, auth:DictProxy, zones:ListProxy):
        try:
            self.conf = conf
            self.recursive = _rec
            self.auth = auth
            self.zones = zones
        except:
            logging.critical('initialization of authority module is fail', exc_info=(logging.DEBUG >= logging.root.level))
    
    def connect(self, db:AccessDB):
        self.db = db


    def findnode(self, qname:dns.name.Name, rdclass:str):
        name = qname.to_text()
        zones = {}
        rawzones = self.db.GetZones(name.split("."))
        if rawzones:
            for obj in rawzones: zones[obj[0].name] = obj[0].signed
            zonelist = list(zones.keys())
            zonelist.sort()
            zonelist.reverse()
            for e in zones:
                sign = zones[e]
                if qname.is_subdomain(dns.name.from_text(e)):
                    auth, state = self.findauth(qname.to_text(),e)
                    rawdata = self.db.GetFromDomains(qname=name,rdclass=rdclass, zone=e)
                    if rawdata:
                        node = [obj[0] for obj in rawdata]
                        '''if sign:
                            rawkey = self.db.GetFromDomains(qname=e,rdtype='DNSKEY', zone=e)
                            print(rawkey[0][0].data)'''
                    else: node = None
                    return node, e, auth, state, sign
        return None, None, None, None, None

    def findauth(self, name:str, zone):
        rawdata = self.db.GetFromDomains(qname=name,rdtype='NS',zone=zone, decomposition=True)
        auth=[]
        high = ''
        state = True
        if rawdata:
            for obj in rawdata:
                if len(obj[0].name) >= len(high):
                    high = obj[0].name
            for obj in rawdata:
                if obj[0].name == high:
                    auth.append(obj[0])
        if high != zone: state = False
        return auth, state
    
    def findadd(self, targets:list):
        rawdata = self.db.GetFromDomains(qname=targets,rdtype='A')
        if rawdata:
            add = []
            for obj in rawdata:
                add.append(obj[0])
        return add

    def fakezone(self, query:dns.message.Message, zone):
            response = dns.message.make_response(query)
            rawdata = self.db.GetFromDomains(qname=zone,rdclass='IN', rdtype='SOA',zone=zone)
            if rawdata:
                soa = rawdata[0][0].data[-1]
                ttl = rawdata[0][0].ttl
                record = dns.rrset.from_text(zone,int(ttl),'IN','SOA', soa)
                response.authority.append(record)
                response.set_rcode(dns.rcode.NXDOMAIN)
            return response

    def filling(self, data, qtype:str|list=None, sign:bool=False):
        if isinstance(qtype,str): qtype = [qtype]
        content = []
        for a in data:
            if not qtype or a.type in qtype:
                content.append(
                    dns.rrset.from_text_list(a.name, a.ttl, a.cls, a.type, a.data)
                )   
        contypes = [dns.rdatatype.to_text(a.rdtype) for a in content]
        if sign and not 'CNAME' in contypes:
            for a in data:
                if a.type == 'RRSIG':
                    if str(a.data[0]).split(' ')[0] in contypes:
                        content.append(
                            dns.rrset.from_text_list(a.name, a.ttl, a.cls, a.type, a.data)
                        )
        '''if a.type == 'NSEC':
                    if set(str(a.data[0]).split(' ')).intersection(set(qtype)):
                        print(a.type, a.data)'''              
        return content
    
    def findcname(self, cname:str|dns.name.Name, qtype:str|dns.rdatatype.RdataType, qcls:str|dns.rdataclass.RdataClass=dns.rdataclass.IN, transport=None):
        q = dns.message.make_query(cname,qtype,qcls)
        for i in range(3):
            try:
                depth = Depth()
                ns = random.choice(_ROOT)
                r, _ = self.recursive.resolve(q, ns, transport, depth)
                if r:
                    return r.answer
            except:
                i+=1
        return []

    def get(self, P:Packet):
        try:
            data = P.data
            addr = P.addr
            transport = P.transport
            isrec = True
            keyring = None
            for i in range(2):
                try:
                    if i > 1:
                        r = echo(data,dns.rcode.REFUSED)
                        return r.to_wire(), r, True
                    q = dns.message.from_wire(data, ignore_trailing=True, keyring=keyring)
                    break
                except dns.message.UnknownTSIGKey:
                    name = dns.name.from_wire(data,12)[0]
                    keyring = dns.tsigkeyring.from_text(self.db.GetTsig(name.to_text()))
                    continue

            qname = q.question[0].name
            qtype = dns.rdatatype.to_text(q.question[0].rdtype)
            qclass = dns.rdataclass.to_text(q.question[0].rdclass)
            if q.ednsflags == dns.flags.DO: DO = True
            else: DO = False
            if q.had_tsig and qtype == 'AXFR' and isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                try:

                    T = Transfer(self.conf, qname, addr, keyring, q.keyname, q.keyalgorithm)
                    result = T.sendaxfr(q,transport)
                    if not result: raise Exception()
                    return result, None, False
                except:
                    logging.error('Sending transfer was failed', exc_info=(logging.DEBUG >= logging.root.level))
                    r = echo(data,dns.rcode.SERVFAIL)
                    return r.to_wire(), r, True
            node, zone, auth, state, sign = self.findnode(qname, qclass)
            if not zone: return None, None, False
            r = dns.message.make_response(q)
            if state is not None:
                if state is True:
                    r.flags += dns.flags.AA
                    if node:
                        r.answer = self.filling(node,[qtype, 'CNAME'], (sign and DO))
                        if r.answer and qtype != 'CNAME':
                            while r.answer[-1].rdtype is dns.rdatatype.CNAME:
                                cname = dns.name.from_text(r.answer[-1][0].to_text())
                                crdclass = dns.rdataclass.to_text(r.answer[-1].rdclass)
                                cnode, zone, auth, state, sign = self.findnode(cname, crdclass)
                                if cnode:
                                    if state:
                                        r.answer += self.filling(cnode, [qtype, 'CNAME'])
                                    else:
                                        break
                                elif isrec:
                                    r.answer += self.findcname(cname, qtype, qclass, transport)  
                                    break 
                                else:
                                    break
                    if not r.answer and not r.authority:
                        r.set_rcode(dns.rcode.NXDOMAIN)
                        r = self.fakezone(q,zone)
                if state is False and auth:
                    targets = []
                    r.authority = self.filling(auth,qtype=None)                  
                    targets = [ns for a in auth for ns in a.data]
                    if targets:
                        add = self.findadd(targets)
                        r.additional = self.filling(add)
            try:
                if (sign and DO):
                    r.use_edns(0,dns.flags.DO)
                return r.to_wire(), r, True
            except dns.exception.TooBig:
                if isinstance(transport,asyncio.selector_events._SelectorDatagramTransport):
                    r = echo(data,flags=[dns.flags.TC])
                    return r.to_wire(), r, True
                elif isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                    return r.to_wire(max_size=65535), r, True
            
        except:
            logging.error('get data from local zones is fail', exc_info=(logging.DEBUG >= logging.root.level))
            r = echo(q,dns.rcode.SERVFAIL)
            return r.to_wire(), r, True

    '''def download(self, db:AccessDB):
        # --Getting all records from cache tatble
        try:
            [self.zones.pop(0) for i in range(self.zones.__len__())]
            [self.zones.append(obj[0].name) for obj in db.getZones()]
            self.zones.sort()
            self.zones.reverse()
        except:
            logging.error('making local zones data is fail', exc_info=True)'''