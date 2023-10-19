import asyncio
import logging
from multiprocessing.managers import DictProxy, ListProxy
import random
import re
from backend.accessdb import AccessDB, enginer
from backend.functions import echo
from backend.transfer import Transfer
from backend.recursive import Recursive, Depth, _ROOT
from backend.objects import Packet
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

    def filling(self, data, qtype:str|list=None):
        if isinstance(qtype,str): qtype = [qtype]
        content = []
        for a in data:
            if not qtype or a.type in qtype:
                content.append(
                    dns.rrset.from_text_list(a.name, a.ttl, a.cls, a.type, a.data)
                )              
        return content
    
    def signer(self, data, zone):
        types = {}
        for rrset in data:
            name = rrset.name.to_text()
            if name not in types: types[name] = set()
            types[name].add(dns.rdatatype.to_text(rrset.rdtype))
        for name in list(types.keys()):
            rawdata = self.db.GetFromDomains(name,rdtype='RRSIG',zone=zone)
            for obj in rawdata:
                a = obj[0]
                rdata = str(a.data[0]).split(' ')
                if rdata[0] in types[name]:
                    data.append(
                        dns.rrset.from_text_list(a.name, a.ttl, a.cls, a.type, a.data)
                    )


    def findcname(self, cname:str|dns.name.Name, qtype:str|dns.rdatatype.RdataType, qcls:str|dns.rdataclass.RdataClass=dns.rdataclass.IN, transport=None, P:Packet=None): 
        q = dns.message.make_query(cname,qtype,qcls)
        if P and P.check.recursive():
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
            for i in range(3):
                try:
                    if i > 1:
                        r = echo(data,dns.rcode.REFUSED)
                        return r.to_wire(), r, True
                    
                    P.query = dns.message.from_wire(data, ignore_trailing=True, keyring=keyring)
                    break
                except dns.message.UnknownTSIGKey:
                    name = dns.name.from_wire(data,12)[0]
                    keyring = dns.tsigkeyring.from_text(self.db.GetTsig(name.to_text()))
                    continue
            qname = P.query.question[0].name
            qtype = dns.rdatatype.to_text(P.query.question[0].rdtype)
            qclass = dns.rdataclass.to_text(P.query.question[0].rdclass)
            if P.query.ednsflags == dns.flags.DO: DO = True
            else: DO = False
            if P.query.had_tsig and qtype == 'AXFR' and isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                try:
                    T = Transfer(self.CONF, qname, addr, keyring, P.query.keyname, P.query.keyalgorithm)
                    result = T.sendaxfr(P.query,transport)
                    return result, None, False
                except:
                    logging.error('Sending transfer was failed', exc_info=(logging.DEBUG >= logging.root.level))
                    r = echo(data,dns.rcode.SERVFAIL)
                    return r.to_wire(), r, True
            node, zone, auth, state, sign = self.findnode(qname, qclass)
            if not zone: return None, None, False
            r = dns.message.make_response(P.query)
            if state is not None:
                if state is True:
                    r.flags += dns.flags.AA
                    if node:
                        r.answer = self.filling(node,[qtype, 'CNAME'])
                        if r.answer and qtype != 'CNAME':
                            while r.answer[-1].rdtype is dns.rdatatype.CNAME:
                                cname = dns.name.from_text(r.answer[-1][0].to_text())
                                crdclass = dns.rdataclass.to_text(r.answer[-1].rdclass)
                                cnode, zone, auth, state, _ = self.findnode(cname, crdclass)
                                if cnode:
                                    if state:
                                        r.answer += self.filling(cnode, [qtype, 'CNAME'])
                                    else:
                                        break
                                elif isrec:
                                    r.answer += self.findcname(cname, qtype, qclass, transport, P)  
                                    break 
                                else:
                                    break
                    if not r.answer and not r.authority:
                        r.set_rcode(dns.rcode.NXDOMAIN)
                        r = self.fakezone(P.query,zone)
                if state is False and auth:
                    targets = []
                    r.authority = self.filling(auth,qtype=None)                  
                    targets = [ns for a in auth for ns in a.data]
                    if targets:
                        add = self.findadd(targets)
                        r.additional = self.filling(add)
            try:
                if (sign and DO):
                    self.signer(r.answer, zone)
                    self.signer(r.authority, zone)
                    self.signer(r.additional, zone)
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
            r = echo(P.query,dns.rcode.SERVFAIL)
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