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


class Authority:
    db = None

    def __init__(self, conf, _rec:Recursive, auth:DictProxy, zones:ListProxy):
        try:
            self.conf = conf
            self.recursive = _rec
            self.auth = auth
            self.zones = zones
        except:
            logging.critical('initialization of authority module is fail')
    
    def connect(self, db:AccessDB):
        self.db = db


    def findnode(self, qname:dns.name.Name, rdclass:str):
        name = qname.to_text()
        zones = []
        rawzones = self.db.GetZones(name.split("."))
        if rawzones:
            for obj in rawzones: zones.append(obj[0].name)
            zones.sort()
            zones.reverse()
            for e in zones:
                if qname.is_subdomain(dns.name.from_text(e)):
                    auth, state = self.findauth(qname.to_text(),e)
                    rawdata = self.db.GetFromDomains(qname=name,rdclass=rdclass, zone=e)
                    if rawdata:
                        node = [obj[0] for obj in rawdata]
                    else: node = None
                    return node, e, auth, state
        return None, None, None, None

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
            key = dns.tsigkeyring.from_text({
                "tinirog-waramik": "302faOimRL7J6y7AfKWTwq/346PEynIqU4n/muJCPbs="
            })
            q = dns.message.from_wire(data, ignore_trailing=True, keyring=key)
            qname = q.question[0].name
            qtype = dns.rdatatype.to_text(q.question[0].rdtype)
            qclass = dns.rdataclass.to_text(q.question[0].rdclass)
            if qtype == 'AXFR' and isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                try:
                    T = Transfer(self.conf, qname, addr, key, q.keyname, q.keyalgorithm)
                    result = T.sendaxfr(q,transport)
                    if not result: raise Exception()
                    return result, None, False
                except:
                    logging.error('Sending transfer was failed')
                    return echo(data,dns.rcode.SERVFAIL)
            node, zone, auth, state = self.findnode(qname, qclass)
            if not zone: return None, None, False
            r = dns.message.make_response(q)
            if state is not None:
                if state is True:
                    r.flags += dns.flags.AA
                    if node:
                        #for e in node: print(e.name, e.type, e.data)
                        r.answer = self.filling(node,[qtype, 'CNAME'])
                        if r.answer and qtype != 'CNAME':
                            while r.answer[-1].rdtype is dns.rdatatype.CNAME:
                                cname = dns.name.from_text(r.answer[-1][0].to_text())
                                crdclass = dns.rdataclass.to_text(r.answer[-1].rdclass)
                                cnode, zone, auth, state = self.findnode(cname, crdclass)
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
                    r.authority = self.filling(auth)                  
                    targets = [ns for a in auth for ns in a.data]
                    if targets:
                        add = self.findadd(targets)
                        r.additional = self.filling(add)
            try:
                return r.to_wire(), r, True
            except dns.exception.TooBig:
                if isinstance(transport,asyncio.selector_events._SelectorDatagramTransport):
                    r = echo(data,flags=[dns.flags.TC])
                    return r.to_wire(), r, True
                elif isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                    return r.to_wire(max_size=65535), r, True
            
        except:
            logging.error('get data from local zones is fail', exc_info=True)
            return echo(q,dns.rcode.SERVFAIL).to_wire(), False

    '''def download(self, db:AccessDB):
        # --Getting all records from cache tatble
        try:
            [self.zones.pop(0) for i in range(self.zones.__len__())]
            [self.zones.append(obj[0].name) for obj in db.getZones()]
            self.zones.sort()
            self.zones.reverse()
        except:
            logging.error('making local zones data is fail', exc_info=True)'''