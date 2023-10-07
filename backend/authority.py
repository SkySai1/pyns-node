import asyncio
import logging
from multiprocessing.managers import DictProxy, ListProxy
from backend.accessdb import AccessDB, enginer
from backend.functions import echo, toobig
from backend.transfer import Transfer
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


def findrdataset(auth:DictProxy, zones:ListProxy, qname:dns.name.Name, rdtype:dns.rdatatype):
    rrset = None
    for e in zones:
        if qname.is_subdomain(dns.name.from_text(e)):
            zone = e
            break
    if zone:
        zdata = auth.get(zone)
        if zdata:
            rrset = zdata.get_rdataset(qname,rdtype)
    return qname, rrset  

class Authority:

    def __init__(self, conf, auth:DictProxy, zones:ListProxy):
        try:
            self.conf = conf
            self.auth = auth
            self.zones = zones
        except:
            logging.critical('initialization of authority module is fail')
    
    def connect(self, engine):
        self.db = AccessDB(engine, self.conf)


    def findnode(self, q:dns.rrset.RRset):
        name = q.name.to_text()
        rdtype = dns.rdatatype.to_text(q.rdtype)
        rdclass = dns.rdataclass.to_text(q.rdclass)
        zones = []
        rawzones = self.db.GetZones(name.split("."))
        if rawzones:
            for obj in rawzones: zones.append(obj[0].name)
            zones.sort()
            zones.reverse()
            for e in zones:
                if q.name.is_subdomain(dns.name.from_text(e)):
                    auth, state = Authority.findauth(self,q.name.to_text(),e)
                    rawdata = self.db.GetFromDomains(qname=name,rdclass=rdclass,rdtype=rdtype,zone=e)
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

    def filling(self, data, qtype=None):
        content = []
        for a in data:
            if not qtype or a.type == dns.rdatatype.to_text(qtype):
                content.append(
                    dns.rrset.from_text_list(a.name, a.ttl, a.cls, a.type, a.data)
                )                   
        return content
    
    def findcname(self,name:str,qtype:str, search:list=[]):
        rawdata = self.db.GetFromDomains(qname=name, rdtype=[qtype, 'CNAME'])
        if rawdata:
            for obj in rawdata:
                row = obj[0]
                #print(row.name, row.type, row.data)
                if row.type == 'CNAME':
                    search.append(row)
                    search = Authority.findcname(self,row.data[0],qtype, search)
                else:
                    if row.type == qtype:
                        search.append(row)
            return search
        elif search:
            pass
            #print(search[-1].name)
        return search

    def get(self, data:bytes, addr:tuple, transport:asyncio.Transport|asyncio.DatagramTransport):
        try:
            key = dns.tsigkeyring.from_text({
                "tinirog-waramik": "302faOimRL7J6y7AfKWTwq/346PEynIqU4n/muJCPbs="
            })
            q = dns.message.from_wire(data, ignore_trailing=True, keyring=key)
            qname = q.question[0].name
            qtype = q.question[0].rdtype
            if qtype == 252 and isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                try:
                    T = Transfer(self.conf, qname, addr, key, q.keyname, q.keyalgorithm)
                    return T.sendaxfr(q,transport), False
                except:
                    logging.error('Sending transfer was failed')
                    return echo(data,dns.rcode.SERVFAIL)
            node, zone, auth, state = Authority.findnode(self,q.question[0])
            if not zone: return None, False
            r = dns.message.make_response(q)
            if state is True:
                r.flags += dns.flags.AA
                if node:
                    r.answer = Authority.filling(self,node,qtype)
                else:
                    data = Authority.findcname(self,qname.to_text(), dns.rdatatype.to_text(qtype), [])
                    if state is True:
                        for row in data:
                            r.answer.append(
                                dns.rrset.from_text_list(row.name, row.ttl, row.cls, row.type, row.data)
                            )
                    else:
                        r.authority = Authority.filling(self,auth)
                if not r.answer and not r.authority:
                    r.set_rcode(dns.rcode.NXDOMAIN)
                    r = Authority.fakezone(self,q,zone)
            else:
                targets = []
                r.authority = Authority.filling(self,auth)                  
                targets = [ns for a in auth for ns in a.data]
                if targets:
                    add = Authority.findadd(self,targets)
                    r.additional = Authority.filling(self,add)
            try:
                return r.to_wire(), True
            except dns.exception.TooBig:
                if isinstance(transport,asyncio.selector_events._SelectorDatagramTransport):
                    r = echo(data,flags=[dns.flags.TC])
                    return r.to_wire(), True
                elif isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                    return r.to_wire(max_size=65535), True
            
        except:
            logging.error('get data from local zones is fail', exc_info=True)
            return echo(q,dns.rcode.SERVFAIL).to_wire(), False

    def download(self, db:AccessDB):
        # --Getting all records from cache tatble
        try:
            [self.zones.pop(0) for i in range(self.zones.__len__())]
            [self.zones.append(obj[0].name) for obj in db.getZones()]
            self.zones.sort()
            self.zones.reverse()
        except:
            logging.error('making local zones data is fail', exc_info=True)