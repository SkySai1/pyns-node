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


def fakezone(query:dns.message.Message, zone, soa, ttl):
        response = dns.message.make_response(query)
        record = dns.rrset.from_text(zone,int(ttl),'IN','SOA', soa)
        response.authority.append(record)
        response.flags += dns.flags.AA
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()

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
        zones = {}
        rawzones = self.db.GetZones()
        if rawzones:
            for obj in rawzones: zones[obj[0].name] = (obj[1].ttl, obj[1].data)
            for e in zones:
                if q.name.is_subdomain(dns.name.from_text(e)):
                    rawdata = self.db.GetFromDomains(qname=name,rdclass=rdclass,zone=e)
                    if rawdata:
                        node = [obj[0] for obj in rawdata]
                        return node, e, zones[e]
                    return None, e, zones[e]
        return None, None, None

    def findauth(self, q:dns.rrset.RRset, zone):
        name = q.name.to_text()
        rawdata = self.db.GetFromDomains(qname=name,zone=zone)
        if rawdata:
            for obj in rawdata:
                print(obj[0].name, obj[0].type, obj[0].data)
        return None

    def get(self, data:bytes, addr:tuple, transport:asyncio.Transport|asyncio.DatagramTransport):
        try:
            key = dns.tsigkeyring.from_text({
            
            })
            q = dns.message.from_wire(data, ignore_trailing=True, keyring=key)
            qname = q.question[0].name
            qtype = q.question[0].rdtype
            if qtype == 252 and isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                T = Transfer(self.conf, qname, addr)
                return T.sendaxfr(q,transport), False
            node, zone, soa = Authority.findnode(self,q.question[0])
            if not zone: return None, False
            r = dns.message.make_response(q)
            r.flags += dns.flags.AA
            if not node:
                r.authority.append(
                    dns.rrset.from_text_list(zone, soa[0], dns.rdataclass.IN, dns.rdatatype.SOA ,soa[1])
                )
            else:
                for record in node:
                    if record.type == dns.rdatatype.to_text(qtype):
                        r.answer.append(
                            dns.rrset.from_text_list(record.name, record.ttl, record.cls, record.type, record.data )
                        )
                #auth = Authority.findauth(self, q.question[0], zone)
            try:
                result = r.to_wire()
            except dns.exception.TooBig:
                if isinstance(transport,asyncio.selector_events._SelectorDatagramTransport):
                    r = echo(data,flags=[dns.flags.TC])
                    return r.to_wire(), False
                elif isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                    return r.to_wire(max_size=65535), True
            return r.to_wire(), False
        except:
            logging.error('get data from local zones is fail', exc_info=True)
            return data, False

    def download(self, db:AccessDB):
        # --Getting all records from cache tatble
        try:
            [self.zones.pop(0) for i in range(self.zones.__len__())]
            [self.zones.append(obj[0].name) for obj in db.getZones()]
            self.zones.sort()
            self.zones.reverse()
        except:
            logging.error('making local zones data is fail', exc_info=True)