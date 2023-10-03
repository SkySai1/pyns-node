import asyncio
import logging
from multiprocessing.managers import DictProxy, ListProxy
from backend.accessdb import AccessDB, enginer
from backend.transfer import Transfer
import dns.message
import dns.rrset
import dns.flags
import dns.name
import dns.rcode
import dns.zone
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring


def fakezone(query:dns.message.Message, zone, soa, ttl):
        response = dns.message.make_response(query)
        record = dns.rrset.from_text(zone,int(ttl),'IN','SOA', soa)
        response.authority.append(record)
        response.flags += dns.flags.AA
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()

def findauth(zdata:dns.zone.Zone, qname:dns.name.Name):
    current = qname
    origin = zdata.origin
    while current >= origin:
        rrauth = zdata.get_rdataset(current,dns.rdatatype.NS)
        if rrauth: break
        current = current.parent()
    return rrauth

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

class Node:
    pass


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
        zone = None
        name = q.name.to_text()
        rdtype = dns.rdatatype.to_text(q.rdtype)
        rdclass = dns.rdataclass.to_text(q.rdclass)
        zones = {}
        rawzones = self.db.GetZones()
        if rawzones:
            for obj in rawzones: zones[obj[0].name] = (obj[1].ttl, obj[1].data)
            for e in zones:
                if q.name.is_subdomain(dns.name.from_text(e)):
                    rawdata = self.db.GetFromDomains(name,rdclass,rdtype,e)
                    if rawdata:
                        data = [(obj[0].ttl, obj[0].data) for obj in rawdata]
                        return data, e, zones[e]
                    return None, e, zones[e]
        return None, None, None

    def get(self, data:bytes, addr:tuple, transport:asyncio.Transport|asyncio.DatagramTransport):
        try:
            key = dns.tsigkeyring.from_text({
            
            })
            q = dns.message.from_wire(data, ignore_trailing=True, keyring=key)
            qname = q.question[0].name
            qclass = q.question[0].rdclass
            qtype = q.question[0].rdtype
            if qtype == 252 and isinstance(transport, asyncio.selector_events._SelectorSocketTransport):
                T = Transfer(self.conf, qname, addr)
                return T.sendaxfr(q,transport), False
            node, zone, soa = Authority.findnode(self,q.question[0])
            if not zone: return None, False
            r = dns.message.make_response(q)
            q.flags += dns.flags.AA
            if not node:
                r.authority.append(
                    dns.rrset.from_text_list(zone, soa[0], dns.rdataclass.IN, dns.rdatatype.SOA ,soa[1])
                )
            return None, False
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