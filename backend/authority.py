import asyncio
import logging
from multiprocessing.managers import DictProxy, ListProxy
from backend.accessdb import AccessDB
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

def findnode(auth:DictProxy, zones:ListProxy, qname:dns.name.Name) :
    zone = None
    node = None
    zdata = None
    for e in zones:
        if qname.is_subdomain(dns.name.from_text(e)):
            zone = e
            break
    if zone:
        zdata = auth.get(zone)
        if zdata:
            node = zdata.get_node(qname)
    return node, zdata

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
            node, zdata = findnode(self.auth, self.zones, qname)
            if zdata:
                r = dns.message.make_response(q)
                r.flags += dns.flags.AA
                if node:
                    rrset_an = node.get_rdataset(qclass,qtype)
                    rrset_au = findauth(zdata, qname)
                    if rrset_an:
                        answer = dns.rrset.from_rdata_list(qname,rrset_an.ttl,rrset_an)
                        r.answer.append(answer)
                    elif qtype == 1:
                        answer = None
                        stop = False
                        while stop is False:
                            if not node: break
                            for rrset in node:
                                if rrset.rdtype is dns.rdatatype.A:
                                    answer = dns.rrset.from_rdata_list(qname,rrset.ttl,rrset)
                                    stop = True
                                    break
                                if rrset.rdtype is dns.rdatatype.CNAME:
                                    answer = dns.rrset.from_rdata_list(qname,rrset.ttl,rrset)
                                    qname = rrset[0].to_text()
                                    node, _ = findnode(self.auth, self.zones, dns.name.from_text(qname))
                                    break
                            if not answer: break
                            else: r.answer.append(answer)
                    if r.answer:
                        if rrset_au:
                            authority = dns.rrset.from_rdata_list(qname,rrset_au.ttl,rrset_au)
                            r.authority.append(authority)
                            rrset_ad_list = [findrdataset(self.auth, self.zones, dns.name.from_text(data.to_text()), dns.rdatatype.A) for data in rrset_au]
                            for rrset in rrset_ad_list:
                                if rrset[1]:
                                    additional = dns.rrset.from_rdata_list(rrset[0],rrset[1].ttl, rrset[1])
                                    r.additional.append(additional) 
                        return r.to_wire(), True
                rrset_au = zdata.get_rdataset(zdata.origin, dns.rdatatype.SOA)
                authority = dns.rrset.from_rdata_list(zdata.origin,rrset_au.ttl,rrset_au)
                r.set_rcode(dns.rcode.NXDOMAIN)
                r.authority.append(authority)
                return r.to_wire(), True
            return None, True
        except:
            logging.error('get data from local zones is fail')
            return data, False

    def download(self, engine):
        db = AccessDB(engine, self.conf)
        # --Getting all records from cache tatble
        try:
            [self.zones.pop(0) for i in range(self.zones.__len__())]
            [self.zones.append(obj[0].name) for obj in db.getZones()]
            self.zones.sort()
            self.zones.reverse()
            zones = set(self.zones)
            zonedata = {}
            for zone in zones:
                zonedata[zone] = []
                rawdata = db.GetFromDomains(zone=zone)
                [zonedata[zone].append((str(obj[0].name), str(obj[0].ttl), str(obj[0].dclass), str(obj[0].type), str(obj[0].data[0]))) for obj in rawdata]
                self.auth[zone] = dns.zone.from_text("\n".join([" ".join(data) for data in zonedata[zone]]), dns.name.from_text(zone), relativize=False)
            for e in set(self.auth.keys()) ^ zones: self.auth.pop(e)
        except:
            logging.error('making local zones data is fail')