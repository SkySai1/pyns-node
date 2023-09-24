import logging
from multiprocessing.managers import DictProxy, ListProxy
import re
from sqlalchemy import create_engine
from backend.accessdb import AccessDB
from backend.caching import packing
import dns.message
import dns.rrset
import dns.flags
import dns.name
import dns.rcode
import dns.zone
import dns.rdataclass
import dns.rdatatype
try: from backend.cparser import parser
except: from backend.parser import parser


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

class Authority:

    def __init__(self, conf, auth:DictProxy, zones:ListProxy):
        self.conf = conf
        self.auth = auth
        self.zones = zones

    def findnode(self, qname):
        zone = None
        node = None
        zdata = None
        for e in self.zones:
            #print(e,qname)
            #if re.match(f".*{re.escape(e)}$", qname.to_text()):
            if qname.is_subdomain(dns.name.from_text(e)):
                zone = e
                break
        if zone:
            zdata = self.auth.get(zone)
            if zdata:
                node = zdata.get_node(qname)
        return node, zdata

    def findrdataset(self, qname, rdtype):
        rrset = None
        for e in self.zones:
            if qname.is_subdomain(dns.name.from_text(e)):
                zone = e
                break
        if zone:
            zdata = self.auth.get(zone)
            if zdata:
                rrset = zdata.get_rdataset(qname,rdtype)
                #print(zdata.get_rdataset(dns.name.from_text('ns1.tinirog.ru.'), dns.rdatatype.A))
        return qname, rrset      

    def get(self, data:bytes):
        try:
            q = dns.message.from_wire(data)
            qname = q.question[0].name
            qclass = q.question[0].rdclass
            qtype = q.question[0].rdtype
            node, zdata = Authority.findnode(self,qname)
            if zdata:
                r = dns.message.make_response(q)
                r.flags += dns.flags.AA
                if node:
                    rrset_an = node.get_rdataset(qclass,qtype)
                    rrset_au = findauth(zdata, qname)

                    if rrset_an:
                        answer = dns.rrset.from_rdata_list(qname,rrset_an.ttl,rrset_an)
                        r.answer.append(answer)
                    if rrset_au:
                        authority = dns.rrset.from_rdata_list(qname,rrset_au.ttl,rrset_au)
                        r.authority.append(authority)
                        rrset_ad_list = [Authority.findrdataset(self, dns.name.from_text(data.to_text()), dns.rdatatype.A) for data in rrset_au]
                        for rrset in rrset_ad_list:
                            if rrset[1]:
                                additional = dns.rrset.from_rdata_list(rrset[0],rrset[1].ttl, rrset[1])
                                r.additional.append(additional)        
                
                else:
                    rrset_au = zdata.get_rdataset(zdata.origin, dns.rdatatype.SOA)
                    authority = dns.rrset.from_rdata_list(zdata.origin,rrset_au.ttl,rrset_au)
                    r.set_rcode(dns.rcode.NXDOMAIN)
                    r.authority.append(authority)
                return r.to_wire()
            return None
        except:
            logging.exception('GET AUTHORITY')
            return data

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
            logging.exception('CACHE LOAD FROM DB CACHE')