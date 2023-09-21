import logging
from multiprocessing.managers import DictProxy, ListProxy
from sqlalchemy import create_engine
from backend.accessdb import AccessDB
from backend.caching import packing
import dns.message
import dns.rrset
import dns.flags
import dns.name
import dns.rcode
try: from backend.cparser import parser
except: from backend.parser import parser


def fakezone(query:dns.message.Message, zone, soa, ttl):
        response = dns.message.make_response(query)
        record = dns.rrset.from_text(zone,int(ttl),'IN','SOA', soa)
        response.authority.append(record)
        response.flags += dns.flags.AA
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()

class Authority:

    def __init__(self, conf, auth:DictProxy, zones:ListProxy):
        self.conf = conf
        self.auth = auth
        self.zones = zones

    def get(self, data:bytes):
        hkey = parser(data)
        query = dns.message.from_wire(data)
        qname = query.question[0].name.to_text()
        hit = []
        for e in self.zones:
            if e[0] in qname:
                hit.append(e) 
        if hit:
            result = fakezone(query, hit[-1][0], hit[-1][1], hit[-1][2])
            self.auth[hkey]=result[2:]
            return data[:2]+result[2:]
        return None



    def download(self, engine):
        db = AccessDB(engine, self.conf)
        # --Getting all records from cache tatble
        try:
            [self.zones.pop(0) for i in range(self.zones.__len__())]
            #print([rr.name for obj in db.getZones() for rr in obj])
            [self.zones.append((obj[0].name, obj[1].data[0], obj[1].ttl)) for obj in db.getZones()]
            '''for zone in self.zones:
                zone = zone[0]
                self.auth[zone] = {}    
                keys, self.auth[zone] = packing({}, db.GetFromDomains(zone=zone))'''
        except:
            logging.exception('CACHE LOAD FROM DB CACHE')