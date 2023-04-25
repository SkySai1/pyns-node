from functools import lru_cache
from dnslib import DNSRecord, RR, QTYPE, CLASS
from sqlalchemy import create_engine
from accessdb import AccessDB
from caching import Caching

class Authority:

    def __init__(self, engine:create_engine, cachetime:int = 0):
        self.engine = engine
        self.cachetime = cachetime

    def resolve(self, packet):
        data = DNSRecord.parse(packet)
        #db = AccessDB(self.engine)
        Q = {}
        Q['name'] = str(data.get_q().qname)
        Q['class'] = CLASS[data.get_q().qclass]
        Q['type'] = QTYPE[data.get_q().qtype]
        result = AccessDB.getA(self, Q['name'], Q['class'], Q['type'])
        #print(AccessDB.get.cache_info(),'\n')
        return result, data
    

    def authority(self, packet):
        result, q = Authority.resolve(self, packet)
        if result:
            answer = q.reply()
            for col in result:
                for row in col:
                    answer.add_answer(*RR.fromZone(
                    f"{row.name} {str(row.ttl)} {row.dclass} {row.type} {row.data}")
                    )
            answer.header.set_aa(1)
        else:
            answer = q
            answer.header.set_rcode(3)
        data = answer.pack()
        cache = Caching(self.cachetime)
        cache.putcache(data, str(q.get_q().qname), QTYPE[q.get_q().qtype])
        return data, int(answer.header.rcode)