from functools import lru_cache
from dnslib import DNSRecord, RR, QTYPE, CLASS
from sqlalchemy import create_engine
from accessdb import AccessDB
#from caching import Caching

class Authority:

    def __init__(self, engine:create_engine, cachetime:int = 0):
        self.engine = engine

    def resolve(self, packet):
        data = DNSRecord.parse(packet)
        db = AccessDB(self.engine)
        Q = {}
        Q['name'] = str(data.get_q().qname)
        Q['class'] = CLASS[data.get_q().qclass]
        Q['type'] = QTYPE[data.get_q().qtype]
        result = db.getA(Q['name'], Q['class'], Q['type']) # <- Get RR from Domain Table
        if not result:
            result = db.getC(Q['name'], Q['class'], Q['type']) #< <- Get RR from Cache Table
        return result, data
    

    def authority(self, packet):
        result, data = Authority.resolve(self, packet)
        if result:
            answer = data.reply()
            for obj in result:
                for row in obj:
                    answer.add_answer(*RR.fromZone(
                    f"{row.name} {str(row.ttl)} {row.dclass} {row.type} {row.data}")
                    )
            if answer.get_q().qtype == 1 and answer.get_a().rtype == 5:
                answer = data
                answer.header.set_rcode(3)
            answer.header.set_aa(1)
        else:
            answer = data
            answer.header.set_rcode(3)
        return answer.pack(), answer