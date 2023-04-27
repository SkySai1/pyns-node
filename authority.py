from functools import lru_cache
from dnslib import DNSRecord, RR, QTYPE, CLASS
from sqlalchemy import create_engine
from accessdb import AccessDB
#from caching import Caching

class Authority:

    def __init__(self, engine:create_engine, conf, cachetime:int = 0):
        self.engine = engine
        self.conf = conf

    def authority(self, packet):
        result, auth, data = Authority.resolve(self, packet)
        if result or auth:
            answer = data.reply()
            if auth: answer = makeanswer(answer,auth, 0)    
            if result: answer = makeanswer(answer,result, 2)                                         
            answer.header.set_aa(1)
        else: # <- if server didn't know about qname it will try to resolve it
            answer = data
            answer.header.set_rcode(3)
            answer.header.set_qr(1)
        return answer.pack(), answer

    def resolve(self, packet):
        data = DNSRecord.parse(packet)
        db = AccessDB(self.engine, self.conf)
        Q = {}
        Q['name'] = str(data.get_q().qname)
        Q['class'] = CLASS[data.get_q().qclass]
        Q['type'] = QTYPE[data.get_q().qtype]
        auth = None
        result = db.getDomain(Q['name'], Q['class'], Q['type']) # <- Get RR from Domain Table
        if not result: # <- if not exists required RR type then return authority list
            auth = db.getDomain(Q['name'], Q['class'], 'NS') # <- Check Authority
        if not result and not auth: # <- if not authority list and RR then check in cache
            result = db.getCache(Q['name'], Q['class'], Q['type']) # <- Get RR from Cache Table
        return result, auth, data
    
def makeanswer(answer:DNSRecord, dbresult, type = None):
    """
    type 0 - for auth section
    type 1 - for additional section
    """
    for obj in dbresult:
        for row in obj:
            record = f"{row.name} {str(row.ttl)} {row.dclass} {row.type} {row.data}"
            if not record: break
            if type == 0:
                answer.add_auth(*RR.fromZone(record))
            if type == 1:
                answer.add_ar(*RR.fromZone(record))
            elif type == 2:
                if answer.get_q().qtype == 1 and row.type == 'CNAME': # <- Break answer for getting addr on A question in CNAME record 
                    answer.header.set_rcode(3) 
                    break
                answer.add_answer(*RR.fromZone(record))
    return answer