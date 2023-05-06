from functools import lru_cache
from dnslib import DNSRecord, RR, QTYPE, CLASS
from sqlalchemy import create_engine
from accessdb import AccessDB
import dns.message
import dns.rrset
import dns.flags
import dns.name
#from caching import Caching

class Authority:

    def __init__(self, engine:create_engine, conf, cachetime:int = 0):
        self.engine = engine
        self.conf = conf

    def authority(self, rdata):
        result, auth, data = Authority.resolve(self, rdata)
        answer = dns.message.make_response(rdata)
        if result or auth:
            answer.origin = rdata.question[0].name
            if result: answer = makeanswer(answer,result, 0)  
            elif auth: answer = makeanswer(answer,auth, 1)                                           
            answer.flags += dns.flags.AA
        else: # <- if server didn't know about qname it will try to resolve it
            answer = data
            answer.set_rcode(3)
        return answer

    def resolve(self, data):
        if data.question:
            rr = data.question[-1].to_text().split(' ')
            db = AccessDB(self.engine, self.conf)
            Q = {}
            Q['name'] = rr[0]
            Q['class'] = rr[1]
            Q['type'] = rr[2]
            auth = None
            result = db.getDomain(Q['name'], Q['class'], Q['type']) # <- Get RR from Domain Table
            if not result: # <- if not exists required RR type then return authority list
                auth = db.getDomain(Q['name'], Q['class'], 'NS') # <- Check Authority
            if not result and not auth: # <- if not authority list and RR then check in cache
                result = db.getCache(Q['name'], Q['class'], Q['type']) # <- Get RR from Cache Table
            return result, auth, data
    
def makeanswer(answer:dns.message.Message, dbresult, type = None):
    """
    type 0 - for auth section
    type 1 - for additional section
    """
    for obj in dbresult:
        for row in obj:
            record = dns.rrset.from_text(row.name, row.ttl, row.dclass, row.type, row.data)
            if not record: break
            if type == 0:
                answer.answer.append(record)
            if type == 1:
                answer.additional.append(record)
            elif type == 2:
                if answer.get_q().qtype == 1 and row.type == 'CNAME': # <- Break answer for getting addr on A question in CNAME record 
                    answer.header.set_rcode(3) 
                    break
                answer.add_answer(*RR.fromZone(record))
    return answer