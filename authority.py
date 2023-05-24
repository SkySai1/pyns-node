from sqlalchemy import create_engine
from accessdb import AccessDB
import dns.message
import dns.rrset
import dns.flags
import dns.name
#from caching import Caching

class Authority:

    def __init__(self, engine:create_engine, conf):
        self.engine = engine
        self.conf = conf

    def authority(self, rdata):
        result, auth = Authority.resolve(self, rdata)
        answer = dns.message.make_response(rdata)
        if result or auth:
            answer.origin = rdata.question[0].name
            if result: answer = makeanswer(answer,result, 0)  
            elif auth: answer = makeanswer(answer,auth, 1)                                           
            answer.flags += dns.flags.AA
        else: # <- if server didn't know about qname it will try to resolve it
            answer = dns.message.make_response(rdata)
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
            return result, auth
    
def makeanswer(answer:dns.message.Message, dbresult, type = None):
    """
    type 0 - for auth section
    type 1 - for additional section
    """
    for obj in dbresult:
        for row in obj:
            record = dns.rrset.from_text(str(row.name), int(row.ttl), str(row.dclass), str(row.type), str(row.data))
            if not record: break
            if type == 0:
                answer.answer.append(record)
            if type == 1:
                answer.additional.append(record)
    return answer