from functools import lru_cache
from dnslib import DNSRecord, RR
from sqlalchemy import create_engine
from accessdb import AccessDB
#from caching import Caching

QTYPE =   {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 10:'NULL', 12:'PTR', 13:'HINFO',
        15:'MX', 16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY',
        28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX',
        37:'CERT', 38:'A6', 39:'DNAME', 41:'OPT', 42:'APL',
        43:'DS', 44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC',
        48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM',
        52:'TLSA', 53:'HIP', 55:'HIP', 59:'CDS', 60:'CDNSKEY',
        61:'OPENPGPKEY', 62:'CSYNC', 63:'ZONEMD', 64:'SVCB',
        65:'HTTPS', 99:'SPF', 108:'EUI48', 109:'EUI64', 249:'TKEY',
        250:'TSIG', 251:'IXFR', 252:'AXFR', 255:'ANY', 256:'URI',
        257:'CAA', 32768:'TA', 32769:'DLV'}

CLASS =   {1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'}
QR =      {0:'QUERY', 1:'RESPONSE'}
RCODE =   {0:'NOERROR', 1:'FORMERR', 2:'SERVFAIL', 3:'NXDOMAIN',
        4:'NOTIMP', 5:'REFUSED', 6:'YXDOMAIN', 7:'YXRRSET',
        8:'NXRRSET', 9:'NOTAUTH', 10:'NOTZONE'}
OPCODE = {0:'QUERY', 1:'IQUERY', 2:'STATUS', 4:'NOTIFY', 5:'UPDATE'}

class Authority:

    def __init__(self, engine:create_engine, conf, cachetime:int = 0):
        self.engine = engine
        self.conf = conf

    def authority(self, query):
        result, auth, data = Authority.resolve(self, query)
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

    def resolve(self, query):
        db = AccessDB(self.engine, self.conf)
        Q = {}
        Q['name'] = str(query.sections[0][0].name)
        Q['class'] = CLASS[int(query.sections[0][0].rdtype)]
        Q['type'] = QTYPE[int(query.sections[0][0].rdclass)]
        auth = None
        result = db.getDomain(Q['name'], Q['class'], Q['type']) # <- Get RR from Domain Table
        if not result: # <- if not exists required RR type then return authority list
            auth = db.getDomain(Q['name'], Q['class'], 'NS') # <- Check Authority
        if not result and not auth: # <- if not authority list and RR then check in cache
            result = db.getCache(Q['name'], Q['class'], Q['type']) # <- Get RR from Cache Table
        return result, auth, query
    
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