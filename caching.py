import datetime
import threading
import time
from dnslib import DNSRecord, QTYPE, CLASS, QR, RCODE, OPCODE

_CACHE = {}
# --- Cahe job ---
class Caching:

    def __init__(self, cachetime = None):
        self.cachetime = cachetime

    def getcache(self, data):
        global _CACHE
        qname = str(DNSRecord.parse(data).get_q().qname)
        qtype = QTYPE[DNSRecord.parse(data).get_q().qtype]
        if qname+qtype in _CACHE:
            answer = data[:2] + _CACHE[qname+qtype][2:]
            return answer
        return None

    def putcache(self, data, qname, qtype):
        cache = Caching(self.cachetime)
        record = qname+qtype
        global _CACHE
        if not record in _CACHE:
            _CACHE[record] = data
            threading.Thread(target=cache.clearcache, args=(record,)).start()
            #print(f'{datetime.datetime.now()}: {record} was cached')

    def clearcache(self, cache):
        time.sleep(self.cachetime)
        global _CACHE
        if cache in _CACHE:
            del _CACHE[cache]
            #print(f'{datetime.datetime.now()}: {cache} was removed from cache')