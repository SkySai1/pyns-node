import datetime
import threading
import time
import sys
from dnslib import DNSRecord, QTYPE, CLASS, QR, RCODE, OPCODE
from functools import lru_cache

_CACHE = {}
# --- Cahe job ---
class Caching:

    def __init__(self, cachetime = 0):
        self.cachetime = cachetime

    def getcache(self, packet):
        global _CACHE
        data = DNSRecord.parse(packet)
        qname = str(data.get_q().qname)
        qtype = QTYPE[data.get_q().qtype]
        if qname+qtype in _CACHE:
            answer = packet[:2] + _CACHE[qname+qtype][2:]
            return answer
        return None

    def putcache(self, data:DNSRecord):
        cache = Caching(self.cachetime)
        qname = str(data.get_q().qname)
        qtype = QTYPE[data.get_q().qtype]
        record = qname+qtype
        global _CACHE
        if not record in _CACHE:
            _CACHE[record] = data.pack()
            threading.Thread(target=cache.clearcache, args=(record,)).start()
            print(f'{datetime.datetime.now()}: {record} was cached')

    def clearcache(self, cache):
        time.sleep(self.cachetime)
        global _CACHE
        if cache in _CACHE:
            print(f'{datetime.datetime.now()}: {cache} was uncached')
            del _CACHE[cache]