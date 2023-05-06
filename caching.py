import datetime
import threading
import time
import sys
import dns.message
from dnslib import DNSRecord, QTYPE, CLASS, QR, RCODE, OPCODE
from functools import lru_cache

_CACHE = {}
# --- Cahe job ---
class Caching:

    def __init__(self, conf):
        self.conf = conf

    def getcache(self, data:dns.message.Message):
        global _CACHE
        qname = str(data.question[0].name)
        qtype = QTYPE[int(data.question[0].rdtype)]
        packet = data.to_wire(data.question[0].name)
        if qname+qtype in _CACHE:
            answer = packet[:2] + _CACHE[qname+qtype][2:]
            #print(f"{qname} was returned from local")
            return answer
        return None

    def putcache(self, data:dns.message.Message):
        cache = Caching(self.conf)
        qname = str(data.question[0].name)
        qtype = QTYPE[int(data.question[0].rdtype)]
        record = qname+qtype
        packet = data.to_wire(data.question[0].name)
        global _CACHE
        if not record in _CACHE and self.conf['buffertime'] and self.conf['buffertime'] > 0:
            _CACHE[record] = packet
            threading.Thread(target=cache.clearcache, args=(record,)).start()
            #print(f'{datetime.datetime.now()}: {record} was cached')

    def clearcache(self, cache):
        time.sleep(self.conf['buffertime'])
        global _CACHE
        if cache in _CACHE:
            #print(f'{datetime.datetime.now()}: {cache} was uncached')
            del _CACHE[cache]