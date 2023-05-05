import datetime
import threading
import time
import sys
from dnslib import DNSRecord, QTYPE, CLASS, QR, RCODE, OPCODE
from functools import lru_cache

_CACHE = {}
# --- Cahe job ---
class Caching:

    def __init__(self, conf):
        self.conf = conf

    def getcache(self, query):
        global _CACHE
        qname = str(query.sections[0][0].name)
        qtype = int(query.sections[0][0].rdtype)
        qclass = int(query.sections[0][0].rdclass)
        packet = query.to_wire()
        if qname in _CACHE:
            if qtype in _CACHE[qname]:
                if qclass in _CACHE[qname][qtype]:
                    answer = packet[:2] + _CACHE[qname][qtype][qclass][2:]
                    #print(f"{qname} was returned from local")
                    return answer
        return None

    def putcache(self, data:DNSRecord):
        cache = Caching(self.conf)
        qname = str(data.get_q().qname)
        qtype = QTYPE[data.get_q().qtype]
        record = qname+qtype
        global _CACHE
        if not record in _CACHE and self.conf['buffertime'] and self.conf['buffertime'] > 0:
            _CACHE[record] = data.pack()
            threading.Thread(target=cache.clearcache, args=(record,)).start()
            #print(f'{datetime.datetime.now()}: {record} was cached')

    def clearcache(self, cache):
        time.sleep(self.conf['buffertime'])
        global _CACHE
        if cache in _CACHE:
            #print(f'{datetime.datetime.now()}: {cache} was uncached')
            del _CACHE[cache]