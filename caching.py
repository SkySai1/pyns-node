import datetime
import threading
import time
import sys
import dns.message
import hashlib
import binascii
from recursive import QTYPE, CLASS
from functools import lru_cache

_CACHE = {}
# --- Cahe job ---
class Caching:

    def __init__(self, conf):
        self.conf = conf

    def getcache(self, data:dns.message.Message, packet:bytes):
        global _CACHE
        record = binascii.hexlify(data.question[0].to_text().encode())
        if record in _CACHE:
            answer = packet[:2] + _CACHE[record][2:]
            #print(f"{data.question[0].to_text()} was returned from local")
            return answer
        return None

    def putcache(self, data:dns.message.Message):
        cache = Caching(self.conf)
        record = binascii.hexlify(data.question[0].to_text().encode())
        global _CACHE
        if not record in _CACHE and self.conf['buffertime'] and self.conf['buffertime'] > 0:
            packet = data.to_wire(data.question[0].name)
            _CACHE[record] = packet
            threading.Thread(target=cache.clearcache, args=(record,)).start()
            #print(f'{datetime.datetime.now()}: {data.question[0].to_text()} was cached as {record}')

    def clearcache(self, cache):
        time.sleep(self.conf['buffertime'])
        global _CACHE
        if cache in _CACHE:
            #print(f'{datetime.datetime.now()}: {cache} was uncached')
            del _CACHE[cache]