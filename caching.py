import datetime
import threading
import time
import sys
import dns.message
import dns.rrset
import hashlib
import binascii
from recursive import QTYPE, CLASS
from functools import lru_cache
from accessdb import AccessDB

_CACHE = {}
# --- Cahe job ---
class Caching:

    def __init__(self, conf, engine):
        self.conf = conf
        self.engine = engine

    def getcache(self, data:dns.message.Message, packet:bytes):
        global _CACHE
        record = binascii.hexlify(data.question[0].to_text().encode())
        if record in _CACHE:
            answer = packet[:2] + _CACHE[record][2:]
            #print(f"{data.question[0].to_text()} was returned from local")
            return answer
        return None

    def putcache(self, data:dns.message.Message):
        cache = Caching(self.conf, self.engine)
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
            name, rdclass, rdtype, = binascii.unhexlify(cache).decode().split(' ')
            db = AccessDB(self.engine, self.conf)
            dbdata = db.getCache(name, rdclass, rdtype)
            if dbdata: 
                packet = Caching.precache(self, name, rdtype, rdclass, dbdata)
                _CACHE[cache] = packet
                #print(f'{datetime.datetime.now()}: {name, rdclass, rdtype} was PREcached')
                Caching.clearcache(self, cache)
            else:
                #print(f'{datetime.datetime.now()}: {name, rdclass, rdtype} was uncached')
                del _CACHE[cache]

    def precache(self, name, rdtype, rdclass, dbdata):
        q = dns.message.make_query(name, rdtype, rdclass)
        r = dns.message.make_response(q)
        for obj in dbdata:
            for row in obj:
                record = dns.rrset.from_text(str(row.name), int(row.ttl), str(row.dclass), str(row.type), str(row.data))
                r.answer.append(record)
        return r.to_wire(q.question[0].name)

