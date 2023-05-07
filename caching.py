import datetime
import logging
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
        Caching.totalcache(self)


    def getcache(self, data:dns.message.Message, packet:bytes):
        global _CACHE
        record = binascii.hexlify(data.question[0].to_text().encode())
        if record in _CACHE:
            answer = packet[:2] + _CACHE[record][2:]
            #print(f"{data.question[0].to_text()} was returned from local")
            return answer
        return None

    def putcache(self, data:dns.message.Message, packet:bytes = None):
        record = binascii.hexlify(data.question[0].to_text().encode())
        global _CACHE
        if not record in _CACHE and self.conf['buffertime'] and self.conf['buffertime'] > 0:
            if not packet: packet = data.to_wire(data.question[0].name)
            _CACHE[record] = packet
            threading.Thread(target=Caching.clearcache, args=(self, record)).start()
            #print(f'{datetime.datetime.now()}: {data.question[0].to_text()} was cached as {record}')

    def clearcache(self, record):
        time.sleep(self.conf['buffertime'])
        global _CACHE
        if record in _CACHE:
            name, rdclass, rdtype, = binascii.unhexlify(record).decode().split(' ')
            packet,_ = Caching.precache(self, name, rdtype, rdclass)
            if packet:
                _CACHE[record] = packet
                #print(f'{datetime.datetime.now()}: {name, rdclass, rdtype} was PREcached')
                Caching.clearcache(self, record)
            elif packet is None:
                del _CACHE[record]
                #print(f'{datetime.datetime.now()}: {name, rdclass, rdtype} was uncached')


    def precache(self, name, rdtype, rdclass):
        db = AccessDB(self.engine, self.conf)
        dbdata = db.getCache(name, rdclass, rdtype)
        if dbdata:
            q = dns.message.make_query(name, rdtype, rdclass)
            r = dns.message.make_response(q)
            for obj in dbdata:
                for row in obj:
                    record = dns.rrset.from_text(str(row.name), int(row.ttl), str(row.dclass), str(row.type), str(row.data))
                    r.answer.append(record)
            return r.to_wire(q.question[0].name), r
        return None, None

    def totalcache(self):
        db = AccessDB(self.engine, self.conf)
        allcache = db.getCache()
        table = []
        for obj in allcache:
            for row in obj:
                table.append((row.name, row.type, row.dclass))
                if row.type == 'CNAME':
                    table.append((row.name, 'A', row.dclass))
        for row in set(table):
            packet, data = Caching.precache(self, row[0], row[1], row[2])
            Caching.putcache(self,data,packet)
            
