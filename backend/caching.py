import datetime
import logging
from multiprocessing.managers import DictProxy, ListProxy
import threading
import time
import sys
import dns.message
import dns.rrset
import hashlib
import binascii
from backend.recursive import QTYPE, CLASS
from functools import lru_cache
from backend.accessdb import AccessDB

# --- Cahe job ---
class Caching:

    def __init__(self, engine, _CONF, CACHE:DictProxy, TEMP:ListProxy):
        self.conf = _CONF
        self.engine = engine
        self.refresh = int(_CONF['DATABASE']['timesync'])
        self.cache = CACHE
        self.temp = TEMP
        self.state = True
        self.maxthreads = threading.BoundedSemaphore(int(_CONF['CACHING']['maxthreads']))
        #if self.refresh > 0: Caching.totalcache(self)


    def get(self, data:dns.message.Message, id:bytes):
        record = binascii.hexlify(data.question[0].to_text().encode())

        if record in self.cache:
            #print(f"{data.question[0].to_text()} was returned from local")
            return id + self.cache[record]
        return None

    def put(self, data:dns.message.Message, packet:bytes=None):
        record = binascii.hexlify(data.question[0].to_text().encode())
        packet = data.to_wire()
        if not record in self.cache and self.refresh > 0:
            self.cache[record] = packet[2:]
            #print(f'{datetime.datetime.now()}: {data.question[0].to_text()} was cached as {record}')
            self.temp.append(data)
            #print(self.temp)
            # - Caching in DB at success resolving
            

    def upload(self):
        try:
            db = AccessDB(self.engine, self.conf) # <- Init Data Base
            if self.temp:
                db.PutInCache(self.temp)
                #print(type(self.temp), self.temp)
                [self.temp.pop(0) for i in range(self.temp.__len__())]
            self.maxthreads.release()
        except:
            logging.exception('FAIL WITH DB CACHING')

    def clear(self, record):
        try:
            while True:
                time.sleep(self.refresh)
                if record in self.cache:
                    name, rdclass, rdtype, = binascii.unhexlify(record).decode().split(' ')
                    packet,_ = Caching.precache(self, name, rdtype, rdclass)
                    if packet:
                        self.cache[record] = packet
                        #print(f'{datetime.datetime.now()}: {name, rdclass, rdtype} was PREcached')
                    elif packet is None:
                        del self.cache[record]
                        #print(f'{datetime.datetime.now()}: {name, rdclass, rdtype} was uncached')
                        break
        except:
            del self.cache[record]


    def precache(self, name, rdtype, rdclass):
        db = AccessDB(self.engine, self.conf)
        dbdata = db.GetFromCache(name, rdclass, rdtype)
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
        allcache = db.GetFromCache()
        table = []
        for obj in allcache:
            for row in obj:
                table.append((row.name, row.type, row.dclass))
                if row.type == 'CNAME':
                    table.append((row.name, 'A', row.dclass))
        for row in set(table):
            packet, data = Caching.precache(self, row[0], row[1], row[2])
            Caching.put(self,data,packet)
            
