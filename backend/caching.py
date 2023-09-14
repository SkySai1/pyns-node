import datetime
import logging
from multiprocessing.managers import DictProxy, ListProxy
import threading
import time
import dns.message
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import binascii
from backend.recursive import QTYPE, CLASS
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
        if self.refresh > 0: Caching.load(self)

    def get(self, data:bytes):
        record = dns.message.from_wire(data).question[0].to_text().__hash__()
        print(time.time(),'ASK:',dns.message.from_wire(data).question[0].to_text())
        return self.cache.get(record)

    def put(self, data:dns.message.Message, packet:bytes=None):
        record = data.question[0].to_text().__hash__()
        packet = data.to_wire()
        if not record in self.cache and self.refresh > 0:
            self.cache[record] = packet[2:]
            #print(f'{datetime.datetime.now()}: {data.question[0].to_text()} was cached as {record}')
            self.temp.append(data)
            

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

    def load(self):
        db = AccessDB(self.engine, self.conf)
        datac = set()
        datad = set()

        # --Getting all records from cache tatble
        rawcache = db.GetFromCache()
        if rawcache:
            try:
                for obj in rawcache:
                    for row in obj:
                        #print((d for d in row.data))
                        datac.add((row.name, row.ttl, row.type, row.dclass, (d for d in row.data)))
            except:
                logging.exception('CACHE LOAD FROM DB CACHE')
        
        # --Getting all records from domains table
        rawdomains = db.GetFromDomains()
        if rawdomains:
            try:
                for obj in rawdomains:
                    for row in obj:
                        datad.add((row.name, row.type, row.dclass, row.data))
                        #print(row.name, row.dclass, row.type, row.data)
            except:
                logging.exception('CACHE LOAD FROM DB DOMAINS')            
        
        # --Make precaching cache data
        for record in datac:
            qname = record[0]
            ttl = int(record[1])
            qtype = dns.rdatatype.from_text(record[2])
            qclass = dns.rdataclass.from_text(record[3])
            rdata = record[4]
            q = dns.message.make_query(qname,qtype,qclass)
            r = dns.message.make_response(q)
            r.answer.append(dns.rrset.from_text_list(
                qname,ttl,qclass,qtype,rdata))
            key = r.question[0].to_text().__hash__()
            print(record)
            self.cache[key]=dns.message.Message.to_wire(r)[2:]
            #print(self.cache)


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



            
