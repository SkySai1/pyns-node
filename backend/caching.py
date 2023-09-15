import datetime
import logging
from multiprocessing.managers import DictProxy, ListProxy
import threading
import time
import dns.message
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import binascii
from backend.recursive import QTYPE, CLASS
from backend.accessdb import AccessDB

def parser(data:bytes, i:int=13):
    struct = data[i:]
    for t in range(struct.__len__()):
        if struct[t] == 0:
            return struct[:t+5].__hash__()

# --- Cahe job ---
class Caching:
    def __init__(self, engine, _CONF, CACHE:DictProxy, TEMP:ListProxy):
        self.conf = _CONF
        self.engine = engine
        self.refresh = int(_CONF['DATABASE']['timesync'])
        self.cache = CACHE
        self.temp = TEMP
        self.state = True
        self.buff = set()
        self.maxthreads = threading.BoundedSemaphore(int(_CONF['CACHING']['maxthreads']))
        #if self.refresh > 0: Caching.totalcache(self)
        if self.refresh > 0: Caching.download(self)


    def get(self, data:bytes):
        for save in self.buff:
            e = parser(save,11)
            if e == parser(data,13): return save
        #print(time.time(),'ASK:',dns.message.from_wire(data).question[0].to_text(), ', with KEY:', Caching.parser(self, data))
        result = self.cache.get(parser(data))
        if result: self.buff.add(result)
        return result

    def put(self, data:dns.message.Message):
        #print(self.cache.keys())
        packet = data.to_wire()
        key = parser(packet)
        if not key in self.cache and self.refresh > 0:
            self.cache[key] = packet[2:]
            #print(f'{datetime.datetime.now()}: {data.question[0].to_text()} was cached as {key}')
            if data.rcode() is dns.rcode.NOERROR:
                self.temp.append(data)
            

    def upload(self):
        try:
            self.buff.clear()             
            db = AccessDB(self.engine, self.conf) # <- Init Data Base
            if self.temp:
                data = []
                for result in self.temp:
                    Q = result.question[0]
                    for record in result.answer:
                        data.append({
                            'name':record.name.to_text(),
                            'ttl':record.ttl,
                            'rclass': dns.rdataclass.to_text(record.rdclass),
                            'type': dns.rdatatype.to_text(record.rdtype),
                            'data':[rr.to_text() for rr in record]
                        })
                db.PutInCache(data)
                [self.temp.pop(0) for i in range(self.temp.__len__())]
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

    def download(self):
        db = AccessDB(self.engine, self.conf)
        # --Getting all records from cache tatble
        rawdata = db.GetFromCache() + db.GetFromDomains()
        if rawdata:
            try:
                for obj in rawdata:
                    for row in obj:
                        #print(row.data)
                        dtype = dns.rdatatype.from_text(row.type)
                        dclass = dns.rdataclass.from_text(row.dclass)
                        q = dns.message.make_query(row.name, dtype, dclass)
                        r = dns.message.make_response(q)
                        r.answer.append(dns.rrset.from_text_list(row.name,row.ttl,dclass,dtype,row.data))
                        packet = dns.message.Message.to_wire(r)
                        key = parser(packet)
                        self.cache[key]=packet[2:]
            except:
                logging.exception('CACHE LOAD FROM DB CACHE')
                  

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



            
