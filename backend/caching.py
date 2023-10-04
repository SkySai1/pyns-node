import logging
from multiprocessing.managers import DictProxy, ListProxy
import threading
import time
import dns.message
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.name
import dns.flags
from backend.accessdb import AccessDB
from backend.functions import getnow
try: from backend.cparser import parser, iterater
except: from backend.parser import parser, iterater

def packing(cache:DictProxy, rawdata, isrec:bool=True):
    try:
        puredata = []
        keys = set()
        if rawdata:
            for obj in rawdata:
                row = obj[0]
                name = row.name.encode('idna').decode('utf-8')
                dtype = dns.rdatatype.from_text(row.type)
                cls = dns.rdataclass.from_text(row.cls)
                q = dns.message.make_query(name, dtype, cls)
                key = parser(q.to_wire())
                keys.add(key)
                if not key in cache:
                    r = dns.message.make_response(q)
                    if isrec is True: r.flags += dns.flags.RA
                    for d in row.data:
                        d = d.split(' ')
                        name,ttl,cls,t= d[:4]
                        data = ' '.join(d[4:])
                        r.answer.append(dns.rrset.from_text(name,ttl,cls,t,data))
                    packet = dns.message.Message.to_wire(r)
                    cache[key]=packet[2:]
            return keys, cache
    except:
        logging.error('packing cache data from database into local cache bytes object is fail', exc_info=True)  
    finally:    
        return None, None

# --- Cahe job ---
class Caching:
    def __init__(self, CONF, CACHE:DictProxy, TEMP:ListProxy):
        try:
            self.conf = CONF
            self.refresh = int(CONF['DATABASE']['timesync'])
            self.cache = CACHE
            self.temp = TEMP
            self.state = True
            self.buff = list()
            self.buffexp = float(CONF['CACHING']['expire'])
            self.bufflimit = int(CONF['CACHING']['limit'])
            self.timedelta = int(CONF['GENERAL']['timedelta'])
            self.iscache = eval(self.conf['CACHING']['download'])
            self.isrec = eval(CONF['RECURSION']['enable']) 
        except:
            logging.critical('initialization of recursive module is fail')

    def connect(self, engine):
        self.db = AccessDB(engine, self.conf)

    def debuff(self):
        while True:
            time.sleep(self.buffexp)
            self.buff.clear()

    def move(self, i):
        if i > 0:
            self.buff.insert(i-1, self.buff.pop(i))

    def get(self, data:bytes):
        try:
            result, key, self.buff = iterater(data, self.buff)
            if result: return result
        except:
            logging.warning('geting cache data from fast local cache is fail')
        result = self.cache.get(key)
        if result:
            if self.buff.__len__() > self.bufflimit: self.buff.clear()
            self.buff.append(result)
        return result

    def put(self, data:bytes, isupload:bool=True):
        key = parser(data)
        result = dns.message.from_wire(data,ignore_trailing=True,one_rr_per_rrset=True)
        if not key in self.cache and self.refresh > 0 and not dns.flags.TC in result.flags:
            self.cache[key] = data[2:]
            if result.rcode() is dns.rcode.NOERROR and isupload is True:
                self.temp.append(result)
                #threading.Thread(target=Caching.upload,args=(self,self.db,result),daemon=True).start()
                #Caching.upload(self,self.db,result)
            
    def download(self, db:AccessDB):
        # --Getting all records from cache tatble
        try:
            #db.CacheExpired(expired=getnow(self.timedelta, 0))
            if self.iscache is True:
                keys,_ = packing(self.cache, db.GetFromCache(), self.isrec)
                if keys:
                    for e in set(self.cache.keys()) ^ keys: self.cache.pop(e)
        except:
            logging.error('making bytes objects from database cache data is fail')
      

    def upload(self, db:AccessDB, data=None):
        try:
            if eval(self.conf['CACHING']['upload']) is True:
                print(self.temp)            
                if data: self.temp = [data]
                if self.temp:
                    data = []
                    for result in self.temp:
                        q = result.question[0]
                        ttl = [record.ttl for record in result.answer]
                        if ttl:
                            data.append({
                                'name':q.name.to_text().encode('utf-8').decode('idna'),
                                'cls': dns.rdataclass.to_text(q.rdclass),
                                'type': dns.rdatatype.to_text(q.rdtype),
                                'data':[record.to_text() for record in result.answer]
                            })
                    if data:                      
                        if db.PutInCache(data, min(ttl)) is True:
                            [self.temp.pop(0) for i in range(self.temp.__len__())]
        except:
            logging.error('making local cache data to database storage format and uploading is fail')





            
