import logging
from multiprocessing.managers import DictProxy, ListProxy
from multiprocessing import current_process
from psutil import Process
import os
import threading
import time
import dns.message
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.name
import dns.flags
import sys
from backend.accessdb import AccessDB
from backend.functions import getnow
from backend.packet import Packet
try: from backend.cparser import parser, iterater
except: from backend.parser import parser, iterater

# --- Cahe job ---
class Caching:
    def __init__(self, CONF, CACHE:DictProxy, TEMP:ListProxy):
        try:
            self.conf = CONF
            self.keys = set()
            self.refresh = int(CONF['DATABASE']['timesync'])
            self.cache = CACHE
            self.temp = TEMP
            self.state = True
            self.buff = {}#list()
            self.buffexp = float(CONF['CACHING']['expire'])
            self.bufflimit = int(CONF['CACHING']['size'])
            self.timedelta = int(CONF['GENERAL']['timedelta'])
            self.isdownload = eval(self.conf['CACHING']['download'])
            self.isupload = eval(self.conf['CACHING']['upload'])
            self.isrec = eval(CONF['RECURSION']['enable'])
        except:
            logging.critical('Initialization of caching module is fail')

    def connect(self, engine):
        self.db = AccessDB(engine, self.conf)

    def debuff(self):
        a = current_process()
        p = Process(a.pid)
        p.cpu_percent()
        wait = self.buffexp
        while True:
            time.sleep(wait)
            self.buff.clear()
            m = int(p.cpu_percent() // 10 + 1)
            try:
                wait = self.buffexp * m
            except:
                wait = self.buffexp
            




    def move(self, i):
        if i > 0:
            self.buff.insert(i-1, self.buff.pop(i))

    def get(self, P:Packet):
        try:
            result, key = iterater(P.data, self.buff)
            if result: return result, True
            result = self.cache.get(key)
            if result:
                if sys.getsizeof(self.buff) > self.bufflimit:
                    print(sys.getsizeof(self.buff), self.bufflimit) 
                    a = self.buff.pop(list(self.buff.keys())[0])
                self.buff[key] = result
            return result, False
        except:
            logging.warning('Geting cache data from fast local cache is fail',exc_info=True)
            return P.data[2:]

    def put(self, data:bytes, response:dns.message.Message, isupload:bool=True):
        key = parser(data)
        if not key in self.cache and self.refresh > 0:
            response.flags = dns.flags.Flag(dns.flags.QR + dns.flags.RD)
            self.buff[key] = self.cache[key] = data[2:]
            if isupload is True:
                self.temp.append(response)

    def packing(self, rawdata):
        try:
            self.keys = set()
            if rawdata:
                for obj in rawdata:
                    row = obj[0]
                    name = row.name.encode('idna').decode('utf-8')
                    dtype = dns.rdatatype.from_text(row.type)
                    cls = dns.rdataclass.from_text(row.cls)
                    q = dns.message.make_query(name, dtype, cls)
                    key = parser(q.to_wire())
                    self.keys.add(key)
                    if not key in self.cache:
                        r = dns.message.make_response(q)
                        if self.isrec is True: r.flags += dns.flags.RA
                        for d in row.data:
                            d = d.split(' ')
                            name,ttl,cls,t= d[:4]
                            data = ' '.join(d[4:])
                            r.answer.append(dns.rrset.from_text(name,ttl,cls,t,data))
                        packet = dns.message.Message.to_wire(r)
                        self.cache[key]=packet[2:]
        except:
            logging.error('Packing cache data is fail')


    def download(self, db:AccessDB):
        # --Getting all records from cache tatble
        try:
            # -- DEBUG LOGGING BLOCK START --
            if self.cache and logging.DEBUG >= logging.root.level:
                emptyid = int.to_bytes(0,2,'big')
                queries = []
                for data in self.cache.values():
                    q = dns.message.from_wire(emptyid+data)
                    queries.append(f"'{q.question[0].to_text()}'")                   
                logging.debug(f"Data in local cache: {'; '.join(queries)}")
            # -- DEBUG LOGGING BLOCK END --

            if self.isdownload is True:
                self.packing(db.GetFromCache())
                for e in set(self.cache.keys()) ^ self.keys: self.cache.pop(e)
        except:
            logging.error('Making bytes objects for local cache is fail', exc_info=True)
      

    def upload(self, db:AccessDB, data=None):
        try:
            db.CacheExpired(expired=getnow(self.timedelta, 0))
            if eval(self.conf['CACHING']['upload']) is True:           
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
            logging.error('Making local cache data to database storage format and uploading it is fail')





            
