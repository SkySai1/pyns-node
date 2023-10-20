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
from backend.objects import Packet
try: from backend.cparser import parser, iterater
except: from backend.parser import parser, iterater

# --- Cahe job ---
class Caching:
    db = None

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
            self.scale = float(CONF['CACHING']['scale'])
        except:
            logging.critical('Initialization of caching module is fail')

    def connect(self, db:AccessDB):
        self.db = db

    def debuff(self):
        a = current_process()
        p = Process(a.pid)
        p.cpu_percent()
        wait = self.buffexp
        while True:
            time.sleep(wait)
            self.buff.clear()
            m = self.scale*round(p.cpu_percent() / 100, 2)
            if m < 1: m = 1
            try: 
                wait = self.buffexp * m
            except: wait = self.buffexp

    def find(self, P:Packet):
        q = dns.message.from_wire(P.data, continue_on_error=True, ignore_trailing=True)
        qname = q.question[0].name.to_text()
        qtype = dns.rdatatype.to_text(q.question[0].rdtype)
        qclass = dns.rdataclass.to_text(q.question[0].rdclass)
        rawcache = self.db.GetFromCache(qname,qclass,qtype)
        if rawcache:
            r = dns.message.make_response(q, P.check.recursive())
            data = rawcache[0][0].split(' ')
            r.answer.append(
                dns.rrset.from_text_list(qname,)
            )
        return None        

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
            else:
                result = self.download(P)
            return result, False
        except:
            logging.warning('Get local cache is fail', exc_info=(logging.DEBUG >= logging.root.level))
            return P.data[2:], False

    def put(self, query:bytes, data:bytes, response:dns.message.Message, isupload:bool=True, isuath:bool=False):
        key = parser(query)
        if not key in self.cache and self.refresh > 0:
            if isuath:
                response.flags = dns.flags.Flag(dns.flags.QR + dns.flags.RD + dns.flags.AA)
            else:
                response.flags = dns.flags.Flag(dns.flags.QR + dns.flags.RD)
            self.buff[key] = self.cache[key] = data[2:]
            if isupload and response.answer:
                self.temp.append(response)

    def packing(self, rawdata, P:Packet, q:dns.message.Message):
        try:
            self.keys = set()
            if rawdata:
                for obj in rawdata:
                    row = obj[0]
                    name = row.name.encode('idna').decode('utf-8')
                    key = parser(q.to_wire())
                    if not key in self.cache:
                        r = dns.message.make_response(q)
                        for d in row.data:
                            d = d.split(' ')
                            name,ttl,cls,t= d[:4]
                            data = ' '.join(d[4:])
                            r.answer.append(dns.rrset.from_text(name,ttl,cls,t,data))
                        result = dns.message.Message.to_wire(r)[2:]
                        self.cache[key] = result
                        logging.debug(f"{name} was found in basecache")
                        return result
            else:
                return None
        except:
            logging.error('Packing cache data is fail', exc_info=(logging.DEBUG >= logging.root.level))


    def download(self, P:Packet):
        q = dns.message.from_wire(P.data, continue_on_error=True, ignore_trailing=True)
        qname = q.question[0].name.to_text()
        qtype = dns.rdatatype.to_text(q.question[0].rdtype)
        qclass = dns.rdataclass.to_text(q.question[0].rdclass)
        if q.ednsflags == dns.flags.DO: eflag = 'DO'
        else: eflag = None
        try:
            if self.isdownload is True:
                return self.packing(self.db.GetFromCache(qname,qclass,qtype,eflag), P, q)
        except:
            logging.error('Making bytes objects for local cache is fail', exc_info=(logging.DEBUG >= logging.root.level))
      

    def upload(self, db:AccessDB):
        try:

            # -- DEBUG LOGGING BLOCK START --
            if self.temp and logging.DEBUG >= logging.root.level and not logging.root.disabled:
                emptyid = int.to_bytes(0,2,'big')
                queries = []
                for data in self.cache.values():
                    q = dns.message.from_wire(emptyid+data)
                    queries.append(f"'{q.question[0].to_text()}'")                   
                logging.debug(f"Data in local cache: {'; '.join(queries)}")
            # -- DEBUG LOGGING BLOCK END --

            [self.cache.pop(e) for e in self.cache.keys()]
            db.CacheExpired(expired=getnow(self.timedelta, 0))
            if eval(self.conf['CACHING']['upload']) is True:           
                if self.temp:
                    data = []
                    for result in self.temp:
                        q = result.question[0]
                        if result.ednsflags == dns.flags.DO: eflag = 'DO'
                        else: eflag = None
                        ttl = [record.ttl for record in result.answer]
                        if ttl:
                            data.append({
                                'name':q.name.to_text().encode('utf-8').decode('idna'),
                                'cls': dns.rdataclass.to_text(q.rdclass),
                                'type': dns.rdatatype.to_text(q.rdtype),
                                'eflag': eflag,
                                'data':[record.to_text() for record in result.answer]
                            })
                    if data:                      
                        if db.PutInCache(data, min(ttl)) is True:
                            [self.temp.pop(0) for i in range(self.temp.__len__())]
        except:
            logging.error('Convert uploading cache is fail', exc_info=(logging.DEBUG >= logging.root.level))





            
