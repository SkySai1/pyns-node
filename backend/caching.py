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
from backend.objects import Query
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
            self.sharecache = CACHE
            self.temp = TEMP
            self.state = True
            self.corecache = {}#list()
            self.expire = float(CONF['CACHING']['expire'])
            self.corecachesize = int(CONF['CACHING']['size'])
            self.timedelta = int(CONF['GENERAL']['timedelta'])
            self.isdownload = eval(self.conf['CACHING']['download'])
            self.isupload = eval(self.conf['CACHING']['upload'])
            self.scale = float(CONF['CACHING']['scale'])

            if self.scale < 1: self.scale = 1
        except:
            logging.critical('Initialization of caching module is fail')

    def connect(self, db:AccessDB):
        self.db = db

    def corecash_cleaner(self):
        a = current_process()
        p = Process(a.pid)
        p.cpu_percent()
        wait = self.expire
        while True:
            time.sleep(wait)
            load = p.cpu_percent()
            self.corecache.clear()
            m = self.scale*round(load / 100, 2)
            if m < 1: m = 1
            try: 
                wait = self.expire * m
                if wait > self.expire*1.5:
                    logging.warning(f"Core CPU load is: {load}%, corecash clear delay for this one is {wait}'s now")
            except: wait = self.expire

    def find(self, P:Query):
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

    def get(self, Q:Query):
        try:
            key = Q.hash
            result = self.corecache.get(key)
            if result: return result
            result = self.sharecache.get(key)
            if result:
                if sys.getsizeof(self.corecache) > self.corecachesize:
                    print(sys.getsizeof(self.corecache), self.corecachesize) 
                    a = self.corecache.pop(list(self.corecache.keys())[0])
                self.corecache[key] = result
            else:
                result = self.download(Q)
            return result
        except:
            logging.warning('Get local cache is fail', exc_info=(logging.DEBUG >= logging.root.level))
            return Q.data[2:]

    def put(self, Q:Query, data:bytes, response:dns.message.Message, isupload:bool=True, isauth:bool=False):
        key = Q.hash
        if not key in self.sharecache and self.refresh > 0:
            if isauth:
                response.flags = dns.flags.Flag(dns.flags.QR + dns.flags.RD + dns.flags.AA)
            else:
                response.flags = dns.flags.Flag(dns.flags.QR + dns.flags.RD)
            self.corecache[key] = data[2:]
            self.sharecache[key] = data[2:]
            if isupload and response.answer:
                self.temp.append(response)
                logging.debug(f"Result of query '{Q.get_meta(True)}' was cached and prepare to upload into databse.")
            else:
                logging.debug(f"Result of query '{Q.get_meta(True)}' was cached.")


    def packing(self, rawdata, P:Query, q:dns.message.Message):
        try:
            self.keys = set()
            if rawdata:
                for obj in rawdata:
                    row = obj[0]
                    name = row.name.encode('idna').decode('utf-8')
                    key = parser(q.to_wire())
                    if not key in self.sharecache:
                        r = dns.message.make_response(q)
                        for d in row.data:
                            d = d.split(' ')
                            name,ttl,cls,t= d[:4]
                            data = ' '.join(d[4:])
                            r.answer.append(dns.rrset.from_text(name,ttl,cls,t,data))
                        result = dns.message.Message.to_wire(r)[2:]
                        self.sharecache[key] = result
                        logging.debug(f"{name} was found in basecache")
                        return result
            else:
                return None
        except:
            logging.error('Packing cache data is fail', exc_info=(logging.DEBUG >= logging.root.level))


    def download(self, P:Query):
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
                for data in self.sharecache.values():
                    q = dns.message.from_wire(emptyid+data,continue_on_error=True, ignore_trailing=True)
                    if len(q.question) > 0:
                        queries.append(f"'{q.question[0].to_text()}'")                   
                logging.debug(f"Data in local cache: {'; '.join(queries)}")
            # -- DEBUG LOGGING BLOCK END --

            [self.sharecache.pop(e) for e in self.sharecache.keys()]
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





            
