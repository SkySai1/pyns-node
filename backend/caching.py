import datetime
import logging
from multiprocessing.managers import DictProxy, ListProxy
import re
import threading
import time
import dns.message
import dns.rrset
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.name
import dns.flags
import binascii
from backend.recursive import QTYPE, CLASS
from backend.accessdb import AccessDB, getnow
try: from backend.cparser import parser
except: from backend.parser import parser

def packing(cache, rawdata):
    puredata = []
    keys = set()
    for obj in rawdata:
        row = obj[0]
        flags = ''
        name = row.name.encode('idna').decode('utf-8')
        dtype = dns.rdatatype.from_text(row.type)
        dclass = dns.rdataclass.from_text(row.dclass)
        q = dns.message.make_query(name, dtype, dclass)
        key = parser(q.to_wire())
        keys.add(key)
        if not key in cache:
            r = dns.message.make_response(q)
            r.answer.append(dns.rrset.from_text_list(name,row.ttl,dclass,dtype,row.data))
            packet = dns.message.Message.to_wire(r)
            cache[key]=packet[2:]
            puredata.append((name,row.ttl,dclass,dtype,row.data,flags))
    cnametoa(cache, puredata)
    return keys, cache  

def rrsetmaker(section, row):
    name = row.name.encode('idna').decode('utf-8')
    dtype = dns.rdatatype.from_text(row.type)
    dclass = dns.rdataclass.from_text(row.dclass)
    section.append(dns.rrset.from_text_list(name,row.ttl,dclass,dtype,row.data))
    return section

def cnametoa(cache, data, row=None, result=None):
    if row:
        #print(row)
        for one in data: 
            if one[0] == row[4][0]:
                if one[3] is dns.rdatatype.CNAME:
                    result = cnametoa(cache, data, one, result)
                    if result: result.append(one)
                    return result
                elif one[3] is dns.rdatatype.A:
                    result.append(one)
                    return result
                return None
    else:
        for one in data:
            if one[3] is dns.rdatatype.CNAME:
                result = []
                result = cnametoa(cache, data, one, result)
                if result:
                    q = dns.message.make_query(one[0], 'A', one[2])
                    r = dns.message.make_response(q)
                    if one[5]:
                        r.flags = one[5]
                    result.reverse()
                    for rr in result: 
                        r.answer.append(dns.rrset.from_text_list(
                            rr[0],rr[1],rr[2],rr[3],rr[4]
                        ))
                    packet = dns.message.Message.to_wire(r)
                    key = parser(packet)
                    cache[key]=packet[2:]

# --- Cahe job ---
class Caching:
    def __init__(self, CONF, CACHE:DictProxy, TEMP:ListProxy):
        self.conf = CONF
        self.refresh = int(CONF['DATABASE']['timesync'])
        self.cache = CACHE
        self.temp = TEMP
        self.state = True
        self.buff = set()
        self.buffexp = float(CONF['CACHING']['expire'])
        self.bufflimit = int(CONF['CACHING']['limit'])
        self.timedelta = int(CONF['DATABASE']['timedelta'])

    def debuff(self):
        while True:
            time.sleep(self.buffexp)
            self.buff.clear()

    def get(self, data:bytes):
        parse = parser(data,13)
        for save in self.buff:
            if parse == parser(save,11):
                return save
        result = self.cache.get(parse)
        if result:
            if self.buff.__len__() > self.bufflimit: self.buff.clear()
            self.buff.add(result)
        return result

    def put(self, data:bytes, isupload:bool=True):
        key = parser(data)
        result = dns.message.from_wire(data)
        if not key in self.cache and self.refresh > 0:
            self.cache[key] = data[2:]
            if result.rcode() is dns.rcode.NOERROR and isupload is True:
                self.temp.append(result)
            
    def download(self, engine):
        db = AccessDB(engine, self.conf)
        # --Getting all records from cache tatble
        try:
            if self.conf['RECURSION']['enable'] is True:
                keys,_ = packing(self.cache, db.GetFromCache())
                for e in set(self.cache.keys()) ^ keys: self.cache.pop(e)
        except:
            logging.exception('CACHE LOAD FROM DB CACHE')
      

    def upload(self, engine):
        try:            
            db = AccessDB(engine, self.conf) # <- Init Data Base
            db.CacheExpired(expired=getnow(self.timedelta, 0))
            if self.temp:
                data = []
                for result in self.temp:
                    Q = result.question[0]
                    for record in result.answer:
                        data.append({
                            'name':record.name.to_text().encode('utf-8').decode('idna'),
                            'ttl':record.ttl,
                            'rclass': dns.rdataclass.to_text(record.rdclass),
                            'type': dns.rdatatype.to_text(record.rdtype),
                            'data':[rr.to_text() for rr in record],
                            'flags':dns.flags.to_text(result.flags)
                        })
                    
                db.PutInCache(data)
                [self.temp.pop(0) for i in range(self.temp.__len__())]
        except:
            logging.exception('FAIL WITH DB CACHING')





            
