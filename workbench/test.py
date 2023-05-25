#!./dns/bin/python3
import datetime
from functools import lru_cache
import random
import dns.query
import dns.message
import dns.name
import dns.rrset
import dns.update
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.zone
import dns.tsig
import dns.tsigkeyring
import dns.flags
import dns.dnssec
import dns.rdtypes
import dns.resolver
import os
import shutil
import socket
import binascii
import hashlib
import hmac
import time
import ipaddress
import uuid
from dnslib import DNSRecord
from threading import Thread
from sqlalchemy import BigInteger, Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, delete, insert, select, or_
from sqlalchemy.orm import declarative_base, Session

from decoder import Decoder

_ROOT = [
    "198.41.0.4",           #a.root-servers.net.
    "199.9.14.201",         #b.root-servers.net.
    "192.33.4.12",          #c.root-servers.net.
    "199.7.91.13",          #d.root-servers.net.
    "192.203.230.10",       #e.root-servers.net.
    "192.5.5.241",          #f.root-servers.net.
    "192.112.36.4",         #g.root-servers.net.
    "198.97.190.53",        #h.root-servers.net.
    "192.36.148.17",        #i.root-servers.net.
    "192.58.128.30",        #j.root-servers.net.
    "193.0.14.129",         #k.root-servers.net.
    "199.7.83.42",          #l.root-servers.net.
    "202.12.27.33"          #m.root-servers.net.
     ]

Base = declarative_base()
class Cache(Base):  
    __tablename__ = "cache" 
    
    id = Column(BigInteger, primary_key=True)  
    name = Column(String(255), nullable=False)
    ttl = Column(Integer, default=60)
    dclass = Column(String(2), default='IN')   
    type = Column(String(10))
    data = Column(String(255))
    cached = Column(DateTime(timezone=True), nullable=False)  
    expired = Column(DateTime(timezone=True), nullable=False)  

class Zones(Base):  
    __tablename__ = "zones" 
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True)
    type = Column(String, default='master')  
    serial = Column(Integer, default=int(datetime.datetime.now().strftime('%Y%m%d01')))
    ttl = Column(Integer, default=60)
    expire = Column(Integer, default = 86400)
    refresh = Column(Integer, default = 28800)
    retry = Column(Integer, default=3600)

class Domains(Base):  
    __tablename__ = "domains" 
    
    id = Column(BigInteger, primary_key=True)
    zone_id = Column(Integer, ForeignKey('zones.id', ondelete='cascade'), nullable=False)
    name = Column(String(255), nullable=False)
    ttl = Column(Integer, default=60)
    dclass = Column(String(2), default='IN')   
    type = Column(String(10))
    data = Column(Text)

engine = create_engine("postgresql+psycopg2://dnspy:dnspy23./@95.165.134.11:5432/dnspy")

def getbyoneof():
     engine = create_engine("postgresql+psycopg2://dnspy:dnspy23./@95.165.134.11:5432/dnspy")
     oneof = ['cn.dns.tinirog.ru.', 'cn4.dns.tinirog.ru.', 'rambler.ru.']
     with Session(engine) as conn:
          stmt = (
               select(Cache)
               .filter(Cache.name.in_(oneof))
          )
          result = conn.execute(stmt).all()
          for obj in result:
               for row in obj:
                    expired = 'alive'
                    if (row.expired) <= getnow(0):
                         expired = 'expired'
                    print(row.name,' ',row.expired,' ', expired)

               

def deleteby():
     with Session(engine) as conn:
          stmt = (delete(Cache)
                  .filter(Cache.expired <= getnow(0))
                  .filter(Cache.name == None)
                  .returning(Cache.name)
          )
          result = conn.scalars(stmt).fetchall()
          for obj in result:
               print(obj)
          conn.commit()

def getnow(rise):
     offset = datetime.timedelta(hours=3)
     tz = datetime.timezone(offset)
     now = datetime.datetime.now(tz=tz)
     return now + datetime.timedelta(0,rise)


def parser(zone:str):
     parser = zone.split('.')[:-1]
     parser = list(reversed(parser))
     zlist = ['.']
     temp = ''
     for i in parser:
          temp = i + '.' + temp
          zlist.append(temp)
     with Session(engine) as conn:
          stmt = select(Zones).filter(Zones.name.in_(zlist))
          result = conn.execute(stmt).fetchall()
          for obj in result:
               for row in obj:
                    print(row.name)
                    pass


def dnspython():
     QTYPE =   {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 10:'NULL', 12:'PTR', 13:'HINFO',
               15:'MX', 16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY',
               28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX',
               37:'CERT', 38:'A6', 39:'DNAME', 41:'OPT', 42:'APL',
               43:'DS', 44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC',
               48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM',
               52:'TLSA', 53:'HIP', 55:'HIP', 59:'CDS', 60:'CDNSKEY',
               61:'OPENPGPKEY', 62:'CSYNC', 63:'ZONEMD', 64:'SVCB',
               65:'HTTPS', 99:'SPF', 108:'EUI48', 109:'EUI64', 249:'TKEY',
               250:'TSIG', 251:'IXFR', 252:'AXFR', 255:'ANY', 256:'URI',
               257:'CAA', 32768:'TA', 32769:'DLV'}

     CLASS =   {1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'}
     QR =      {0:'QUERY', 1:'RESPONSE'}
     RCODE =   {0:'NOERROR', 1:'FORMERR', 2:'SERVFAIL', 3:'NXDOMAIN',
               4:'NOTIMP', 5:'REFUSED', 6:'YXDOMAIN', 7:'YXRRSET',
               8:'NXRRSET', 9:'NOTAUTH', 10:'NOTZONE'}
     OPCODE = {0:'QUERY', 1:'IQUERY', 2:'STATUS', 4:'NOTIFY', 5:'UPDATE'}

     udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     udp.bind(('192.168.1.10', 53))
     q,_,addr = dns.query.receive_udp(udp)
     dns.rdata.from_text(dns.rdataclass.IN,dns.rdatatype.A,)
     rdtype = int(q.sections[0][0].rdtype)
     r = dns.message.make_response(q)
     dns.query.send_udp(udp,r,addr)



     '''for obj in q.sections:
          for rr in obj:
               print(rr.name)
               print(rr.rdtype)
               print(rr.rdclass)'''


def transfer():
     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     data = DNSRecord.question("tinirog.ru", "AXFR", "IN")
     data.header.rd = 0
     data = data.pack()
     lg = len(data).to_bytes(2,'big')
     data = lg+data
     s.connect(('95.165.134.11', 53))
     s.sendall(data)
     answer = b''
     packet = True
     try:
          while packet:
                packet = s.recv(4096)
                s.settimeout(1)  
                answer+=packet
     except socket.timeout: pass
     s.close()
     print(DNSRecord.parse(answer[2:]))

def getaxfr():
     key = dns.tsigkeyring.from_text({
          "tinirog-waramik": "302faOimRL7J6y7AfKWTwq/346PEynIqU4n/muJCPbs=",
          "mykey": "oUHtrekkN1RJ3MNjplEeO6Yxax46Qs7pR++NPpcH/4g="

    })
     dns.tsigkeyring.to_text(key)
     xfr = dns.query.xfr(
          '95.165.134.11',
          'araish.ru',
          port=53,
          #keyring=key,
          #keyalgorithm='HMAC-SHA256'
     )
     zone = dns.zone.from_xfr(xfr)
     #print(zone.get_soa())
     
     qname = dns.name.from_text('example.su')
     xfr = dns.message.make_query(qname, 'AXFR', 'IN')
     xfr.use_tsig(key, "mykey")
     r = dns.query.tcp(xfr,'95.165.134.11')
     print(r)

def maketsig():
     an = 'SAMPLE-ALG.EXAMPLE.'.encode('utf-8')
     ts = int.to_bytes(853804800,6,'big')
     f =  int.to_bytes(300,2,'big')
     er = int.to_bytes(0,2,'big')
     ot = int.to_bytes(0,2,'big')
     packet = an + ts + f + er + ot
     shit = os.urandom(16)
     dig = hmac.new(b'1234567890', msg=shit, digestmod=hashlib.sha256).digest()
     key = dns.dnssec.base64.b64encode(dig)
     print(key)


def makerr():
     raw = b'\x0c\x8d\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x06google\x02ru\x00\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08\xca\x90}=m\xa2\x03\x13'
     google = dns.message.from_wire(raw)
     a = dns.message.make_response(google)
     rr = dns.rrset.from_text('google.ru', 30, 'IN', 'A', '127.0.0.1')
     a.answer.append(rr)
     rr = dns.rrset.from_text('google.ru', 30, 'IN', 'A', '127.0.0.2')
     a.answer.append(rr)
     print(a)

          

     #print(r)
     #print(DNSRecord.parse(r))

def zonedel():
     with Session(engine) as session:
          stmt = delete(Zones).filter(Zones.name == 'tinirog.ru.')
          session.execute(stmt)
          session.commit()

def udplisten():
    data = dns.query.receive_udp()

def spamer(answer:dns.message.Message = None):
     if not answer:
          udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          rdata = dns.message.make_query('vtb.ru', 'MX', 'IN')
          packet = rdata.to_wire()
          dns.query.send_udp(udp, rdata, ('195.242.83.129', 53),1)
          result, ip = dns.query.receive_udp(udp,('195.242.83.129', 53),1)
          spamer(result)
     if answer:
          print(answer.question[0].to_text())

def decoding():
     udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     rdata = dns.message.make_query('ru', 'A', 'IN')
     packet = rdata.to_wire()
     udp.sendto(packet, ('192.58.128.30', 53))
     answer, _ = udp.recvfrom(1024)
     #print(answer)
     start = time.time()
     Decoder(answer)
     print(time.time()-start)

     start = time.time()
     print(dns.message.from_wire(answer))
     print(time.time()-start)

def prerecursio():
     start = time.time()
     qname = dns.name.from_text('google.ru')
     q = dns.message.make_query(qname,'A','IN')
     stream = []
     for ns in _ROOT:
          t = ThreadResolve(ns, q)
          t.start()
          stream.append(t)
          break
     answer = []
     for t in stream:
          t.join()
          answer.append(t.value)
     end = time.time()
     print(end-start, answer[0][0])



def recursio(ns, rdata:dns.message.Message, depth = 0):
     try:
          result = dns.query.udp(rdata,ns)
          if result.answer: 
               #print('\n', result)
               return result, True
     except:
          result = dns.message.make_response(rdata)
          result.set_rcode(2)
          return result, False
     nslist = []
     for auth in result.authority[0]:
          for ad in result.additional:
               if str(auth) == str(ad.name):
                    ip = ipaddress.ip_address(str(ad[0]))
                    if ip.version == 4:
                         nslist.append(str(ip))
     if not nslist:
          for rr in result.authority[0]:
               qname = dns.name.from_text(str(rr))
               nsQuery = dns.message.make_query(qname, dns.rdatatype.A, dns.rdataclass.IN)
               stream = []
               for ns in _ROOT:
                    t = ThreadResolve(ns, nsQuery)
                    t.start()
                    stream.append(t)
                    break
               response = []
               for t in stream:
                    t.join()
                    response.append(t.value)
               if response:
                    for data in response:
                         if True in data:
                              for rr in data[0].answer:
                                   if not str(rr[0]) in nslist:
                                        nslist.append(str(rr[0]))
     if not nslist:
          result = dns.message.make_response(rdata)
          result.set_rcode(3)
          return result, False
     
     stream = []
     for ns in nslist:
          t = ThreadResolve(ns, rdata)
          t.start()
          stream.append(t)
     answer = []
     for t in stream:
          t.join()
          answer.append(t.value)
     for a in answer:
          if True in a:
               return a

# custom thread
class ThreadResolve(Thread):

    def __init__(self, ns, rdata):
        Thread.__init__(self)
        self.value = None
        self.ns = ns
        self.rdata = rdata
 
    def run(self):
        self.value = recursio(self.ns, self.rdata)


if __name__ == "__main__":
     prerecursio()