import asyncio
import logging
import struct
import dns.name
from netaddr import IPNetwork as CIDR, IPAddress as IP
from backend.functions import RDTYPE, RDCLASS

class ThisNode:
    id = None
    name = None

class Access:
    query = False
    cache = False
    authority = False
    recursive = False

class Rules:

    def __init__(self, addr, *args) -> None:
        self.addr = addr
        self.access = Access()
        self.allow = self.Allow(self.access)
        self.deny = self.Deny(self.access)

        allower = {
            'Q': self.allow.query,
            'C': self.allow.cache,
            'A': self.allow.authority,
            'R': self.allow.recursive
        }

        denier = {
            'q': self.deny.query,
            'c': self.deny.cache,
            'a': self.deny.authority,
            'r': self.deny.recursive
        }            
        [allower[r]() for r in args]

    class Allow:

        def __init__(self, access:Access) -> None:
            self.access = access

        def query(self):
            self.access.query = True
        
        def cache(self):
            self.access.cache = True
        
        def authority(self):
            self.access.authority = True
        
        def recursive(self):
            self.access.recursive = True

    class Deny:

        def __init__(self, access:Access) -> None:
            self.access = access

        def query(self):
            self.access.query = False
        
        def cache(self):
            self.access.cache = False
        
        def authority(self):
            self.access.authority = False
        
        def recursive(self):
            self.access.recursive = False


class Query:
    query = None
    name = None
    qtype = None
    qclass = None
    hash = None
    id = None
    access = Access
    correct = True

    def __init__(self, data:bytes, addr:tuple, transport):
        try:
            self.data = data
            self.ip = IP(addr[0])
            self.addr = addr
            self.transport = transport
            self.check = self.Check(self.access)
            
            self.set_meta()
        except:
            self.correct = False

    def set_meta(self):
        try:
            chunks = []
            part = self.data[12:]
            i = 0
            for t in range(part.__len__()):
                ptr = part[i]
                #if ptr > 64: raise Exception
                if ptr == 0: break
                i+=1
                chunks.append(part[i:i+ptr].decode())
                i+=ptr
            self.id = struct.unpack('>H', self.data[:2])[0]
            self.name = '.'.join(chunks)+'.'
            self.qtype = part[i+2]
            self.qclass = part[i+4]
            self.hash = part[:i+13].__hash__()

            '''part = self.data[12:]
            self.id = struct.unpack('>H', self.data[:2])[0]
            self.name, l = dns.name.from_wire(part, 0)
            self.qtype = part[l+1]
            self.qclass = part[l+3]
            self.hash = part[:l+12].__hash__()'''
            #if self.addr[0] == '95.165.134.11': print('Q:', self.name, self.qtype, self.qclass, self.hash)
        except:
            logging.debug(f"Query from {self.addr} is malformed!")
            self.correct = False
    
    def get_meta(self, as_text:bool=False):
        if as_text:
            t = RDTYPE.get(self.qtype)
            if not t: t = self.qtype

            c = RDCLASS.get(self.qclass)
            if not c: c = self.qclass
            meta = f"({self.id}) '{self.name} {c} {t}' from {self.addr}"
        else:
            meta = (self.id, self.name, self.qclass, self.qtype)
        return meta


    def getperms(self, as_text:bool=False):
        import re
        perms = {}
        perms[self.check.query.__name__] = self.check.query()
        perms[self.check.cache.__name__] = self.check.cache()
        perms[self.check.authority.__name__] = self.check.authority()
        perms[self.check.recursive.__name__] = self.check.recursive()

        if as_text:
            perms = ", ".join([f"{str(p).upper()} is {str(perms[p])}" for p in perms])
        return perms
    
    def response(self, data:bytes):
        if isinstance(self.transport, asyncio.selector_events._SelectorSocketTransport):
            l = struct.pack('>H',len(data))
            self.transport.write(l+data)
        else:
            self.transport.sendto(data, self.addr)
  
    def set_rules(self, access:Access):
        self.check = self.Check(access)

    class Check(Access):

        def __init__(self, access:Access) -> None:
            self.access = access     

        def query(self):
            return self.access.query

        def cache(self):
            return self.access.cache
    
        def authority(self):
            return self.access.authority

        def recursive(self):
            return self.access.recursive