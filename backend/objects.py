import asyncio
import struct
import ipaddress

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
        self.addr = ipaddress.ip_network(addr)
        self.access = Access()
        self.allow = self.Allow(self.access)
        self.deny = self.Deny(self.access)

        allower = {
            'q': self.allow.query,
            'c': self.allow.cache,
            'a': self.allow.authority,
            'r': self.allow.recursive
        }

        denier = {
            'q': self.deny.query,
            'c': self.deny.cache,
            'a': self.deny.authority,
            'r': self.deny.recursive
        }            
        for r in args: 
            if r[-1] == '+': allower[r[0]]()
            elif r[-1] == '-': denier[r[0]]()

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


class Packet:
    query = None

    def __init__(self, data:bytes, addr:tuple, transport) -> None:
        self.access = access = Access()
        self.data = data
        self.ip = ipaddress.ip_address(addr[0])
        self.addr = addr
        self.transport = transport
        self.allow = self.Allow(access)
        self.check = self.Check(access)

    def getperms(self, as_text:bool=False):
        import re
        perms = {}
        perms[self.check.query.__name__] = self.check.query()
        perms[self.check.cache.__name__] = self.check.cache()
        perms[self.check.authority.__name__] = self.check.authority()
        perms[self.check.recursive.__name__] = self.check.recursive()
        '''for p in self.access.__dict__:
            perms.append((p, self.access.__dict__[p]))'''
        if as_text:
            perms = ", ".join([f"{str(p).upper()} is {str(perms[p])}" for p in perms])
        return perms
    
    def response(self, data:bytes):
        if isinstance(self.transport, asyncio.selector_events._SelectorSocketTransport):
            l = struct.pack('>H',len(data))
            self.transport.write(l+data)
        else:
            self.transport.sendto(data, self.addr)

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
    
    class Check:

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