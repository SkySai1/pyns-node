class Access:
    query = False
    cache = False
    auth = False
    recursive = False


class Packet:

    def __init__(self, data:bytes, addr:tuple, transport) -> None:
        access = Access()
        self.data = data
        self.addr = addr
        self.transport = transport
        self.allow = self.Allow(access)
        self.check = self.Check(access)

    class Allow:

        def __init__(self, access:Access) -> None:
            self.access = access

        def query(self):
            self.access.query = True
        
        def cache(self):
            self.access.cache = True
        
        def auth(self):
            self.access.auth = True
        
        def recursive(self):
            self.access.recursive = True
    
    class Check:

        def __init__(self, access:Access) -> None:
            self.access = access        

        def query(self):
            return self.access.query

        def cache(self):
            return self.access.cache
    
        def auth(self):
            return self.access.auth

        def recursive(self):
            return self.access.recursive