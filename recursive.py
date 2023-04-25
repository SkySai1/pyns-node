import socket
from dnslib import DNSRecord, QTYPE, CLASS
from accessdb import AccessDB
#from caching import Caching

class Recursive:

    def __init__(self, resolver, engine):
        self.resolver = resolver
        self.engine = engine

    def recursive(self, packet):
        db = AccessDB(self.engine)
        result, state = Recursive.extresolve(self.resolver, packet)
        data = DNSRecord.parse(result)
        ttl = int(data.get_a().ttl)
        rdata = str(data.get_a().rdata)
        if state is True and ttl > 0 and rdata:  # <- ON FUTURE, DYNAMIC CACHING BAD RESPONCE
            rname = str(data.get_a().rname)
            rclass = CLASS[data.get_a().rclass]
            rtype = QTYPE[data.get_a().rtype]
            db.putC(rname, ttl, rclass, rtype, rdata)
        return result, data


    def extresolve(resolver, packet):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(5)
        try:
            udp.sendto(packet, (resolver, 53))
            answer = udp.recv(512)
            state = True
        except socket.timeout:
            answer = packet
            state = False
        return answer, state


# --- Dont work ---

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

def resolver(q, ns, udp:socket.socket):
    result = None
    udp.sendto(q, (ns, 53))
    try:
        ans, ip = udp.recvfrom(512)
    except socket.timeout:
        return DNSRecord.parse(q)
    result = DNSRecord.parse(ans)
    if result.short():
        return result
    else:
        for i in DNSRecord.parse(ans).ar:
            ip = str(i.rdata)
            if '.' in ip:
                #print(ip)
                result = resolver(q, ip, udp)
            if result: return result