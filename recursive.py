import socket
import time
from dnslib import DNSRecord, QTYPE, CLASS
from accessdb import AccessDB

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

class Recursive:

    def __init__(self, engine, conf, iscache = True):
        self.conf = conf
        self.engine = engine
        self.state = iscache

    def recursive(self, packet):
       
        db = AccessDB(self.engine, self.conf)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(2)
        resolver = self.conf['resolver']
        if resolver:
            result = extresolve(resolver, packet, udp)
            return result, None
        data = resolve(packet, _ROOT, udp)
        try: result = data.pack()
        except: result = packet
        if data and data.rr:
            for rr in data.rr:
                ttl = int(rr.ttl)
                rdata = str(rr.rdata)
                if self.state is True and ttl > 0 and rdata:  # <- ON FUTURE, DYNAMIC CACHING BAD RESPONCE
                    rname = str(rr.rname)
                    rclass = CLASS[rr.rclass]
                    rtype = QTYPE[rr.rtype]
                    db.putC(rname, ttl, rclass, rtype, rdata)
        return result, data


def extresolve(resolver, packet, udp):
    try:
        udp.sendto(packet, (resolver, 53))
        answer = udp.recv(512)
    except socket.timeout:
        answer = packet
    return answer


def resolve(packet, nslist, udp:socket.socket):
    if type(nslist) is not list:
        nslist = [nslist]
    for ns in nslist:
        result = None
        udp.sendto(packet, (ns, 53))
        try:
            ans, ip = udp.recvfrom(1024)
            result = DNSRecord.parse(ans)
        except Exception as e:
            print(e)
            continue
        #print(result)
        if result.short():
            return result
        elif result.ar:
            for i in result.ar:
                ip = str(i.rdata)
                if '.' in ip:
                    try: newresult = resolve(packet, ip, udp)
                    except: continue
                    if newresult: 
                        return newresult
            if result.auth:
                for a in result.auth:
                    aQuery=DNSRecord.question(str(a.rdata)).pack()
                    try: aIp=resolve(aQuery, _ROOT, udp)
                    except: continue
                    if aIp:
                        try: newresult = resolve(packet, aIp.short(), udp)
                        except: continue
                        if newresult:
                            return newresult
            return result