import socket
import time
import ipaddress
from dnslib import DNSRecord, DNSError, QTYPE, CLASS
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

    def __init__(self, engine, conf, iscache = True, depth = 0):
        self.conf = conf
        self.engine = engine
        self.state = iscache
        self.depth = depth

    def recursive(self, packet):
       
        db = AccessDB(self.engine, self.conf)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(2)
        resolver = self.conf['resolver']
        if resolver:
            result = Recursive.extresolve(self, resolver, packet, udp)
            return result, None
        data = Recursive.resolve(self, packet, _ROOT, udp)
        try: 
            for rr in data.rr:
                ttl = int(rr.ttl)
                rdata = str(rr.rdata)
                if self.state is True and ttl > 0 and rdata:  # <- ON FUTURE, DYNAMIC CACHING BAD RESPONCE
                    rname = str(rr.rname)
                    rclass = CLASS[rr.rclass]
                    rtype = QTYPE[rr.rtype]
                    db.putC(rname, ttl, rclass, rtype, rdata)
            self.depth = 0
            result = data.pack()
            return result, data
        except Exception as e:
            result = DNSRecord.parse(packet)
            result.header.set_rcode(2)
            return result.pack(), None


    def extresolve(self, resolver, packet, udp):
        try:
            udp.sendto(packet, (resolver, 53))
            answer = udp.recv(512)
        except socket.timeout:
            answer = packet
        return answer



    def resolve(self, packet, nslist, udp:socket.socket):
        if type(nslist) is not list:
            nslist = [nslist]
        for ns in nslist:
            if self.depth > 333: return packet
            self.depth += 1
            #print('\n\n',self.depth,': ',ns)
            #result = None
            try:
                udp.sendto(packet, (ns, 53))
                ans, ip = udp.recvfrom(1024)
                if ans[:2] != packet[:2]:
                   raise DNSError('ID mismatch!')
                result = DNSRecord.parse(ans)
                #print(result)
            except Exception as e:
                print(e)
                continue
            if result.short():
                #print(f'\nSHORT: {result.short()}')
                return result
            if result.ar and not hasattr(result.ar[0], 'edns_len'):
                #print(f"\n ADDITIONAL\n")
                for i in result.ar:
                    ip = str(i.rdata)
                    if ipaddress.ip_network(ip, False):
                        try:
                            result = Recursive.resolve(self, packet, ip, udp)
                            if result.short(): break
                        except: continue
            elif result.auth:
                #print(f'\n AUTHORITY \n')
                for a in result.auth:
                    aQuery=DNSRecord.question(str(a.rdata)).pack()
                    try: aIp=Recursive.resolve(self, aQuery, _ROOT, udp)
                    except: continue
                    if aIp:
                        try:
                            result = Recursive.resolve(self, packet, aIp.short(), udp)
                            if result.short(): break
                        except: continue
            #print(f'\nRETURNED\n')
            return result