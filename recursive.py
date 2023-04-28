import socket
import time
import ipaddress
import logging
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

    def __init__(self, engine, conf, iscache = True):
        self.conf = conf
        self.engine = engine
        self.state = iscache
        self.depth = 0

    def recursive(self, packet):
       
        db = AccessDB(self.engine, self.conf)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(2)
        resolver = self.conf['resolver']
        if resolver:
            result = Recursive.extresolve(self, resolver, packet, udp)
            return result, None
        result = Recursive.resolve(self, packet, _ROOT, udp)
        try: 
            if result.header.rcode == 0 and result.get_a().rdata:
                for rr in result.rr:
                    ttl = int(rr.ttl)
                    rdata = str(rr.rdata)
                    if self.state is True and ttl > 0 and rdata:  # <- ON FUTURE, DYNAMIC CACHING BAD RESPONCE
                        rname = str(rr.rname)
                        rclass = CLASS[rr.rclass]
                        rtype = QTYPE[rr.rtype]
                        db.putC(rname, ttl, rclass, rtype, rdata)
                #self.depth = 0
            answer = result.pack()
            return answer, result
        except:
            logging.exception('Stage: Return answer after resolving')
            result = DNSRecord.parse(packet)
            result.header.set_rcode(2)
            return result.pack(), None


    def extresolve(self, resolver, packet, udp):
        try:
            self.udp.sendto(packet, (resolver, 53))
            answer = self.udp.recv(1024)
        except socket.timeout:
            answer = packet
        return answer



    def resolve(self, packet, nslist, udp):
        if type(nslist) is not list:
            nslist = [nslist] # < - Create list of NameServers if it doesnt
        for ns in nslist:

                #if self.depth >= 10: 
                #    raise DNSError(f'Reach max recursion depth is {self.depth}!')# <- Set max recursion depth
                #self.depth += 1
                #print(self.depth,': ',ns)

                # -Trying to get answer from authority nameserver-
            try:
                udp.sendto(packet, (ns, 53))
                ans, ip = udp.recvfrom(1024)
                result = DNSRecord.parse(ans)
                if packet[:2] != ans[:2]:
                   raise DNSError('ID mismatch!')
                #print(result,'\n\n')
            except socket.timeout:
                continue
            except DNSError:
                logging.exception('Stage: Request to Authoirt NS')
                result = DNSRecord.parse(packet)
                result.header.set_rcode(5) 
                return result

            if result.short(): return result # <- If got a rdata then return it
            elif not result or not result.auth: # <- And if there is no authority NS then domain doesnt exist
                result.header.set_rcode(3) 
                return result
            
            NewNSlist = [] # <- IP for authority NS
            for authRR in result.auth:
                for arRR in result.ar:
                    if not arRR.rdata: break
                    try:
                        ip = ipaddress.ip_address(str(arRR.rdata))
                        if (str(arRR.rname).lower() in str(authRR.rdata).lower() and # <- Check for fool
                            ip.version == 4): # <- Working only with ipv4 addresses
                            NewNSlist.append(str(ip))
                    except: 
                        #logging.exception("message")
                        break
                if not NewNSlist:
                    nsQuery = DNSRecord.question(str(authRR.rdata)).pack()
                    result = Recursive.resolve(self, nsQuery, _ROOT, udp)
                    try: 
                        if result.short():
                            if type(result.short()) is list:
                                for ip in result.short():
                                    NewNSlist.append(str(ip))
                            else: NewNSlist = result.short()
                            break
                    except:
                        logging.exception('Stage: Getting IP address for Authority NS') 
                        continue
            result = Recursive.resolve(self, packet, NewNSlist, udp)
            return result