import socket
import dns.message
import dns.rrset
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

_DEBUG = 0

class Recursive:

    def __init__(self, engine, conf, iscache = True):
        self.conf = conf
        self.engine = engine
        self.state = iscache
        self.maxdepth =  30

    def recursive(self, packet):
        db = AccessDB(self.engine, self.conf) # <- Init Data Base
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # < - Init Recursive socket
        udp.settimeout(2) # < - Setting timeout
        resolver = self.conf['resolver']
        # - External resolving if specify external DNS server
        if resolver:
            result = Recursive.extresolve(self, resolver, packet, udp)
            return result, None
        # - Internal resolging if it is empty
        result = Recursive.resolve(self, packet, _ROOT, udp, 0)
        responce = result.pack()
        message = dns.message.from_wire(bytes(responce))
        try: 
            # - Caching in DB at success resolving
            if int(message.rcode()) == 0 and message.answer:
                for rr in message.answer:
                    rr = rr.to_text().split(' ')
                    ttl = int(rr[1])
                    rdata = str(rr[4])
                    if self.state is True and ttl > 0 and rdata:  # <- ON FUTURE, DYNAMIC CACHING BAD RESPONCE
                        rname = str(rr[0])
                        rclass = str(rr[2])
                        rtype = str(rr[3])
                        #db.putC(rname, ttl, rclass, rtype, rdata)
                #self.depth = 0
            return result.pack(), message # <- In anyway returns byte's packet and DNS Record data
        # -In any troubles at process resolving returns request with SERVFAIL code
        except:
            logging.exception('Stage: Return answer after resolving')
            result = DNSRecord.parse(packet)
            result.header.set_rcode(2)
            return result.pack(), None


    def extresolve(self, resolver, packet, udp):
        try:
            udp.sendto(packet, (resolver, 53))
            answer = udp.recv(1024)
        except socket.timeout:
            answer = packet
        return answer



    def resolve(self, packet, nslist, udp, depth):
        if type(nslist) is not list:
            nslist = [nslist] # < - Create list of NameServers if it doesnt
        for ns in nslist:
            # -Checking current recursion depth-
            try:
                if depth >= self.maxdepth: 
                    raise DNSError(f'Reach maxdetph - {self.maxdepth}!')# <- Set max recursion depth
                depth += 1
                '''print(f"{depth}: {ns}", 1)''' # <- SOME DEBUG
            except DNSError:
                result = DNSRecord.parse(packet)
                result.header.set_rcode(5)
                logging.exception(f'Resolve: #1, qname - {result.get_q().qname}')
                return result
            
                # -Trying to get answer from authority nameserver-
            try:
                udp.sendto(packet, (ns, 53))
                ans, ip = udp.recvfrom(1024)
                result = DNSRecord.parse(ans)
                if packet[:2] != ans[:2]:
                   raise DNSError('ID mismatch!')
                '''print(result,'\n\n')'''  # <- SOME DEBUG
            except DNSError:
                logging.exception(f'Resolve: #2')
                continue
            except socket.timeout:
                continue

            if result.short(): return result # <- If got a rdata then return it
            elif not result or not result.auth: # <- And if there is no authority NS then domain doesnt exist
                result.header.set_rcode(3) 
                return result
            
            NewNSlist = [] # <- IP list for authority NS
            for authRR in result.auth:
                for arRR in result.ar:
                    if not arRR.rdata: continue
                    try:
                        ip = ipaddress.ip_address(str(arRR.rdata))
                        if (str(arRR.rname).lower() in str(authRR.rdata).lower() and # <- Check for fool
                            ip.version == 4): # <- Working only with ipv4 addresses
                            NewNSlist.append(str(ip))
                    except: 
                        '''logging.exception("message")'''
                        continue
                if not NewNSlist and authRR.rtype == 2:
                    nsQuery = DNSRecord.question(str(authRR.rdata)).pack()
                    NSdata = Recursive.resolve(self, nsQuery, _ROOT, udp, depth)
                    try: 
                        if NSdata.header.rcode == 5:
                            result.header.rcode = 5 
                            return result
                        if NSdata.short():
                            for ip in NSdata.short().split('\n'):
                                NewNSlist.append(str(ip))
                            break
                    except:
                        logging.exception('Resolve #3:') 
                        continue
            if NewNSlist:
                NewResult = Recursive.resolve(self, packet, NewNSlist, udp, depth)
            else:
                result.header.set_rcode(3)
                return result
            return NewResult