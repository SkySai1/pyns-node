import ipaddress
import socket
import dns.message
import dns.rrset
import dns.query
import dns.exception
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import logging
from dnslib import DNSRecord, DNSError
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

QTYPE = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 10:'NULL', 12:'PTR', 13:'HINFO',
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

CLASS = {1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'}

class Recursive:

    def __init__(self, engine, conf, iscache = True):
        self.conf = conf
        self.engine = engine
        self.state = iscache
        self.maxdepth =  30

    def recursive(self, query:dns.message.Message):
        db = AccessDB(self.engine, self.conf) # <- Init Data Base
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # < - Init Recursive socket
        udp.settimeout(2) # < - Setting timeout
        resolver = self.conf['resolver']

        # - External resolving if specify external DNS server
        if resolver:
            result = Recursive.extresolve(self, resolver, query, udp)
            return result, None
        
        # - Internal resolging if it is empty
        result = Recursive.resolve(self, query, _ROOT, udp, 0)
        try: 
            # - Caching in DB at success resolving
            if int(result.rcode()) == 0 and result.answer:
                for records in result.answer:
                    for rr in records:
                        rdata= str(rr)
                        ttl = int(records.ttl)
                        if self.state is True and ttl > 0 and rdata:  # <- ON FUTURE, DYNAMIC CACHING BAD RESPONCE
                            rname = str(records.name)
                            rclass = CLASS[records.rdclass]
                            rtype = QTYPE[records.rdtype]
                            db.putC(rname, ttl, rclass, rtype, rdata)
            return  result# <- In anyway returns byte's packet and DNS Record data
        # -In any troubles at process resolving returns request with SERVFAIL code
        except:
            logging.exception('Stage: Return answer after resolving')
            result = dns.message.make_response(query)
            result.set_rcode(2)
            return result


    def extresolve(self, resolver, rdata, udp):
        try:
            dns.query.send_udp(udp, rdata, (resolver, 53))
            answer,_ = dns.query.receive_udp(udp,(resolver, 53))
            print(answer)
        except:
            answer = dns.message.make_response(rdata)
            answer.set_rcode(2)
        return answer



    def resolve(self, rdata:dns.message.Message, nslist, udp:socket, depth):
        if type(nslist) is not list:
            nslist = [nslist] # < - Create list of NameServers if it doesnt
        for ns in nslist:
            # -Checking current recursion depth-
            try:
                if depth >= self.maxdepth: 
                    raise Exception(f'Reach maxdetph - {self.maxdepth}!')# <- Set max recursion depth
                depth += 1
                '''print(f"{depth}: {ns}")''' # <- SOME DEBUG
            except:
                result = dns.message.make_response(rdata)
                result.set_rcode(2)
                logging.exception(f'Resolve: #1, qname - {result.question[0].name}')
                return result
            
                # -Trying to get answer from authority nameserver-
            try:
                rdata.set_rcode(0)
                dns.query.send_udp(udp, rdata, (ns, 53),1)
                result, ip = dns.query.receive_udp(udp,(ns, 53),1)
                if rdata.id != result.id:
                   raise DNSError('ID mismatch!')
                '''print(result,'\n\n')'''  # <- SOME DEBUG
            except socket.timeout:
                continue
            except dns.exception.DNSException:
                logging.exception(f'Resolve: #2')
                continue


            if result.answer: return result # <- If got a rdata then return it
            elif not result or not result.authority: # <- And if there is no authority NS then domain doesnt exist
                result.set_rcode(3) 
                return result
            
            NewNSlist = [] # <- IP list for authority NS
            if result.additional:
                for rr in result.additional:
                    ip = ipaddress.ip_address(str(rr[0]))
                    if ip.version == 4:
                        NewNSlist.append(str(ip))
            
                
            '''for authRR in result.auth:
                for arRR in result.ar:
                    if not arRR.rdata: continue
                    try:
                        ip = ipaddress.ip_address(str(arRR.rdata))
                        if (str(arRR.rname).lower() in str(authRR.rdata).lower() and # <- Check for fool
                            ip.version == 4): # <- Working only with ipv4 addresses
                            NewNSlist.append(str(ip))
                    except: 
                        logging.exception("message")
                        continue'''
            if not NewNSlist:
                for rr in result.authority[0]:
                    nsQuery = dns.message.make_query(rr, dns.rdatatype.A, dns.rdataclass.IN)
                    NSdata = Recursive.resolve(self, nsQuery, _ROOT, udp, depth)
                    try: 
                        if NSdata.rcode == dns.rcode.REFUSED:
                            continue
                        if NSdata.answer:
                            for rr in NSdata.answer:
                                NewNSlist.append(str(rr[0]))
                            break
                    except:
                        logging.exception('Resolve #3:') 
                        continue
            if NewNSlist:
                NewResult = Recursive.resolve(self, rdata, NewNSlist, udp, depth)
            else:
                result.set_rcode(3)
                return result
            return NewResult