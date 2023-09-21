#!/home/dnspy/server/dns/bin/python3
import ipaddress
import random
import socket
import threading
import dns.message
import dns.rrset
import dns.query
import dns.exception
import dns.rdatatype
import dns.rdataclass
import dns.rcode
import dns.name
import dns.flags
import logging

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

    def __init__(self, _CONF, iscache = True):
        try:
            self.conf = _CONF
            self.state = iscache
            self.depth = int(_CONF['RECURSION']['maxdepth'])
            self.timeout = float(_CONF['RECURSION']['timeout'])
            self.retry = int(_CONF['RECURSION']['retry'])
            self.resolver = _CONF['RECURSION']['resolver']
        except:
            logging.exception('ERROR with recursive init')

    def recursive(self, data:bytes):
        # - External resolving if specify external DNS server
        try:
            query = dns.message.from_wire(data)
            if self.resolver:
                result = Recursive.extresolve(self, self.resolver, query)
                return result, None
            # - Internal resolving if it is empty

            random.shuffle(_ROOT)
            global depth
            for i in range(3):
                depth = 0
                result,_ = Recursive.resolve(self, query, _ROOT[i])
                if type(result) is dns.message.QueryMessage: break
            if result and dns.flags.AA in result.flags and not result.answer: 
                result.set_rcode(3)
            if not result: 
                result = dns.message.make_response(query)
                result.set_rcode(2)
            #result.flags += dns.flags.RA
            return  result.to_wire()# <- In anyway returns byte's packet and DNS Record data
        except: # <-In any troubles at process resolving returns request with SERVFAIL code
            logging.exception(f'Stage: Recursive: {query.question}')
            result = dns.message.make_response(query)
            result.set_rcode(2)
            return result.to_wire()

    def resolve(self, query:dns.message.QueryMessage, ns):
        # -Checking current recursion depth-
        try:
            global depth
            depth += 1
            if depth >= self.depth:
                raise Exception("Reach maxdetph - %s!" % self.depth)# <- Set max recursion depth
            
            if _DEBUG in [1,3]: print(f"{depth}: {ns}") # <- SOME DEBUG
        except:
            result = dns.message.make_response(query)
            result.set_rcode(5)
            #logging.exception(f'Resolve: #1, qname - {result.question[0].name}')
            return result, ns
        
        # -Trying to get answer from specifing nameserver-
        try:
            for i in range(self.retry):
                try:
                    result = dns.query.udp(query, ns, self.timeout)
                    break
                except dns.exception.Timeout as e:
                    result = None
                    pass
            if _DEBUG in [2,3]: print(result,'\n\n')  # <- SOME DEBUG
            if not result: 
                return None, ns
            if query.id != result.id:
                raise Exception('ID mismatch!')
        except Exception:
            logging.exception(f'Resolve: #2, qname - {result.question[0].name}')
            result = dns.message.make_response(query)
            result.set_rcode(2)
            return result, ns

        if result.answer or dns.flags.AA in result.flags:
            return result, ns # <- If got a rdata then return it
        
        if result.additional:
            random.shuffle(result.additional)
            for rr in result.additional:
                ns = str(rr[0])
                if ipaddress.ip_address(ns).version == 4:
                    result, ns = Recursive.resolve(self,query, ns)
                    if result and result.rcode() in [
                        dns.rcode.NOERROR, dns.rcode.REFUSED]: return result, ns
            return None, ns

        elif result.authority:
            for authlist in result.authority:
                for rr in authlist.processing_order():
                    qname = dns.name.from_text(str(rr))
                    nsquery = dns.message.make_query(qname, dns.rdatatype.A, dns.rdataclass.IN)
                    for ns in _ROOT:
                        nsdata, _ = Recursive.resolve(self, nsquery, ns)
                        if nsdata:
                            if not nsdata.rcode() in [
                            dns.rcode.NOERROR, dns.rcode.REFUSED]:
                                continue
                            if nsdata.answer:
                                for rr in nsdata.answer:
                                    ns = str(rr[0])
                                    if ipaddress.ip_address(ns).version == 4:
                                        result, ns = Recursive.resolve(self, query, ns)
                                    if result and result.rcode() in [
                                        dns.rcode.NOERROR, dns.rcode.REFUSED]: return result, ns
                                return None, ns
        return None, ns

    def extresolve(self, resolver, query):
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # < - Init Recursive socket
            udp.settimeout(2) # < - Setting timeout
            dns.query.send_udp(udp, query, (resolver, 53))
            answer,_ = dns.query.receive_udp(udp,(resolver, 53))
            print(answer)
        except:
            answer = dns.message.make_response(query)
            answer.set_rcode(2)
        return answer

