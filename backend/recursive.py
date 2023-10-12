#!/home/dnspy/server/dns/bin/python3
import asyncio
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

from backend.functions import echo

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

class Depth:

    count = 0

    def __init__(self) -> None:
        self.count = 0

class Recursive:

    def __init__(self, _CONF, iscache = True):
        try:
            self.conf = _CONF
            self.state = iscache
            self.maxdepth = int(_CONF['RECURSION']['maxdepth'])
            self.timeout = float(_CONF['RECURSION']['timeout'])
            self.retry = int(_CONF['RECURSION']['retry'])
            self.resolver = _CONF['RECURSION']['resolver']
        except:
            logging.critical('Initialization of recursive module is fail.')

    def recursive(self, P):
        # - External resolving if specify external DNS server
        try:
            data = P.data
            transport = P.transport
            query = dns.message.from_wire(data, continue_on_error=True, ignore_trailing=True)
            if self.resolver:
                result = self.extresolve(query)
                return result.to_wire(), result, True
            # - Internal resolving if it is empty
            random.shuffle(_ROOT)
            global depth
            for i in range(3):
                self.depth = Depth()
                result,_ = Recursive.resolve(self, query, _ROOT[i], transport)
                if isinstance(result, dns.message.Message): break
            if result:
                return result.to_wire(), result, True
            else:
                raise Exception('empty recursion result') 
        except:
            logging.error(f'Recursive search fail at \'{dns.name.from_wire(P.data,12)[0]}\'.')
            result = echo(data,dns.rcode.SERVFAIL,[dns.flags.RA])
            return result.to_wire(), result, False

    def resolve(self, query:dns.message.QueryMessage, ns, transport, depth = None):
        # -Checking current recursion depth-
        try:
            if depth: self.depth = depth
            self.depth.count += 1
            if self.depth.count >= self.maxdepth:
                raise Exception("Reach maxdetph - %s!" % self.maxdepth)# <- Set max recursion depth
            
            if _DEBUG in [1,3]: print(f"{depth}: {ns}") # <- SOME DEBUG
        except:
            logging.warning(f'Query \'{query.question[0].to_text()}\' was reached max recursion depth ({self.maxdepth}).')
            return echo(query,dns.rcode.REFUSED, [dns.flags.RA]), ns
        
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
            if dns.flags.TC in result.flags:
                result = dns.query.tcp(query, ns, self.timeout)
        except Exception:
            logging.error(f'Query\'{query.question[0].to_text()}\' is recursion fail.')
            return echo(query,dns.rcode.SERVFAIL, [dns.flags.RA]), ns

        if result.answer:
            if result.answer[-1].rdtype != result.question[0].rdtype and result.answer[-1].rdtype == 5:
                qcname = dns.message.make_query(
                    result.answer[-1][0].to_text(),
                    result.question[0].rdtype,
                    result.question[0].rdclass
                )
                cname_res, _ = self.resolve(qcname, random.choice(_ROOT), transport)
                if cname_res.answer:
                    [result.answer.append(rrset) for rrset in cname_res.answer]

        if result.answer or dns.flags.AA in result.flags:
            return result, ns # <- If got a rdata then return it
        
        if result.additional:
            random.shuffle(result.additional)
            for rr in result.additional:
                ns = str(rr[0])
                if ipaddress.ip_address(ns).version == 4:
                    result, _ = self.resolve(query, ns, transport)
                    if result:
                        if (result.rcode() in [dns.rcode.NOERROR, dns.rcode.REFUSED, dns.rcode.NXDOMAIN] 
                        or dns.flags.AA in result.flags):
                            return result, ns
            return None, ns

        elif result.authority:
            for authlist in result.authority:
                for rr in authlist.processing_order():
                    qname = dns.name.from_text(str(rr))
                    nsquery = dns.message.make_query(qname, dns.rdatatype.A, dns.rdataclass.IN)
                    for ns in _ROOT:
                        nsdata, _ = self.resolve(nsquery, ns, transport)
                        if nsdata:
                            if not nsdata.rcode() in [
                            dns.rcode.NOERROR, dns.rcode.REFUSED]:
                                continue
                            if nsdata.answer:
                                for rr in nsdata.answer:
                                    ns = str(rr[0])
                                    if ipaddress.ip_address(ns).version == 4:
                                        result, ns = self.resolve(query, ns, transport)
                                    if result:
                                        if (result.rcode() in [dns.rcode.NOERROR, dns.rcode.REFUSED, dns.rcode.NXDOMAIN]
                                           or dns.flags.AA in result.flags): 
                                            return result, ns
                                return None, ns
        return None, ns

    def extresolve(self, query:dns.message.Message):
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # < - Init Recursive socket
            udp.settimeout(2) # < - Setting timeout
            dns.query.send_udp(udp, query, (self.resolver, 53))
            answer,_ = dns.query.receive_udp(udp,(self.resolver, 53))
        except:
            answer = echo(query, dns.rcode.SERVFAIL, [dns.flags.RA])
            logging.error(f'resolve \'{query.question[0].to_text()}\' querie was failed on \'{self.resolver}\' nameserver')
        finally:
            return answer

