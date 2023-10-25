#!/home/dnspy/server/dns/bin/python3
import ipaddress
import random
import re
import socket
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
from netaddr import IPAddress as IP
from backend.caching import Caching
from backend.functions import echo
from backend.objects import Query

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
_RU = [
    "193.232.128.6",        #a.dns.ripn.net.
    "194.85.252.62",        #b.dns.ripn.net.
    "194.190.124.17",       #d.dns.ripn.net.
    "193.232.142.17",       #e.dns.ripn.net.
    "193.232.156.17",       #f.dns.ripn.net.
]

_COM = [
    "192.5.6.30",           #a.gtld-servers.net
    "192.33.14.30",         #b.gtld-servers.net
    "192.26.92.30",         #c.gtld-servers.net
    "192.31.80.30",         #d.gtld-servers.net
    "192.12.94.30",         #e.gtld-servers.net
    "192.35.51.30",         #f.gtld-servers.net
    "192.42.93.30",         #g.gtld-servers.net
    "192.54.112.30",        #h.gtld-servers.net
    "192.43.172.30",        #i.gtld-servers.net
    "192.48.79.30",         #j.gtld-servers.net
    "192.52.178.30",        #k.gtld-servers.net
    "192.41.162.30",        #l.gtld-servers.net
    "192.55.83.30",         #m.gtld-servers.net
]

TLD = {
    b'com': _COM,
    b'ru': _RU
}

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
            self.listen = [IP(ip) for ip in re.sub('\s','',str(_CONF['GENERAL']['listen-ip'])).split(',')]
            self.state = iscache
            self.maxdepth = int(_CONF['RECURSION']['maxdepth'])
            self.timeout = float(_CONF['RECURSION']['timeout'])
            self.retry = int(_CONF['RECURSION']['retry'])
            self.resolver = _CONF['RECURSION']['resolver']
            self.iscache = eval(_CONF['CACHING']['upload'])
        except:
            logging.critical('Initialization of recursive module is fail.', exc_info=(logging.DEBUG >= logging.root.level))

    def recursive(self, P:Query, cache:Caching):
        # - External resolving if specify external DNS server
        try:
            if not P.query: 
                try: P.query = dns.message.from_wire(P.data, continue_on_error=True, ignore_trailing=True)
                except:
                    logging.warning(f"Query from {P.addr} is malformed!") 
                    return
            if self.resolver:
                result = self.extresolve(P.query)
            
            # - Internal resolving if it is empty
            else:
                try:
                    NS = TLD.get(P.query.question[0].name[1])
                    if not NS: NS = _ROOT
                except:
                    NS = _ROOT
                random.shuffle(NS)
                for i in range(3):
                    D = Depth()
                    result,_ = self.resolve(P.query, NS[i], P.transport, D)
                    if isinstance(result, dns.message.Message): break
                    if i >=1: NS = random.choice(_ROOT)

        except:
            try: info = dns.name.from_wire(P.data,12)[0]
            except: info = f'from {P.addr}. Querie is malformed!'
            logging.error(f'Recursive search is fail \'{info}\'.', exc_info=(logging.DEBUG >= logging.root.level))
            result = echo(P.data,dns.rcode.SERVFAIL,[dns.flags.RA])
        finally:
            if result:
                P.response(result.to_wire())
                cache.put(P.data, result.to_wire(), result, self.iscache)

    def resolve(self, query:dns.message.QueryMessage, ns, transport, depth:Depth):
        # -Checking current recursion depth-
        try:
            depth.count+=1
            if depth.count >= self.maxdepth:
                raise Exception("Reach maxdetph - %s!" % self.maxdepth)# <- Set max recursion depth
            
            if _DEBUG in [1,3]: print(f"{depth}: {ns}") # <- SOME DEBUG
        except:
            logging.warning(f'Query \'{query.question[0].to_text()}\' was reached max recursion depth ({self.maxdepth}).')
            return echo(query,dns.rcode.REFUSED, [dns.flags.RA]), ns
        
        # -Trying to get answer from specifing nameserver-
        try:
            for i in range(self.retry):
                try:
                    if IP(ns) in self.listen:
                        logging.warning(f"Query loop detected at {query.question[0].to_text()}")
                        result = echo(query,dns.rcode.SERVFAIL)
                        return result, ns
                    if ipaddress.ip_address(ns):
                        result = dns.query.udp(query, ns, self.timeout)
                    break
                except dns.exception.Timeout as e:
                    result = None
                    pass
                except ValueError:
                    result = None
                    break
            if _DEBUG in [2,3]: print(result,'\n\n')  # <- SOME DEBUG
            if not result: 
                return None, ns
            if query.id != result.id:
                raise Exception('ID mismatch!')
            if dns.flags.TC in result.flags:
                result = dns.query.tcp(query, ns, self.timeout)
        except dns.exception.Timeout:
            logging.warning(f'Query\'{query.question[0].to_text()}\' is timeout on {ns}.', exc_info=(logging.DEBUG >= logging.root.level))
            return None, ns
        except Exception:
            logging.error(f'Query\'{query.question[0].to_text()}\' is recursion fail.', exc_info=(logging.DEBUG >= logging.root.level))
            return echo(query,dns.rcode.SERVFAIL, [dns.flags.RA]), ns

        if result.answer:
            if result.answer[-1].rdtype != result.question[0].rdtype and result.answer[-1].rdtype == 5:
                qcname = dns.message.make_query(
                    result.answer[-1][0].to_text(),
                    result.question[0].rdtype,
                    result.question[0].rdclass
                )
                cname_res, _ = self.resolve(query=qcname, ns=random.choice(_ROOT), transport=transport)
                if cname_res.answer:
                    [result.answer.append(rrset) for rrset in cname_res.answer]

        if result.answer or dns.flags.AA in result.flags:
            return result, ns # <- If got a rdata then return it
        
        if result.additional:
            random.shuffle(result.additional)
            for rr in result.additional:
                ns = str(rr[0])
                if rr.rdtype == dns.rdatatype.A and ipaddress.ip_address(ns).version == 4:
                    result, _ = self.resolve(query=query, ns=ns, transport=transport, depth=depth)
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
                        nsdata, _ = self.resolve(query=nsquery, ns=ns, transport=transport, depth=depth)
                        if nsdata:
                            if not nsdata.rcode() in [
                            dns.rcode.NOERROR, dns.rcode.REFUSED]:
                                continue
                            if nsdata.answer:
                                for rr in nsdata.answer:
                                    ns = str(rr[0])
                                    if rr.rdtype == dns.rdatatype.A and ipaddress.ip_address(ns).version == 4:
                                        result, ns = self.resolve(query=query, ns=ns, transport=transport, depth=depth)
                                    if result:
                                        if (result.rcode() in [dns.rcode.NOERROR, dns.rcode.REFUSED, dns.rcode.NXDOMAIN]
                                           or dns.flags.AA in result.flags): 
                                            return result, ns
                                return None, ns
        return None, ns

    def extresolve(self, query:dns.message.Message):
        try:
            answer = None
            for i in range(3):
                try:
                    answer = dns.query.udp(query, self.resolver, 2)
                except:
                    answer = dns.query.tcp(query, self.resolver, 2)
        except:
            answer = echo(query, dns.rcode.SERVFAIL, [dns.flags.RA])
            logging.error(f'Resolve \'{query.question[0].to_text()}\' querie was failed on \'{self.resolver}\' nameserver', exc_info=(logging.DEBUG >= logging.root.level))
        finally:
            return answer

