import socket
import threading
import time
import random
from dnslib import DNSRecord, QTYPE
from caching import Caching

_RESOLVER = '127.0.0.53'
_ANSWER = []
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

def recursive(packet):
    result = extresolve(packet)
    parsed = DNSRecord.parse(result)
    ttl = parsed.get_a().ttl
    qname = str(parsed.get_q().qname)
    qtype = QTYPE[parsed.get_q().qtype]
    cache = Caching(ttl)
    cache.putcache(result, qname, qtype)
    return result


def extresolve(q):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)
    udp.sendto(q, (_RESOLVER, 53))
    answer = udp.recv(512) 
    return answer


# --- Dont work ---
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