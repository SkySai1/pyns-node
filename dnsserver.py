#!./dns/bin/python3
import os
import sys
import socket
import time
import threading
import datetime
from dnslib import DNSRecord, DNSHeader, DNSQuestion, QTYPE, CLASS, QR, RCODE, OPCODE
from dnslib import RR, A
from sqlalchemy import create_engine
from accessdb import get

# --- Test working

# --- Cahe job ---

def getcache(data):
    global _CACHE
    qname = str(DNSRecord.parse(data).get_q().qname)
    qtype = QTYPE[DNSRecord.parse(data).get_q().qtype]
    if qname+qtype in _CACHE:
        answer = data[:2] + _CACHE[qname+qtype][2:]
        #print('cached')
        return answer
    return None

def putcache(data, qname, qtype):
    record = qname+qtype
    global _CACHE
    if not record in _CACHE:
        _CACHE[record] = data
        threading.Thread(target=clearcache, args=(record,)).start()
        #print(f'{datetime.datetime.now()}: {record} was cached')

def clearcache(cache):
    global _CACHETIME
    time.sleep(_CACHETIME)
    global _CACHE
    if cache in _CACHE:
        del _CACHE[cache]
        #print(f'{datetime.datetime.now()}: {cache} was removed from cache')

# --- UDP socket ---

def resolve(packet):
    data = DNSRecord.parse(packet)
    Q = {}
    Q['name'] = str(data.get_q().qname)
    Q['class'] = CLASS[data.get_q().qclass]
    Q['type'] = QTYPE[data.get_q().qtype]
    result = get(engine, Q['name'], Q['class'], Q['type'])
    return result, data

def makequerie(result, q):
    answer = q.reply()
    for col in result:
        for row in col:
            answer.add_answer(*RR.fromZone(
            f"{row.name} {str(row.ttl)} {row.dclass} {row.type} {row.data}")
            )
    data = answer.pack()
    threading.Thread(
        target=putcache, 
        args=(data, str(q.get_q().qname), QTYPE[q.get_q().qtype])
        ).start()
    return data

def handle(udp, data, addr):
    answer = getcache(data)
    if not answer:
        result, q = resolve(data)
        answer = makequerie(result, q)
    udp.sendto(answer, addr)
    try: pass
        #print(f"Querie from {addr[0]}: {DNSRecord.parse(data).questions}")
        #print(f"Answer to {addr[0]}: {DNSRecord.parse(answer).rr}")
    except: pass

def udpsock(udp, ip, port):
    server_address = (ip, port)
    udp.bind(server_address)
    while True:
        data, address = udp.recvfrom(512) #receive(udp)
        threading.Thread(target=handle, args=(udp, data, address)).start()

# --- Main Function ---
if __name__ == "__main__":
    _CACHE = {}
    _CACHETIME = 1
    try:
        engine = create_engine("postgresql+psycopg2://dnspy:dnspy23./@localhost:5432/dnspy")
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udpsock(udp, '77.73.132.32', 53)
    except KeyboardInterrupt:
        udp.close()
        sys.exit()
