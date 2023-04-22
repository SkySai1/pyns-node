#!./dns/bin/python3
import os
import sys
import socket
import datetime
import threading
from dnslib import DNSRecord, DNSHeader, QTYPE, CLASS, QR, RCODE, OPCODE
from dnslib import RR, A
from accessdb import get


#UDP SOCK
def resolve(data):
    data = DNSRecord.parse(data)
    Q = {}
    Q['name'] = str(data.get_q().qname)
    Q['class'] = CLASS[data.get_q().qclass]
    Q['type'] = QTYPE[data.get_q().qtype]
    result = get(Q['name'], Q['class'], Q['type'])
    return result, data

def makequerie(result, q):
    answer = q.reply()
    for col in result:
        for row in col:
           answer.add_answer(*RR.fromZone(
            f"{row.name} {str(row.ttl)} {row.dclass} {row.type} {row.data}")
            )
    return answer.pack()

def handle(udp, data, addr):
    result, q = resolve(data)
    answer = makequerie(result, q)
    udp.sendto(answer, addr)
    try:
        print(f"Querie: {DNSRecord.parse(data).questions}")
        print(f"Answer: {DNSRecord.parse(answer).rr}")
    except: pass

def udpsock(udp, ip, port):
    server_address = (ip, port)
    udp.bind(server_address)
    while True:
        data, address = udp.recvfrom(512) #receive(udp)
        threading.Thread(target=handle, args=(udp, data, address)).start()

# --- Main Function ---
if __name__ == "__main__":
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udpsock(udp, '77.73.132.32', 53)
    except KeyboardInterrupt:
        udp.close()
        sys.exit()
