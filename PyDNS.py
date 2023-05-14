#!./dns/bin/python3
import datetime
import logging
import asyncio
from multiprocessing import Process, cpu_count
import socketserver
import sys
import socket
import threading
import os
import time
import dns.rcode
import dns.query
import dns.message
from authority import Authority
from caching import Caching
from recursive import Recursive
from confinit import getconf
from helper import Helper
from techincal import Tech
from accessdb import enginer
# --- Test working


# --- UDP socket ---
class UDPserver(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        UDPserver.handle(self.transport, data, addr)

    def qfilter(rdata:dns.message.Message, packet:bytes, addr):
        answer = _cache.getcache(rdata, packet)
        if not answer:
            data = auth.authority(rdata)
            if data.rcode() == dns.rcode.NXDOMAIN and recursion is True:
                data = recursive.recursive(rdata)
            if data:
                _cache.putcache(data)
                #threading.Thread(target=_cache.putcache, args=(data,)).start()
                answer = data.to_wire(rdata.question[0].name)
        return answer
    
    def handle(transport:asyncio.DatagramTransport, data:bytes, addr:tuple):
        global _COUNT
        _COUNT +=1
        try:
            rdata = dns.message.from_wire(data)
            answer = UDPserver.qfilter(rdata, data, addr)
        except:
            #logging.exception('HANDLE')
            answer = data
        transport.sendto(answer, addr)
        try:
            #print(f"Querie from {addr[0]}: {DNSRecord.parse(querie).questions}")
            #print(f"Answer to {addr[0]}: {DNSRecord.parse(answer).rr}")
            pass
        except Exception as e: pass


def techsock():
    try:
        tech = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tech.bind(('127.0.0.1', 5300))
        while True:
            tech.listen(3)
            conn, addr = tech.accept()
            data = conn.recv(4096)
            t = Tech(_CONF['init'],data,addr)
            t.worker()
    except KeyboardInterrupt:
        tech.close()
        sys.exit()

def newoneif(addr):
    print(f"Start listen to: {addr}")
    loop = asyncio.new_event_loop()
    listen = loop.create_datagram_endpoint(UDPserver, addr)
    transport, protocol = loop.run_until_complete(listen)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    transport.close()
    loop.close()

def start(listens, port):
    global _COUNT
    _COUNT = 0
    # -Counter-
    if _CONF['init']['printstats'] is True:
        threading.Thread(target=counter).start()

    # -MainListener for every IP-
    for ip in listens:
        #threading.Thread(target=newoneif, args=((ip, port),)).start()
        for i in range(cpu_count()):
            print(i)

    # -TechSocket-
    threading.Thread(target=techsock).start()


# --- Some Functions ---

def counter():
    global _COUNT
    while True:
        l1,l2,l3 = os.getloadavg()
        now = datetime.datetime.now().strftime('%m/%d %H:%M:%S')
        print(f"{now}\t{_COUNT}\t{l1} {l2} {l3}")
        _COUNT = 0
        time.sleep(1)
        
# Мультипроцессинг:
def Parallel(data):
    proc = []
    for pos in data:
        for fn in pos:
            if type(pos[fn]) is dict:
                p = Process(target=fn, kwargs=pos[fn])
                p.start()
                proc.append(p)
            else:
                p = Process(target=fn, args=pos[fn])
                p.start()
                proc.append(p)
    for p in proc:
        p.join()


# --- Main Function ---
if __name__ == "__main__":
    try:
        _CONF = {}
        _CONF['init'] = getconf(sys.argv[1])
    except IndexError:
        print('Specify path to config file')
        sys.exit()

    # -DB Engines
    engine1 = enginer(_CONF['init']) # < - for main work
    engine2 = enginer(_CONF['init']) # < - for caching
    engine3 = enginer(_CONF['init']) # < - for background
    # -Init Classes
    auth = Authority(engine1, _CONF['init'])
    recursive = Recursive(engine1, _CONF['init'])
    _cache = Caching(_CONF['init'], engine2)
    helper = Helper(engine3, _CONF['init'])

    # -ConfList-
    listens = _CONF['init']['listen-ip']
    port = _CONF['init']['listen-port']
    recursion = _CONF['init']['recursion']

    # -Launch server
    proc = [
        {helper.watcher: []}, #Start process which make control for DB
        {start: [listens, port]} #Start process with UDP listener
    ]
    try:  Parallel(proc)
    except KeyboardInterrupt: pass
    

