#!./dns/bin/python3
import datetime
from multiprocessing import Process
import sys
import socket
import threading
import os
import time
import traceback
import dns.query
from sqlalchemy import create_engine
from authority import Authority
from caching import Caching
from recursive import Recursive
from confinit import getconf
from accessdb import checkconnect
from helper import Helper
from dnslib import DNSRecord
# --- Test working


# --- UDP socket ---
def qfilter(querie, addr):
    try:
        answer = _cache.getcache(querie)
        if not answer:
            answer, data = auth.authority(querie)
            if int(data.header.rcode) == 3 and recursion is True:
                answer, data = recursive.recursive(querie)
            if data:
                _cache.putcache(data)
        return answer
    except Exception as e:
        answer = querie
        print(traceback.format_exc())


def handle(udp:socket.socket, querie, addr):
    global _COUNT
    _COUNT +=1
    answer = qfilter(querie, addr)
    try: 
        udp.sendto(answer, addr)
    except:
        answer = DNSRecord.parse(querie)
        answer.header.set_rcode(2)
        udp.sendto(answer.pack(), addr)

    try:
        #print(f"Querie from {addr[0]}: {DNSRecord.parse(querie).questions}")
        #print(f"Answer to {addr[0]}: {DNSRecord.parse(answer).rr}")
        pass
    except Exception as e: pass

def udpsock(udp:socket.socket, ip, port):
    try:
        server_address = (ip, port)
        udp.bind(server_address)
        while True:
            query,_,addr = dns.query.receive_udp(udp)
            '''data, address = udp.recvfrom(1024)'''
            #if address[0] in ['95.165.134.11']:
            '''threading.Thread(target=handle, args=(udp, data, address)).start()'''
            threading.Thread(target=handle, args=(udp, query, addr)).start()
    except KeyboardInterrupt:
        udp.close()
        sys.exit()

def start(listens):
    global _COUNT
    _COUNT = 0
    # -Counter-
    #threading.Thread(target=counter).start()

    for ip in listens:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        threading.Thread(target=udpsock, args=(udp, ip, port)).start()


# --- Some Functions ---
def enginer(_CONF):
    try:  
        engine = create_engine(
            f"postgresql+psycopg2://{_CONF['dbuser']}:{_CONF['dbpass']}@{_CONF['dbhost']}:{_CONF['dbport']}/{_CONF['dbname']}"
        )
        checkconnect(engine)
        return engine
    except Exception as e: 
        print(e)
        sys.exit()


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
    engine1 = enginer(_CONF['init'])
    engine2 = enginer(_CONF['init'])

    # -Init Classes
    auth = Authority(engine1, _CONF['init'])
    recursive = Recursive(engine1, _CONF['init'])
    _cache = Caching(_CONF['init'])
    helper = Helper(engine2, _CONF['init'])

    # -ConfList-
    listens = _CONF['init']['listen-ip']
    port = _CONF['init']['listen-port']
    recursion = _CONF['init']['recursion']

    # -Launch server
    proc = [
        {helper.watcher: []}, #Start process which make control for DB
        {start: [listens]} #Start process with UDP listener
    ]
    try:  Parallel(proc)
    except KeyboardInterrupt: pass
    

