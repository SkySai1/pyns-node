#!./dns/bin/python3
from multiprocessing import Process
import sys
import socket
import threading
import os
import time
import traceback
from sqlalchemy import create_engine
from authority import Authority
from caching import Caching
from recursive import Recursive
from confinit import getconf
from accessdb import checkconnect
from dbcontrol import watcher
# --- Test working


# --- UDP socket ---
def qfilter(querie, addr):
    try:
        answer = _cache.getcache(querie)
        if not answer:
            answer, data = auth.authority(querie)
            if int(data.header.rcode) == 3 and recursion is True:
                answer, data = recursive.recursive(querie)
            _cache.putcache(data)
        return answer
    except Exception as e:
        answer = querie
        print(traceback.format_exc())


def handle(udp:socket.socket, querie, addr):
    global _COUNT
    _COUNT +=1
    answer = qfilter(querie, addr)
    udp.sendto(answer, addr)
    try: pass
        #print(f"Querie from {addr[0]}: {DNSRecord.parse(data).questions}")
        #print(f"Answer to {addr[0]}: {DNSRecord.parse(answer).rr}")
    except: pass

def udpsock(udp:socket.socket, ip, port):
    try:
        server_address = (ip, port)
        udp.bind(server_address)
        while True:
            data, address = udp.recvfrom(512)
            threading.Thread(target=handle, args=(udp, data, address)).start()
    except KeyboardInterrupt:
        udp.close()
        sys.exit()

def start(listens):
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
        l1,_,_ = os.getloadavg()
        print(f"{_COUNT}: {l1}")
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
        _CONF = getconf(sys.argv[1])
    except IndexError:
        print('Specify path to config file')
        sys.exit()

    # -Variables-
    _cache = Caching(_CONF['buffertime'])
    _COUNT = 0

    # -ConfList-
    engine1 = enginer(_CONF)
    engine2 = enginer(_CONF)
    auth = Authority(engine1)
    recursive = Recursive(_CONF['resolver'], engine1)
    listens = _CONF['listen-ip']
    port = _CONF['listen-port']
    recursion = _CONF['recursion']


    # -Launch server
    proc = [
        {watcher: [engine2]}, #Start process which make control for DB
        {start: [listens]} #Start process with UDP listener
    ]
    try:  Parallel(proc)
    except KeyboardInterrupt: pass
    

