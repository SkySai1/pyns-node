#!./dns/bin/python3
import sys
import socket
import threading
import os
import time
from sqlalchemy import create_engine
from authority import Authority
from caching import Caching
from recursive import Recursive
from confinit import getconf
from accessdb import checkconnect

# --- Test working


# --- UDP socket ---

def handle(udp, querie, addr):
    global _COUNT
    _COUNT +=1
    try:
        answer = _cache.getcache(querie)
        if not answer:
            answer, rcode = auth.authority(querie)
            if rcode == 3 and recursion is True:
                answer = recursive.recursive(querie)
    except Exception as e:
        answer = querie
        print(e)

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
            data, address = udp.recvfrom(512) #receive(udp)
            threading.Thread(target=handle, args=(udp, data, address)).start()
    except KeyboardInterrupt:
        udp.close()
        sys.exit()

def counter():
    global _COUNT
    while True:
        l1,_,_ = os.getloadavg()
        print(f"{_COUNT}: {l1}")
        _COUNT = 0
        time.sleep(1)

# --- Main Function ---
if __name__ == "__main__":
    try: 
        _CONF = getconf(sys.argv[1])
    except IndexError:
        print('Specify path to config file')
        sys.exit()

    # -Variables-
    _cache = Caching()
    _COUNT = 0

    # -ConfList-
    engine = create_engine(
        f"postgresql+psycopg2://{_CONF['dbuser']}:{_CONF['dbpass']}@{_CONF['dbhost']}:{_CONF['dbport']}/{_CONF['dbname']}"
    )
    auth = Authority(engine, _CONF['buffertime'])
    recursive = Recursive(_CONF['resolver'])
    listens = _CONF['listen-ip']
    port = _CONF['listen-port']
    recursion = _CONF['recursion']

    try:  checkconnect(engine)
    except Exception as e: 
        print(e)
        sys.exit()
    threading.Thread(target=counter).start()
    for ip in listens:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        threading.Thread(target=udpsock, args=(udp, ip, port)).start()
