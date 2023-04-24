#!./dns/bin/python3
import sys
import socket
import threading
import struct
from sqlalchemy import create_engine
from authoritative import Authoritative
from caching import Caching
from recursive import Recursive
from confinit import getconf

# --- Test working


# --- UDP socket ---

def handle(udp, querie, addr):
    answer = cache.getcache(querie)
    if not answer:
        answer, rcode = auth.authoritative(querie)
        if rcode == 3 and allow_recursion is True:
            answer = recursive.recursive(querie)

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



# --- Main Function ---
if __name__ == "__main__":
    try: 
        _CONF = getconf(sys.argv[1])
    except IndexError:
        print('Specify path to config file')
        sys.exit()

    cache = Caching()

    # -ConfList-
    engine = create_engine("postgresql+psycopg2://dnspy:dnspy23./@127.0.0.1:5432/dnspy")
    auth = Authoritative(engine, int(_CONF['buffertime']))
    recursive = Recursive(_CONF['resolver'])
    listens = _CONF['listen-ip'].split(' ')
    port = int(_CONF['listen-port'])
    allow_recursion = _CONF['allowrecursion']
    
    for ip in listens:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        threading.Thread(target=udpsock, args=(udp, ip, port)).start()