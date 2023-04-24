#!./dns/bin/python3
import sys
import socket
import threading
from sqlalchemy import create_engine
from authoritative import Authoritative
from caching import Caching
from recursive import recursive

# --- Test working


# --- UDP socket ---

def handle(udp, querie, addr):
    answer = cache.getcache(querie)
    if not answer:
        answer, rcode = auth.authoritative(querie)
    if rcode == 3:
        answer = recursive(querie)

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
    try:
        cache = Caching(None)
        engine = create_engine("postgresql+psycopg2://dnspy:dnspy23./@127.0.0.1:5432/dnspy")
        auth = Authoritative(engine, 1)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udpsock(udp, '77.73.132.32', 53)
    except KeyboardInterrupt:
        udp.close()
        sys.exit()
