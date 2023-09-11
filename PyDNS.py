#!/home/dnspy/server/dns/bin/python3
import datetime
import ipaddress
import logging
import asyncio
from multiprocessing import Process, cpu_count, Pipe, current_process, Manager
import pickle
import re
import sys
import socket
import threading
import os
import time
from typing import Any
import dns.rcode
import dns.query
import dns.message
from backend.authority import Authority
from backend.caching import Caching
from backend.recursive import Recursive
from initconf import getconf
from backend.helper import Helper
from backend.techincal import Tech
from backend.accessdb import enginer


_COUNT = 0
# --- UDP socket ---
class UDPserver(asyncio.DatagramProtocol):

    def connection_made(self, transport:asyncio.DatagramTransport,):
        self.transport = transport

    def datagram_received(self, data, addr):
        UDPserver.handle(self, data, addr)

    def railway(self, request:dns.message.Message, ip):
        try:
            return True
        except:
            logging.exception('SECURITY CHECK')
            return False         
    
    def thandle(self, data:bytes, addr:tuple):
        global _COUNT
        _COUNT +=1
        request = dns.message.from_wire(data)
        result = _cache.get(request, data[:2])
        self.transport.sendto(data, addr)


    def handle(self, data:bytes, addr:tuple):
        global _COUNT
        _COUNT +=1

        try:
            request = dns.message.from_wire(data)
            if UDPserver.railway(self, request, addr[0]) is True:
                result = _cache.get(request, data[:2])
                if result:
                    pack = result
                else:
                    '''result = _auth.authority(request)'''
                    '''if result.rcode() == dns.rcode.NXDOMAIN and bool(_CONF['RECURSION']['enable']) is True:'''
                    result = _recursive.recursive(request)
                    if result and type(result) is dns.message.QueryMessage:
                       threading.Thread(target=_cache.put, args=(result,)).start()
                       pack = result.to_wire(request.question[0].name)
                       pass
                    else:
                        raise Exception
            else:
                result = dns.message.make_response(request)
                result.set_rcode(5)
                pack = result.to_wire(request.question[0].name)
        except:
            logging.exception('UDP HANDLE')
            request = dns.message.from_wire(data)
            result = dns.message.make_response(request)
            result.set_rcode(2)
            pack = result.to_wire(request.question[0].name)
        finally:
            self.transport.sendto(pack, addr)
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

def newone(ip, port):
    addr = (ip, port)
    print(f"Core {current_process().name} Start listen to: {addr}")
    loop = asyncio.new_event_loop()
    listen = loop.create_datagram_endpoint(UDPserver, addr, reuse_port=True)
    transport, protocol = loop.run_until_complete(listen)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    transport.close()
    loop.close()

def launcher(c:Pipe, CONF, CACHE):
    # -Counter-
    if eval(CONF['GENERAL']['printstats']) is True:
        threading.Thread(target=counter, args=(c,)).start()

    # -DB Engines
    engine0 = enginer(CONF) # < - for recursive
    engine1 = enginer(CONF) # < - for caching

    # -Init Classes
    global _auth
    _auth = Authority(CONF)

    global _recursive
    _recursive = Recursive(engine0, CONF)

    global _cache
    _cache = CACHE
    #Caching(engine1, CONF)

    global _CONF
    _CONF = CONF # <- for asyncio class
    # -MainListener for every IP-
    ip = CONF['GENERAL']['listen-ip']
    port = CONF['GENERAL']['listen-port']
    try:
        if ipaddress.ip_address(ip).version == 4:
            threading.Thread(target=newone, args=(ip, port)).start()
    except:
        logging.exception('ERROR with listen on')


# --- Some Functions ---

def counter(pipe, output:bool = False):
    if output is True:
        while True:
            try:
                l1,l2,l3 = os.getloadavg()
                now = datetime.datetime.now().strftime('%m/%d %H:%M:%S')
                total = 0
                for parent in pipe:
                    data = parent.recv()
                    print(data)
                    total += data[1]
                print(f'{now}\t{total}\t{l1,l2,l3}')              
            except Exception as e: print(e)
            time.sleep(1)
    else:
        global _COUNT
        proc = current_process().name
        while True:
            pipe.send([proc, _COUNT])
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
def handler(CONF):

    # -DB Engines
    engineH = enginer(CONF) # < - for background

    # -Init Classes
    helper = Helper(engineH, CONF)

    try: 
        # -Start background worker
        Process(target=helper.watcher).start()

        # -Start server for each core-
        Parents = []
        Stream = []
        with Manager() as manager:
            _cache = Caching(enginer(CONF), CONF, manager.dict())
            for i in range(cpu_count()):
                parent, child = Pipe()
                name = f'#{i}'
                p = Process(target=launcher, args=(child, CONF, _cache), name=name)
                p.start()
                Stream.append(p)
                Parents.append(parent)

            # -Counter-
            if eval(CONF['GENERAL']['printstats']) is True:
                threading.Thread(target=counter, args=(Parents,True), daemon=True).start()
            
            for p in Stream:
                p.join()

        # -Start technical socket
        #Process(target=techsock).start()
        techsock()

    except KeyboardInterrupt: pass

if __name__ == "__main__":
    try:
        if sys.argv[1:]:
            path = os.path.abspath(sys.argv[1])
            if os.path.exists(path):
                CONF, state = getconf(sys.argv[1]) # <- for manual start
            else:
                print('Missing config file at %s' % path)
        else:
            thisdir = os.path.dirname(os.path.abspath(__file__))
            CONF, state = getconf(thisdir+'/config.ini')
        if state is False:
            raise Exception()
    except:
        print('Bad config file')
        sys.exit()
    handler(CONF)

    

