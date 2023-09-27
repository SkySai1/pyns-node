#!/home/dnspy/server/dns/bin/python3
import datetime
import ipaddress
import logging
import asyncio
from multiprocessing import Process, cpu_count, Pipe, current_process, Manager
import sys
import threading
import os
import time
import dns.rcode
import dns.query
import dns.message
from backend.authority import Authority
from backend.caching import Caching
from backend.recursive import Recursive
from initconf import getconf
from backend.helper import Helper
from backend.functions import echo


_COUNT = 0

def handle(auth:Authority, recursive:Recursive, cache:Caching, rec:bool, data:bytes, addr:tuple):
    try:        
        result = cache.get(data) # <- Try to take data from Cache
        if result: return data[:2]+result

        result = auth.get(data) # <- Try to take data from Authoirty
        if result:
            threading.Thread(target=cache.put, args=(result,False)).start()
            return result

        if rec is True:
            result = recursive.recursive(data)
            if result:
                threading.Thread(target=cache.put, args=(result,)).start()
                return result
        else:
            return echo(data,dns.rcode.REFUSED).to_wire()
    except:
        logging.exception('UDP HANDLE')
        return echo(data,dns.rcode.SERVFAIL).to_wire()


# --- UDP socket ---
class UDPserver(asyncio.DatagramProtocol):

    def __init__(self, _auth:Authority, _recursive:Recursive, _cache:Caching, CONF, stat:bool=False) -> None:
        self.auth = _auth
        self.recursive = _recursive
        self.cache = _cache
        self.stat = stat
        self.rec = eval(CONF['RECURSION']['enable']) 
        super().__init__()

    def connection_made(self, transport:asyncio.DatagramTransport,):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.stat is True:
            global _COUNT
            _COUNT += 1
        result = handle(self.auth, self.recursive, self.cache, self.rec, data, addr)
        self.transport.sendto(result, addr)

# -- TCP socket --
class TCPServer(asyncio.Protocol):

    def __init__(self, _auth:Authority, _recursive:Recursive, _cache:Caching, CONF, stat:bool=False) -> None:
        self.auth = _auth
        self.recursive = _recursive
        self.cache = _cache
        self.stat = stat
        self.rec = eval(CONF['RECURSION']['enable']) 
        super().__init__()    
    
    def connection_made(self, transport:asyncio.Transport):
        self.transport = transport

    def data_received(self, data):
        if self.stat is True:
            global _COUNT
            _COUNT += 1
        addr = self.transport.get_extra_info('peername')
        result = handle(self.auth, self.recursive, self.cache, self.rec, data[2:], addr)
        l = result.__len__().to_bytes(2,'big')
        #print(int.from_bytes(l,'big'), result.__len__())
        self.transport.write(l+result)


def listener(ip, port, _auth:Authority, _recursive:Recursive, _cache:Caching, stat, isudp:bool=True):
    loop = asyncio.new_event_loop()
    if isudp is True:
        addr = (ip, port)
        listen = loop.create_datagram_endpoint(lambda: UDPserver(_auth, _recursive, _cache, CONF, stat), addr, reuse_port=True)
        transport, protocol = loop.run_until_complete(listen)
    else:
        listen = loop.create_server(lambda: TCPServer(_auth, _recursive, _cache, CONF, stat),ip,port,reuse_port=True)
        transport = loop.run_until_complete(listen)
    try:
        threading.Thread(target=_cache.debuff, daemon=True).start()
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        transport.close()
        loop.run_until_complete(transport.wait_closed())
        loop.close()

def launcher(statiscics:Pipe, CONF, _cache:Caching, _auth:Authority):
    # -Counter-
    stat = False
    if eval(CONF['GENERAL']['printstats']) is True:
        threading.Thread(target=counter, args=(statiscics,False)).start()
        stat = True

    _recursive = Recursive(CONF)

    # -MainListener IP-
    try:
        ip = CONF['GENERAL']['listen-ip']
        port = int(CONF['GENERAL']['listen-port'])
        l = []
        if ipaddress.ip_address(ip).version == 4:
            threading.Thread(target=listener,args=(ip, port, _auth,_recursive,_cache, stat)).start()
            threading.Thread(target=listener,args=(ip, port, _auth,_recursive,_cache, stat, False)).start()
            print(f"Core {current_process().name} Start listen to: {ip, port}")
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
        
# --- Main Function ---
def start(CONF):

    try: 
        with Manager() as manager:
            # -Init Classes
            
            _cache = Caching(CONF, manager.dict(), manager.list())
            _auth = Authority(CONF, manager.dict(), manager.list())
            helper = Helper(CONF, _cache, _auth)

            # -Start server for each core-
            Parents = []
            Stream = []
            for i in range(cpu_count()):
                gather, stat = Pipe()
                name = f'#{i}'
                p = Process(target=launcher, args=(stat, CONF, _cache, _auth), name=name)
                p.start()
                Stream.append(p)
                Parents.append(gather)
            
            # -Start background worker
            Stream.append(Process(target=helper.watcher).start())

            # -Counter-
            if eval(CONF['GENERAL']['printstats']) is True:
                threading.Thread(target=counter, args=(Parents,True), daemon=True).start()
            
            for p in Stream:
                p.join()

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
    start(CONF)

    

