#!/home/dnspy/node/dns/bin/python3
import datetime
import ipaddress
import logging
import asyncio
import re
import struct
from logging.handlers import DEFAULT_UDP_LOGGING_PORT
from multiprocessing import Process, cpu_count, Pipe, current_process, Manager
import sys
import threading
import os
import time
import dns.rcode
import dns.query
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
from backend.accessdb import AccessDB, enginer
from backend.authority import Authority
from backend.caching import Caching
from backend.recursive import Recursive
from backend.objects import Query, Rules
from initconf import setup
from backend.helper import Helper
from backend.functions import echo
from backend.logger import LogServer, logsetup
from backend.objects import ThisNode
from netaddr import IPNetwork as CIDR, IPAddress as IP


_COUNT = 0

def handle(auth:Authority, recursive:Recursive, cache:Caching, data:bytes, addr:tuple, transport, rules):
    try:

        Q = Query(data, addr, transport)
        if Q.correct is False: return data

        for network in rules:
            if Q.ip in network:
                Q.set_rules(rules[network])
                break



        # -- DEBUG LOGGING BLOCK START --
        if logging.DEBUG >= logging.root.level and not logging.root.disabled:
            debug = True
            logging.debug(f"Get query {Q.get_meta(True)}. Permissions: '{Q.getperms(as_text=True)}.'")
        else: debug = None
        # -- DEBUG LOGGING BLOCK END --

        if Q.check.query() is False:
            if debug: logging.debug(f"Query {Q.get_meta(True)} is not Allowed. REFUSED.")
            result = Q.data[:3] + b'\x05' + Q.data[4:] # <- REFUSED RCODE
            if result: return result
            else: return None
     

        if Q.check.cache():
            result = cache.get(Q) # <- Try to take data from Cache
            if result:
                if debug: logging.debug(f"Query {Q.get_meta(True)} was returned from cache.")
                return data[:2]+result

        if Q.check.authority():
            result, response = auth.get(Q) # <- Try to take data from Authoirty
            if result:
                if debug: logging.debug(f"Query {Q.get_meta(True)} was returned from authority.")
                if response:
                    name = '%i-Authority' % Q.id
                    threading.Thread(target=cache.put, args=(Q, result, response, False, True), name=name).start()
                return result

        if Q.check.recursive():
            name = '%i-Recursive' % Q.id
            threading.Thread(target=recursive.get, args=(Q, cache), name=name).start()
            return None

        return echo(data,dns.rcode.REFUSED).to_wire()
    except:
        result = echo(data,dns.rcode.SERVFAIL)
        if result: info = result.question[0].to_text()
        else: info = "from %s, is malformed!" % addr
        logging.error(f'Fail handle query {info}', exc_info=(logging.DEBUG >= logging.root.level))


# --- UDP socket ---
class UDPserver(asyncio.DatagramProtocol):

    def __init__(self, _auth:Authority, _recursive:Recursive, _cache:Caching, CONF, rules, stat:bool=False) -> None:
        self.auth = _auth
        self.recursive = _recursive
        self.cache = _cache
        self.stat = stat
        self.rules = rules
        super().__init__()

    def connection_made(self, transport:asyncio.DatagramTransport,):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
   
            if self.stat is True:
                global _COUNT
                _COUNT += 1
            result = handle(self.auth, self.recursive, self.cache, data, addr, self.transport, self.rules)
            
            # -- INFO LOGGING BLOCK START --
            '''if logging.INFO >= logging.root.level and not logging.root.disabled:
                qid = int.from_bytes(data[:2],'big')
                rcode = dns.rcode.to_text(struct.unpack('>B',result[4:5])[0])
                logging.info(f"Return response ({qid}) to client {addr}. {rcode}'")'''
            # -- INFO LOGGING BLOCK END --


            if result:
                self.transport.sendto(result, addr)
        except:
            sock = self.transport.get_extra_info('socket')
            laddr = sock.getsockname()
            logging.error(f'UDP fail with handle query from {addr} at {laddr}', exc_info=(logging.DEBUG >= logging.root.level))
            self.transport.sendto(data, addr)

# -- TCP socket --
class TCPServer(asyncio.Protocol):

    def __init__(self, _auth:Authority, _recursive:Recursive, _cache:Caching, CONF, rules, stat:bool=False) -> None:
        self.auth = _auth
        self.recursive = _recursive
        self.cache = _cache
        self.stat = stat
        self.rules = rules
        super().__init__()    
    

    def connection_made(self, transport:asyncio.Transport):
        self.transport = transport

    def data_received(self, data):
        try:
            if self.stat is True:
                global _COUNT
                _COUNT += 1
            addr = self.transport.get_extra_info('peername')
            result = handle(self.auth, self.recursive, self.cache, data[2:], addr, self.transport, self.rules)
            

            # -- INFO LOGGING BLOCK START --
            '''if logging.INFO >= logging.root.level and not logging.root.disabled:
                qid = int.from_bytes(data[:2],'big')
                rcode = dns.rcode.to_text(struct.unpack('>B',result[4:5])[0])
                logging.info(f"Return response ({qid}) to client {addr}. {rcode}'")'''
            # -- INFO LOGGING BLOCK END --
            
            if result:
                l = struct.pack('>H',len(result))
                self.transport.write(l+result)
        except:
            sock = self.transport.get_extra_info('socket')
            laddr = sock.getsockname()
            logging.error(f'TCP fail with handle query from {addr} at {laddr}',exc_info=(logging.DEBUG >= logging.root.level))
            self.transport.write(data)

def listener(ip, port, _auth:Authority, _recursive:Recursive, _cache:Caching, stat, CONF, rules, isudp:bool=True,):
    loop = asyncio.new_event_loop()
    if isudp is True:
        addr = (ip, port)
        listen = loop.create_datagram_endpoint(lambda: UDPserver(_auth, _recursive, _cache, CONF, rules, stat), addr, reuse_port=True)
        transport, protocol = loop.run_until_complete(listen)
    else:
        listen = loop.create_server(lambda: TCPServer(_auth, _recursive, _cache, CONF, rules, stat),ip,port,reuse_port=True)
        transport = loop.run_until_complete(listen)
    try:
        logging.info(f'Started listen at {ip, port}')
        loop.run_forever()
        transport.close()
        loop.run_until_complete(transport.wait_closed())
        loop.close()
    except KeyboardInterrupt:
        pass
    except:
        logging.critical(f'Start new listener is fail {current_process().name}.', exc_info=(logging.DEBUG >= logging.root.level))
        sys.exit(1)


def launcher(statiscics:Pipe, CONF, _cache:Caching, _auth:Authority, _recursive:Recursive, rules):
    engine = enginer(CONF)
    db = AccessDB(engine, CONF)

    _auth.connect(db)
    logging.debug(f'AUTHORITY module connect to database is successful.')

    _cache.connect(db)
    logging.debug(f'CACHE module connect to database is successful.')

    # -Counter-
    stat = False
    if eval(CONF['GENERAL']['printstats']) is True:
        threading.Thread(target=counter, args=(statiscics,False)).start()
        stat = True

    # -MainListener IP-
    try:
        addresses = [ip for ip in re.sub('\s','',str(CONF['GENERAL']['listen-ip'])).split(',')]
        port = int(CONF['GENERAL']['listen-port'])
        l = []
        for ip in addresses:
            if ipaddress.ip_address(ip).version == 4:
                threading.Thread(target=listener,name='UDP-handler',args=(ip, port, _auth,_recursive,_cache, stat, CONF, rules, True)).start()
                threading.Thread(target=listener,name='TCP-handler',args=(ip, port, _auth,_recursive,_cache, stat, CONF, rules, False)).start()
                threading.Thread(target=_cache.corecash_cleaner, name='CC_Cleaner', daemon=True).start()
            else:
                logging.error(f"{ip} is not available")
        print(f"Core {current_process().name} Start listen to: ({', '.join(addresses)}): {port}")
    except Exception as e:
        logging.critical('some problem with main launcher', exc_info=(logging.DEBUG >= logging.root.level))


# --- Some Functions ---

def counter(pipe, output:bool = False):
    try:
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
    except:
        logging.error('Some problem with counter.', exc_info=(logging.DEBUG >= logging.root.level))
        
# --- Main Function ---
def start():
    CONF = setup()
    ThisNode.name = CONF['DATABASE']['node']
    logreciever = logsetup(CONF, __name__)
    rules = {}
    networks = CONF.items('ACCESS')
    networks.reverse()
    for opt in networks:
            cidr = CIDR(opt[0])
            args = set(opt[1]) - {'+'}
            Rule = Rules(cidr, *args)
            rules[Rule.addr] = Rule.access             
    try: 
        with Manager() as manager:
            # -Init Classes
            
            _cache = Caching(CONF, manager.dict(), manager.list())
            logging.debug('CACHE module was init successful')

            _recursive = Recursive(CONF)
            logging.debug('RECURSIVE module was init successful')

            _auth = Authority(CONF, _recursive, manager.dict(), manager.list())
            logging.debug('AUTHORITY module was init successful')
            
            
            helper = Helper(CONF, _cache, _auth, logreciever)
            logging.debug('HELPER module was init successful')  

            helper.connect(enginer(CONF))
            logging.debug('HELPER module connect to database was successful')  

            # -Start server for each core-
            Parents = []
            Stream = []
            for i in range(cpu_count()):
                try:
                    gather, stat = Pipe()
                    name = f'Core#{i}'
                    p = Process(target=launcher, args=(stat, CONF, _cache, _auth, _recursive, rules), name=name)
                    p.start()
                    logging.debug(f'New Listener ({name}) was started successful')
                    Stream.append(p)
                    Parents.append(gather)
                except:
                    logging.critical(f'Fail with up {name}', exc_info=(logging.DEBUG >= logging.root.level))
            # -Start background worker
            p = Process(target=helper.run, name='Helper')
            p.start()
            Stream.append(p)
            # -Counter-
            if eval(CONF['GENERAL']['printstats']) is True:
                threading.Thread(target=counter, args=(Parents,True), daemon=True).start()
                logging.debug(f'Gather statistics is enable')
            for p in Stream:
                p.join()

    except KeyboardInterrupt: 
        for p in Stream:
            p.terminate()
    except:
        logging.critical('Some problems with starting', exc_info=(logging.DEBUG >= logging.root.level))
        sys.exit(1)


if __name__ == "__main__":
    start()

    

