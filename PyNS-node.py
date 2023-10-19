#!/home/dnspy/server/dns/bin/python3
import datetime
import ipaddress
import logging
import asyncio
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
from backend.objects import Packet, Rules
from initconf import getconf
from backend.helper import Helper
from backend.functions import echo
from backend.logger import LogServer, logsetup
from backend.objects import ThisNode
from netaddr import IPNetwork as CIDR, IPAddress as IP


_COUNT = 0

def warden(data, addr, transport, rules:dict) -> Packet:
    P = Packet(data,addr, transport)
    for network in rules:
        if P.ip in network:
            P.access.__dict__ = rules[network]
            break

    # -- INFO LOGGING BLOCK START --
    if logging.INFO >= logging.root.level and not logging.root.disabled:
        try:
            qid = struct.unpack('>H',data[:2])[0]
            name,l = dns.name.from_wire(data,12)
            qtype = struct.unpack('>B',data[14+l-1:14+l])[0]
            qclass = struct.unpack('>B',data[16+l-1:16+l])[0]
            logging.info(f"Get Query({qid}) from {addr} '{name.to_text()} {qclass} {qtype}'")
        except:
            logging.info(f"Query from {addr} is malformed!", exc_info=(logging.DEBUG >= logging.root.level))
    # -- INFO LOGGING BLOCK END --
    return P



def handle(auth:Authority, recursive:Recursive, cache:Caching, data:bytes, addr:tuple, transport, rules):
    try:
        P = warden(data, addr, transport, rules)
        # -- DEBUG LOGGING BLOCK START --
        if logging.DEBUG >= logging.root.level and not logging.root.disabled:
            debug = True
            try:
                qid = int.from_bytes(data[:2],'big')
                q = dns.message.from_wire(data,continue_on_error=True)
                question = q.question[0].to_text()
                logging.debug(f"Get query({q.id}) from {addr} is '{question}'. Permissions: '{P.getperms(as_text=True)}.'")
            except:
                qid = '00000'
                logging.debug(f"Query from {addr} is malformed!. Permissions: '{P.getperms(as_text=True)}.'", exc_info=(logging.DEBUG >= logging.root.level))        
        else: debug = None

        # -- DEBUG LOGGING BLOCK END --


        if P.check.query() is False:
            if debug: logging.debug(f"Query({qid}) from {addr} is not Allowed. REFUSED.")
            result = P.data[:3] + b'\x05' + P.data[4:] # <- REFUSED RCODE
            return result
     

        if P.check.cache():
            result, state = cache.get(P) # <- Try to take data from Cache
            if result:
                if debug: logging.debug(f"Query({qid}) from {addr} was returned from cache. Core cash is {state}.")
                return data[:2]+result

        if P.check.authority():
            result, response, iscache = auth.get(P) # <- Try to take data from Authoirty
            if result:
                if debug: logging.debug(f"Query({qid}) from {addr} was returned from authority.")
                if iscache is True:
                    threading.Thread(target=cache.put, args=(data, result, response, False, True)).start()
                return result

        if P.check.recursive():
            threading.Thread(target=recursive.recursive, args=(P, cache)).start()
            if debug: logging.debug(f"Query({qid}) from {addr} was returned after recrusive search.")
            return None
        else:
            return echo(data,dns.rcode.REFUSED).to_wire()
    except:
        result = echo(data,dns.rcode.SERVFAIL)
        logging.error(f'Fail handle query {result.question[0].to_text()}', exc_info=(logging.DEBUG >= logging.root.level))


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
        if self.stat is True:
            global _COUNT
            _COUNT += 1
        result = handle(self.auth, self.recursive, self.cache, data, addr, self.transport, self.rules)
        
        # -- INFO LOGGING BLOCK START --
        if logging.INFO >= logging.root.level and not logging.root.disabled:
            qid = int.from_bytes(data[:2],'big')
            if isinstance(result, dns.message.Message): rcode = dns.rcode.to_text(struct.unpack('>B',result[4:5])[0])
            else: rcode = 'UNKOWN'
            logging.info(f"Return response ({qid}) to client {addr}. {rcode}'")
        # -- INFO LOGGING BLOCK END --


        if result:
            self.transport.sendto(result, addr)

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
        if self.stat is True:
            global _COUNT
            _COUNT += 1
        addr = self.transport.get_extra_info('peername')
        result = handle(self.auth, self.recursive, self.cache, data[2:], addr, self.transport, self.rules)
        

        # -- INFO LOGGING BLOCK START --
        if logging.INFO >= logging.root.level and not logging.root.disabled:
            qid = int.from_bytes(data[:2],'big')
            rcode = dns.rcode.to_text(struct.unpack('>B',result[4:5])[0])
            logging.info(f"Return response ({qid}) to client {addr}. {rcode}'")
        # -- INFO LOGGING BLOCK END --
        
        if result:
            l = struct.pack('>H',len(result))
            self.transport.write(l+result)
        


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
        ip = CONF['GENERAL']['listen-ip']
        port = int(CONF['GENERAL']['listen-port'])
        l = []
        if ipaddress.ip_address(ip).version == 4:
            threading.Thread(target=listener,name='UDP-handler',args=(ip, port, _auth,_recursive,_cache, stat, CONF, rules, True)).start()
            threading.Thread(target=listener,name='TCP-handler',args=(ip, port, _auth,_recursive,_cache, stat, CONF, rules, False)).start()
            threading.Thread(target=_cache.debuff, daemon=True).start()
            print(f"Core {current_process().name} Start listen to: {ip, port}")
        else:
            logging.error(f"{ip} is not available")
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
def start(CONF):
    ThisNode.name = CONF['DATABASE']['node']
    logreciever = logsetup(CONF, __name__)
    rules = {}
    networks = CONF.items('ACCESS')
    networks.reverse()
    for opt in networks:
            cidr = CIDR(opt[0])
            args = set(opt[1])
            Rule = Rules(cidr, *args)
            rules[Rule.addr] = Rule.access.__dict__              
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
                    name = f'Listener#{i}'
                    p = Process(target=launcher, args=(stat, CONF, _cache, _auth, _recursive, rules), name=name)
                    p.start()
                    logging.debug(f'New Listener ({name}) was started successful')
                    Stream.append(p)
                    Parents.append(gather)
                except:
                    logging.critical(f'Fail with up {name}', exc_info=(logging.DEBUG >= logging.root.level))
            # -Start background worker
            p = Process(target=helper.watcher, name='Watcher')
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
    except Exception as e:
        logging.critical(f'Error with manual start - {e}')
        sys.exit(1)
    start(CONF)

    

