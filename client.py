#!./dns/bin/python3
import datetime
import logging
import os
import socket
import sys

from prettytable import PrettyTable
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, Session
from backend.accessdb import AccessDB, checkconnect
from backend.transfer import Transfer
from backend.zonemanager import Zonemaker
from createconf import getconf

def commandsender(command:tuple):
    c1, c2, c3 = command
    command = '%s/%s/%s' % (c1,c2,c3)
    if c1 == 'axfr':
        if c2 == 'get':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(('127.0.0.1', 5300))
            s.sendall(command.encode())
            s.settimeout(2)
    pass



def zonecreator():
    data = {}
    zone = {}
    data['name'] = inputer("- Write to zone name:\n",str)
    if data['name'][-1] != '.': data['name'] += '.'

    while True:
        data['type'] = inputer("- Specify one of zone's type: 'm' - master (default), 's' - slave \n",str, 'm')
        if data['type'] == 'm': 
            data['type'] = 'master'
            break
        elif data['type'] == 's':
            data['type'] = 'slave'
            break
        print('- Chooose "m" or "s" or enter empty line')
    if data['type'] == 'master':
        data['NS'] = inputer(f"- Write to Main Name Server, ({data['name']} by default):\n",str, data['name'])
        data['email'] = inputer("- Write to Admin's email, replase '@' by '.' (dot) like admin.google.com (dns.localhost. by default):\n",str, 'dns.localhost.')
        data['serial'] = int(datetime.datetime.now().strftime('%Y%m%d01'))
        data['refresh'] = inputer("- Write to refresh time (28800 by default):\n", int, 28800)
        data['retry'] = inputer("- Write to expire time (3600 by default):\n", int, 3600)
        data['expire'] = inputer("- Write to expire time (86400 by default):\n", int, 86400)
        data['ttl'] = inputer("- Write to ttl (60 by default):\n",int, 60)
        rdata = f"{data['NS']} {data['email']} {data['serial']} {data['refresh']} {data['retry']} {data['expire']} {data['ttl']}"
        soa = {
            "name": data['name'],
            "ttl": data['ttl'],
            "type": 'SOA',
            "data": rdata
            }
        Z = Zonemaker(_CONF['init'])
        Z.zonecreate(data)
    if data['type'] == 'slave':
        data['master'] = inputer("- Specify IP of master:\n",str)
        data['tsig'] = inputer("- Specify TSIG key if you need it (none by default):\n",str, None)
        axfr = Transfer(_CONF['init'], data['name'], data['master'], data['tsig'])
        axfr.getaxfr()
    

    printzones()

def inputer(text, what, default = False):
    while True:
        try:
            pre = input(text).strip()
            if not pre:
                raise ValueError
            value = what(pre)
            return value
        except ValueError:
            if default is not False and not pre: 
                value = default
                return value
            print(f"\n- it must a {what.__name__}!")
        except KeyboardInterrupt:
            print("- Aborted!")
            sys.exit()


def printzones():
    zlist = db.getZones()
    if zlist:
        header = ['ID', 'Name', 'Type']
        width = (os.get_terminal_size().columns - 48 - header.__len__()*2 - header.__len__())
        t = PrettyTable(header)
        t._max_width = {'ID': 5, 'Name':width, 'Type': 7}
        t.align = 'l'
        for obj in zlist:
            for row in obj:
                try:
                    t.add_row([row.id, row.name, row.type])
                except:
                    logging.exception('zone table')
        print(t)
    action = int(input("Choose action:\n 0. Return to back\n 1. Create new zone\n"))
    selectel(action, [MainMenu, zonecreator])
    

def printcache(short:bool = None):
    if short is None:
        action = int(input("Choose action:\n 0. Back\n 1. Short info\n 2. Full info\n"))
        selectel(action, [MainMenu, (printcache, True), (printcache, False)])
    else:
        if short is True:
            result = db.GetFromCache()
            if result:
                header = ['№', 'Name', 'ttl', 'type', 'data']
                width = (os.get_terminal_size().columns - 15 - header.__len__()*2 - header.__len__()) // 2
                print(width)
                t = PrettyTable(header)
                t._max_width = {'N':4, 'Name': width, 'TTL': 6, 'Type': 5, 'data':width}
                t.align = 'l'
                id = []
                for obj in result:
                    for row in obj:
                        id.append(row.uuid)
                        t.add_row([id.index(row.uuid)+1, row.name, row.ttl, row.type, row.data])  
            print(t,'\n')   
        if short is False:
            result = db.GetFromCache()
            if result:
                id = []
                for obj in result:
                    header = ['Parameter', 'Value']
                    t = PrettyTable(header)
                    width = (os.get_terminal_size().columns - header.__len__()*2 - header.__len__() - 10)
                    t._max_width = {'Parameter': 10, 'Value': width}
                    t.align = 'l'
                    for row in obj:
                        id.append(row.uuid)
                        t.add_row(['№', id.index(row.uuid)+1])
                        t.add_row(['Name', row.name])
                        t.add_row(['UUID',row.uuid])
                        t.add_row(['TTL', row.ttl]) 
                        t.add_row(['Class',row.dclass]) 
                        t.add_row(['Type',row.type])
                        t.add_row(['Data', row.data])
                        t.add_row(['Cached', row.cached])
                        t.add_row(['Expired', row.expired])
                        t.add_row(['Is Frozen', row.freeze])
                    print(t,'\n')
        action = int(input("Choose action:\n 0. Return to back\n"))
        selectel(action, [printcache])


def ZonaManager():
    action = int(input('- Choose action:\n 0. Back\n 1. Show list of zones\n 2. Create new zone\n'))


def MainMenu():
    action = int(input('- Choose action:\n 0. Exit\n 1. Zones\n 2. Cache\n'))
    selectel(action, [sys.exit, printzones, printcache, (test, 'one', 2)])

def selectel(action, functions):
    """First argument is an Action, 
    the others is cotege of functions,
    like (Action, [MainMenu, zonecreator]).
    For execute of sequence of functions make them into a list,
    like (Action, [MainMenu, [printzones,zonecreator]])"""
    try:
        while True:
            i = 0
            for args in functions: # <- get functions list from 2nd arguemnts
                if action == i: # <- action will linked to number
                    if type(args) is not list: args = [args] # <- making list of functions if it doesnt
                    for func in args:
                        if type(func) is tuple: # <- gives to function arguments if they are exists
                            func[0](*func[1:])
                        else:
                            func()
                i+=1
            break
    except ValueError: pass
    except KeyboardInterrupt: sys.exit()

def test(one, two):
    #commandsender(('axfr','get', 'araish.ru:95.165.134.11'))
    axfr = Transfer(_CONF['init'], 'araish.ru', '95.165.134.11', None)
    axfr.getaxfr()
    #print(one,two)

if __name__ == "__main__":
    cpath = f"{os.path.abspath('./')}/config.conf"
    _CONF = {}
    _CONF['init'] = getconf(cpath)
    engine = create_engine(
        f"postgresql+psycopg2://{_CONF['init']['dbuser']}:{_CONF['init']['dbpass']}@{_CONF['init']['dbhost']}:{_CONF['init']['dbport']}/{_CONF['init']['dbname']}"
    )
    try: 
        checkconnect(engine, _CONF['init'])
    except: 
        print('Filed with DB connection')
        sys.exit()

    Base = declarative_base()
    Base.metadata.create_all(engine)

    db = AccessDB(engine, _CONF['init'])
    try: MainMenu()
    except KeyboardInterrupt: sys.exit()