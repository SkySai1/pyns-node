#!./dns/bin/python3
import os
import sys

from prettytable import PrettyTable
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, Session
from accessdb import AccessDB, checkconnect
from confinit import getconf

def zonecreator():
    data = {}
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

    data['ttl'] = inputer("- Write to serial ttl (60 by default):\n",int, 60)
    data['expire'] = inputer("- Write to expire time (86400 by default):\n", int, 86400)
    data['refresh'] = inputer("- Write to refresh time (28800 by default):\n", int, 28800)
    data['retry'] = inputer("- Write to expire time (3600 by default):\n", int, 3600)
    db.addZone(data)
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
    if not zlist:
        while True:
            try:
                y = str(input("There is no zones, do you wanna to create first? (y/n)\n"))
                if y == "n": sys.exit()
                elif y == "y": 
                    zonecreator(db)
                    zlist = db.getZones()
                    break
            except ValueError:
                pass
            except KeyboardInterrupt:
                sys.exit()
    print("List of available zones:")
    t = PrettyTable(['ID', 'Name', 'Type', 'Serial', 'TTL', 'Expire', 'Refresh', 'Retry'])
    for obj in zlist:
        for row in obj:
            t.add_row([row.id, row.name, row.type, row.serial, row.ttl, row.expire, row.refresh, row.retry])
    print(t)
    action = int(input("Choose action:\n 0. Return to back\n 1. Create new zone\n"))
    selectel(action, [MainMenu, zonecreator])
    

def printcache():
    result = db.getCache()
    if result:
        t = PrettyTable(['ID', 'Name', 'ttl', 'class', 'type', 'data', 'cached', 'expired'])
        uuid = []
        for obj in result:
            for row in obj:
                uuid.append(row.id)
                t.add_row([uuid.index(row.id)+1, row.name, row.ttl, row.dclass, row.type, row.data, row.cached, row.expired])
        print(t)

        action = int(input("Choose action:\n 0. Return to back\n"))
        selectel(action, [MainMenu])

def MainMenu():
    choose = [
        printzones, 
        printcache
    ]
    action = int(input('- Choose action:\n 0. Exit\n 1. Zones\n 2. Cache\n'))
    selectel(action, [sys.exit, printzones, printcache])

def selectel(*args):
    """First argument is an Action, 
    the others is cotege of functions
    like Action, [MainMenu, Zonecreator]"""
    while True:
        try:
            i = 0
            for arg in args[1]:
                if args[0] == i: 
                    arg()
                i+=1
        except ValueError: pass
        except KeyboardInterrupt: sys.exit()

if __name__ == "__main__":
    cpath = f"{os.path.abspath('./')}/dnspy.conf"
    _CONF = {}
    _CONF['init'] = getconf(cpath)
    engine = create_engine(
        f"postgresql+psycopg2://{_CONF['init']['dbuser']}:{_CONF['init']['dbpass']}@{_CONF['init']['dbhost']}:{_CONF['init']['dbport']}/{_CONF['init']['dbname']}"
    )
    try: 
        checkconnect(engine)
    except: 
        print('Filed with DB connection')
        sys.exit()

    Base = declarative_base()
    Base.metadata.create_all(engine)

    db = AccessDB(engine, _CONF)
    try: MainMenu()
    except KeyboardInterrupt: sys.exit()