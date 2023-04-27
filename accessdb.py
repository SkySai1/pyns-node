#!./dns/bin/python3
import datetime
from functools import lru_cache
import os
import re
import sys
from sqlalchemy import BigInteger, Column, DateTime, Float, ForeignKey, Integer, String, create_engine, delete, insert, select, or_, not_
from sqlalchemy.orm import declarative_base, Session
from prettytable import PrettyTable

from confinit import getconf
# --- DB structure
Base = declarative_base()

def checkconnect(engine:create_engine):
    Base.metadata.create_all(engine)
    engine.connect()



class Domains(Base):  
    __tablename__ = "domains" 
    
    id = Column(Integer, primary_key=True)
    zone_id = Column(Integer, ForeignKey('zones.id'), nullable=False)
    name = Column(String(255), nullable=False)
    ttl = Column(Integer, default=60)
    dclass = Column(String(2), default='IN')   
    type = Column(String(10))
    data = Column(String(255))

class Zones(Base):  
    __tablename__ = "zones" 
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True)
    type = Column(String, default='master')  
    serial = Column(Integer, default=int(datetime.datetime.now().strftime('%Y%m%d01')))
    ttl = Column(Integer, default=60)
    expire = Column(Integer, default = 86400)
    refresh = Column(Integer, default = 28800)
    retry = Column(Integer, default=3600)

class Cache(Base):  
    __tablename__ = "cache" 
    
    id = Column(BigInteger, primary_key=True)  
    name = Column(String(255), nullable=False)
    ttl = Column(Integer, default=60)
    dclass = Column(String(2), default='IN')   
    type = Column(String(10))
    data = Column(String(255))
    cached = Column(DateTime(timezone=True), nullable=False)  
    expired = Column(DateTime(timezone=True), nullable=False)  


class AccessDB:

    def __init__(self, engine, conf):
        self.engine = engine
        self.conf = conf


    # -- Get from Zones
    def getZones(self, name = None):
        with Session(self.engine) as conn:
            if not name:
                stmt = select(Zones)
            else:
                stmt = select(Zones).filter(Zones.name == name)
            try:
                result = conn.execute(stmt).fetchall()
                return result
            except Exception as e:
                print(e)
                return None

    # -- Get from Domains
    def getDomain(self, qname, qclass, qtype = None):
        if type(qtype) is not list: qtype = [qtype]
        with Session(self.engine) as conn:
            if not qtype:
                stmt = (select(Domains)
                        .filter(or_(Domains.name == qname, Domains.name == qname[:-1]))
                        .filter(Domains.dclass == qclass)
                )                
            else:
                stmt = (select(Domains)
                    .filter(or_(Domains.name == qname, Domains.name == qname[:-1]))
                    .filter(Domains.dclass == qclass)
                    .filter(Domains.type.in_(qtype))
                )
            result = conn.execute(stmt).all()
            return result


    # -- Get from Cache    
    def getCache(self, qname = None, qclass = None, qtype = None):
        #print(f'{qname} ask to Cache in DB')
        with Session(self.engine) as conn:
            if not qname and not qclass and not qtype:
                return conn.execute(select(Cache)).fetchall()
            if qtype == 'A':
                stmt = (select(Cache)
                    .filter(or_(Cache.name == qname, Cache.name == qname[:-1]))
                    .filter(Cache.dclass == qclass)
                    .filter(or_(Cache.type == 'A', Cache.type == 'CNAME'))
                )
                result = conn.execute(stmt).all()
                for obj in result:
                    for row in obj:
                        if row.type == 'CNAME':
                            result = AccessDB.getCNAME(conn, [row.name, row.data])
            else:
                stmt = (select(Cache)
                        .filter(or_(Cache.name == qname, Cache.name == qname[:-1]))
                        .filter(Cache.dclass == qclass)
                        .filter(Cache.type == qtype)
                )
                result = conn.execute(stmt).all()
            return result
    
    def getCNAME(conn:Session, oneof:list):
        stmt = (
            select(Cache)
            .filter(Cache.name.in_(oneof))
            .filter(or_(Cache.type == 'A', Cache.type == 'CNAME'))
        )
        result = conn.execute(stmt).all()
        for obj in result:
            for row in obj:
                if row.name == oneof[-1] and row.type == 'CNAME':
                    oneof.append(row.data)
                    result = AccessDB.getCNAME(conn, oneof)
        return result



    # -- Put to Cache
    def putC(self, rname, ttl, rclass, rtype, rdata):
        #print(f"{rname} try to access in DB")
        with Session(self.engine) as conn:
            stmt = (select(Cache)
                    .filter(or_(Cache.name == rname, Cache.name == rname[:-1]))
                    .filter(Cache.dclass == rclass)
                    .filter(Cache.type == rtype)
                    .filter(Cache.data == rdata)
            )
            result = conn.execute(stmt).first()
            if not result:
                stmt = insert(Cache).values(
                    name = rname,
                    ttl = ttl,
                    dclass = rclass,
                    type = rtype,
                    data = rdata,
                    cached = AccessDB.getnow(self, 0),
                    expired = AccessDB.getnow(self, ttl)
                )
                conn.execute(stmt)
                conn.commit()

    # -- New zone
    def addZone(self, data):
        with Session(self.engine) as conn:
            stmt = insert(Zones).values(
                name = data['name'],
                type = data['type'],
                ttl = data['ttl'],
                expire = data['expire'],
                refresh = data['refresh'],
                retry = data['expire']
            )
            try:
                conn.execute(stmt)
                conn.commit()
            except Exception as e:
                print(e)

    # -- New domain
    def addDomain(self, d, qtype, rdata):
        with Session(engine) as conn:
            stmt = insert(Domains).values(
                name = d,
                type = qtype,
                data = rdata
            )
            conn.execute(stmt)
            conn.commit()
            conn.close()

    def getnow(self, rise):
        offset = datetime.timedelta(hours=self.conf['timedelta'])
        tz = datetime.timezone(offset)
        now = datetime.datetime.now(tz=tz)
        return now + datetime.timedelta(0,rise) 

# --- Direct Access to file ---


def zonecreator(db:AccessDB):
    data = {}
    data['name'] = inputer("- Write to zone name:\n",str)
    if data['name'][-1] != '.': data['name'] += '.'

    while True:
        data['type'] = inputer("- Specify one of zone's type: 'm' - master (default), 's' - slave \n",str, 'm')
        if data['type'] == 'm': 
            data['type'] = 'master'
            print(data['type'])
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


def printzones(db:AccessDB):
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
    for obj in zlist:
        for row in obj:
            print(row.name)

def printcache(db:AccessDB):
    result = db.getCache()
    if result:
        t = PrettyTable(['ID', 'Name', 'ttl', 'class', 'type', 'data', 'cached', 'expired'])
        for obj in result:
            for row in obj:
                t.add_row([row.id, row.name, row.ttl, row.dclass, row.type, row.data, row.cached, row.expired])
        print(t)


def first(db:AccessDB):
    choose = [
        printzones, 
        printcache
    ]
    while True:
        try:
            where = int(input('-1. Select action:\n 1. Zones\n 2. Cache\n'))
            where -= 1
            return choose[where](db)
        except ValueError:
            pass
        except KeyboardInterrupt:
            print('Aborted')
            sys.exit()

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

    Base.metadata.create_all(engine)

    db = AccessDB(engine, _CONF)
    result = first(db)
    #print(result)
    
