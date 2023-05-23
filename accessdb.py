import datetime
from functools import lru_cache
import logging
import os
import uuid
import sys
from sqlalchemy import engine, UUID, BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, delete, insert, select, or_, not_
from sqlalchemy.orm import declarative_base, Session
from prettytable import PrettyTable

from confinit import getconf
# --- DB structure
Base = declarative_base()

def checkconnect(engine:engine.base.Engine):
    engine.connect()
    Base.metadata.create_all(engine)


def enginer(_CONF):
    try:  
        engine = create_engine(
            f"postgresql+psycopg2://{_CONF['dbuser']}:{_CONF['dbpass']}@{_CONF['dbhost']}:{_CONF['dbport']}/{_CONF['dbname']}",
            connect_args={'connect_timeout': 5},
            pool_pre_ping=True
        )
        checkconnect(engine)
        return engine
    except Exception as e: 
        print(e)
        sys.exit()



class Domains(Base):  
    __tablename__ = "domains" 
    
    id = Column(BigInteger, primary_key=True)
    zone_id = Column(Integer, ForeignKey('zones.id', ondelete='cascade'), nullable=False)
    name = Column(String(255), nullable=False)
    ttl = Column(Integer, default=60)
    dclass = Column(String(2), default='IN')   
    type = Column(String(10))
    data = Column(Text)

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
    
    uuid = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    ttl = Column(Integer, default=60)
    dclass = Column(String(2), default='IN')   
    type = Column(String(10))
    data = Column(Text)
    cached = Column(DateTime(timezone=True), nullable=False)  
    expired = Column(DateTime(timezone=True), nullable=False)  
    freeze = Column(Boolean, default=False)


class AccessDB:

    def __init__(self, engine, conf):
        self.engine = engine
        self.conf = conf


    # -- Get from Zones
    def getZones(self, name = None):
        with Session(self.engine) as conn:
            try:
                if not name:
                    stmt = select(Zones)
                    result = conn.execute(stmt).fetchall()
                else:
                    stmt = select(Zones).filter(Zones.name == name)
                    result = conn.execute(stmt).fetchone()
                return result
            except Exception as e:
                print(e)
                return None

    # -- Get from Domains
    def getDomain(self, qname, qclass, qtype = None):
        if type(qtype) is not list: qtype = [qtype]
        with Session(self.engine) as conn:
            stmt = (select(Zones)
                    .filter(Zones.name.in_(qname.split('.')))

            )
            result = conn.execute(stmt).fetchall()
            for obj in result:
                print(obj)
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
                result = conn.execute(select(Cache)).fetchall()
                return result
            if qtype == 'A':
                stmt = (select(Cache)
                    .filter(or_(Cache.name == qname, Cache.name == qname[:-1]))
                    .filter(Cache.dclass == qclass)
                    .filter(or_(Cache.type == 'A', Cache.type == 'CNAME'))
                )
                result = conn.execute(stmt).fetchall()
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
                result = conn.execute(stmt).fetchall()
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
    



    # -- Cache functions
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

    def CacheExpired(self, expired):
        with Session(self.engine) as conn:
            stmt = (delete(Cache)
                    .filter(Cache.expired <= expired)
                    .filter(Cache.freeze == False)
                    .returning(Cache.name, Cache.type)
            )
            result = conn.scalars(stmt).all()
            conn.commit()

    # -- New zone
    def addZone(self, data):
        with Session(self.engine) as conn:
            stmt = insert(Zones).values(
                name = data['name'],
                type = data['type'],
                ttl = data['ttl'],
                serial = data['serial'],
                expire = data['expire'],
                refresh = data['refresh'],
                retry = data['expire']
            ).returning(Zones)
            try:
                result = conn.scalars(stmt)
                conn.commit()
                return result.all()
            except Exception as e:
                print(e)
                return False

    # -- New domain
    def addDomain(self, d, qtype, rdata):
        with Session(self.engine) as conn:
            stmt = insert(Domains).values(
                name = d,
                type = qtype,
                data = rdata
            )
            conn.execute(stmt)
            conn.commit()
            conn.close()

    def NewDomains(self, data:list):
        with Session(self.engine) as conn:
            #stmt = insert(Domains).
            try:
                conn.execute(insert(Domains), data)
                conn.commit()
            except:
                logging.exception('NewDomains')

    def getnow(self, rise):
        offset = datetime.timedelta(hours=self.conf['timedelta'])
        tz = datetime.timezone(offset)
        now = datetime.datetime.now(tz=tz)
        return now + datetime.timedelta(0,rise) 

# --- Direct Access to file ---



    
