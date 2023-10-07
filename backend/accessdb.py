import datetime
import logging
import time
import uuid
import sys
import psycopg2
import dns.rdataclass
import dns.rdatatype
from sqlalchemy import engine, UUID, BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, ARRAY, exc, create_engine, delete, insert, select, or_, not_, update
from sqlalchemy.orm import declarative_base, Session, relationship
from backend.functions import getnow
from backend.rulesmaker import makerules
from backend.recursive import QTYPE, CLASS

# --- DB structure
Base = declarative_base()

def checkconnect(engine:engine.base.Engine, conf):
    try:
        engine.connect()
        Base.metadata.create_all(engine)
        return True
    except:
        return False

def enginer(_CONF):
    try:  
        engine = create_engine(
            f"postgresql+psycopg2://{_CONF['DATABASE']['dbuser']}:{_CONF['DATABASE']['dbpass']}@{_CONF['DATABASE']['dbhost']}:{int(_CONF['DATABASE']['dbport'])}/{_CONF['DATABASE']['dbname']}",
            connect_args={'connect_timeout': 5},
            pool_pre_ping=True
        )
        if checkconnect(engine, _CONF) is True:
            return engine
        else: raise Exception()
    except Exception as e: 
        logging.critical(f"The database is unreachable")
        sys.exit(1)



class Domains(Base):  
    __tablename__ = "domains" 
    
    id = Column(BigInteger, primary_key=True)
    zone_id = Column(Integer, ForeignKey('zones.id', ondelete='cascade'), nullable=False)
    name = Column(String(255), nullable=False)
    ttl = Column(Integer, default=60)
    cls = Column(String(2), default='IN')   
    type = Column(String(10))
    data = Column(ARRAY(String))

class Zones(Base):  
    __tablename__ = "zones" 
    
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True)
    type = Column(String, default='master')

    rules = relationship("Rules", secondary="zones_rules", back_populates="zones", cascade='delete')
    tsigkeys = relationship("Tkeys", secondary="zones_tsigkeys", back_populates="zones", cascade='delete')

class Cache(Base):  
    __tablename__ = "cache" 
    
    uuid = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    cls = Column(String(2), default='IN')   
    type = Column(String(10))
    data = Column(ARRAY(String))
    cached = Column(DateTime(timezone=True), nullable=False)  
    expired = Column(DateTime(timezone=True), nullable=False)  
    freeze = Column(Boolean, default=False)

class Rules(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    iszone = Column(Boolean, default=False)

    zones = relationship("Zones", secondary="zones_rules", back_populates="rules", cascade='delete', single_parent=True)

class Logs(Base):
    __tablename__ = "logs"
    uuid = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    node = Column(String(255), nullable=False, unique=True)
    date = Column(DateTime(timezone=True), nullable=False)
    level = Column(String(20), nullable=False)
    thread = Column(String(255), nullable=False)
    message = Column(Text)

class Join_ZonesRules(Base):
    __tablename__ = "zones_rules"
    id = Column(Integer, primary_key=True, autoincrement=True)
    zone_id = Column(Integer, ForeignKey('zones.id', ondelete='cascade'))
    rule_id = Column(Integer, ForeignKey('rules.id', ondelete='cascade'))
    value = Column(Text, nullable=False)

class Tkeys(Base):
    __tablename__ = "tsigkeys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    value = Column(String(255), nullable=False) 
    zones = relationship("Zones", secondary="zones_tsigkeys", back_populates="tsigkeys", cascade='delete', single_parent=True)


class Join_ZonesTkeys(Base):
    __tablename__ = "zones_tsigkeys"
    id = Column(Integer, primary_key=True, autoincrement=True)
    zone_id = Column(Integer, ForeignKey('zones.id', ondelete='cascade'))
    tkey_id = Column(Integer, ForeignKey('tsigkeys.id', ondelete='cascade'))

class AccessDB:

    def __init__(self, engine:engine, _CONF):
        self.engine = engine
        self.conf = _CONF
        self.sync = float(_CONF['DATABASE']['timesync'])
        self.timedelta = int(_CONF['GENERAL']['timedelta'])
        self.c = Session(engine)

    def drop(self):
        logging.error('Database is lost connection')
        self.c.rollback()   

    def Test(self):
        q = 'bla.online.vtb.ru.'
        arr = q.split('.')
        pos = []
        for x in range(len(arr)):
            pos.append(".".join(arr[x:-1])+'.')
        dcm = [".".join(arr[x:-1])+'.' for x in range(len(arr))]
        print(dcm)
        state = (Domains.name.in_(pos))
        stmt = (
            select(Domains)
            .filter(state)
        )
        return self.c.execute(stmt).fetchall()

    # -- Get data from Domains table
    def GetFromDomains(self, qname:str|list = None, rdclass = None, rdtype:str|list = None, zone=None, decomposition:bool=False):
        try:
            if decomposition is False:
                if not qname: state = (Domains.name == Domains.name)
                else: 
                    if isinstance(qname,str): 
                        state = (Domains.name == qname)
                    elif isinstance(qname,list):
                        state = (Domains.name.in_(qname))
            else:
                spl = qname.split('.')
                decomp = [".".join(spl[x:-1])+'.' for x in range(len(spl))]
                state = (Domains.name.in_(decomp))               
            if not rdtype: rdtype = (Domains.type == Domains.type)
            else:
                if isinstance(rdtype,str): 
                    rdtype = (Domains.type == rdtype)
                elif isinstance(rdtype,list):
                    rdtype = (Domains.type.in_(rdtype))                
            if not rdclass: rdclass = Domains.cls
            if not zone: zone = Zones.name
            stmt = (select(Domains, Zones.name).join(Zones)
                    .filter(state)
                    .filter(rdtype)
                    .filter(Domains.cls == rdclass)
                    .filter(Zones.name == zone)
                    )
            result = self.c.execute(stmt).fetchall()
            return result
        except Exception as e:
            logging.error('Retrieve domains data from database is fail')
            if isinstance(e,(exc.PendingRollbackError, exc.OperationalError)):
                AccessDB.drop(self)


    # -- Cache functions
    def PutInCache(self, data, ttl):
        try:
            for record in data:
                name = record.get('name')
                stmt = (select(Cache)
                    .filter(Cache.name == name)
                    .filter(Cache.cls == record.get('cls'))
                    .filter(Cache.type == record.get('type'))
                )
                result = self.c.execute(stmt).first()
                if not result:
                    record.update(cached=getnow(self.timedelta, 0), expired=getnow(self.timedelta, ttl))
                    self.c.execute(insert(Cache),record)
            self.c.commit()
            return True
        except Exception as e:
            logging.error('Upload cache data to database is fail')
            if isinstance(e,(exc.PendingRollbackError, exc.OperationalError)):
                AccessDB.drop(self)
            return False

            
    def GetFromCache(self, qname = None, qclass = None, qtype = None):
        try:
            if not qname and not qclass and not qtype:
                result = self.c.execute(select(Cache)).fetchall()
                return result
            if qtype == 'A':
                stmt = (select(Cache)
                    .filter(or_(Cache.name == qname, Cache.name == qname[:-1]))
                    .filter(Cache.cls == qclass)
                    .filter(or_(Cache.type == 'A', Cache.type == 'CNAME'))
                )
                result = self.c.execute(stmt).fetchall()
                for obj in result:
                    for row in obj:
                        if row.type == 'CNAME':
                            result = AccessDB.getCNAME(self.c, [row.name, row.data])
            else:
                stmt = (select(Cache)
                        .filter(or_(Cache.name == qname, Cache.name == qname[:-1]))
                        .filter(Cache.cls == qclass)
                        .filter(Cache.type == qtype)
                )
                result = self.c.execute(stmt).fetchall()
            return result
        except Exception as e:
            logging.error('Download cache data from database is fail')
            if isinstance(e,(exc.PendingRollbackError, exc.OperationalError)):
                AccessDB.drop(self)

    def CacheExpired(self, expired):
        try:
            stmt = (delete(Cache)
                    .filter(Cache.expired <= expired)
                    .filter(Cache.freeze == False)
                    .returning(Cache.name, Cache.type)
            )
            result = self.c.scalars(stmt).all()
            self.c.commit()
        except Exception as e:
            logging.error('Clean cache data in database is fail')
            if isinstance(e,(exc.PendingRollbackError, exc.OperationalError)):
                AccessDB.drop(self)

    # -- Zones
    def ZoneCreate(self, data):
        stmt = insert(Zones).values(
                name = data['name'],
                type = data['type'],
            ).returning(Zones.id)                
        try:
            result = self.c.scalars(stmt).one()
            self.c.commit()
            return result
        except Exception as e:
            logging.error('Zone create is fail')
            if isinstance(e,(exc.PendingRollbackError, exc.OperationalError)):
                AccessDB.drop(self)
            return False

    def ZoneExpired(self, now):
            stmt = (self.c.query(Zones, Rules)
                    .join(Join_ZonesRules)
                    .filter(Join_ZonesRules.zone_id)
            )

    def GetZones(self, name = None):
        try:
            if not name: 
                state = (Zones.name == Zones.name)
            else:
                if isinstance(name,str):
                    state = (Zones.name == name)
                elif isinstance(name,list):
                    decomp = [".".join(name[x:-1])+'.' for x in range(len(name))]
                    state = (Zones.name.in_(decomp))
            stmt = (select(Zones, Domains).join(Domains)
                    .filter(Domains.type == 'SOA')
                    .filter(state))
            return self.c.execute(stmt).fetchall()
        except Exception as e:
            logging.error('Retrieve zones from database is fail')
            if isinstance(e,(exc.PendingRollbackError, exc.OperationalError)):
                AccessDB.drop(self)
            return None

    # -- Domains
    def NewDomains(self, data:list):
        try:
            for rr in data:
                if rr['type'] in ['SOA', 'CNAME']:
                    if AccessDB.GetFromDomains(self,rr['name'],rr['cls'],rr['type']):
                        return False
            self.c.execute(insert(Domains), data)
            self.c.commit()
        except Exception as e:
            logging.error('Creating new domains into database is fail')
            if isinstance(e,(exc.PendingRollbackError, exc.OperationalError)):
                AccessDB.drop(self)

    # -- Rules
    def NewRules(self, data:list):
        try:
            for row in data:
                check = self.c.execute(
                    select(Rules)
                    .filter(Rules.name == row['name'])
                ).first()
                if check:
                    stmt = (
                        update(Rules)
                        .filter(Rules.name == row['name'])
                        .values(
                            name = row['name'],
                            iszone = row['iszone']
                        )
                    )
                else:
                    stmt = (
                        insert(Rules)
                        .values(
                            name = row['name'],
                            iszone = row['iszone']
                        )                                
                    )
                self.c.execute(stmt)
            self.c.commit()
        except Exception as e:
            logging.error('Creating new rules into database is fail')
            if isinstance(e,(exc.PendingRollbackError, exc.OperationalError)):
                AccessDB.drop(self)
    
    def NewZoneRules(self, zoneid, data:list):
        try:
            for name in data:
                stmt_ruleid = (select(Rules.id)
                            .filter(Rules.name == name)
                            .filter(Rules.iszone == True)
                )
                ruleid = self.c.execute(stmt_ruleid).fetchone()
                if not ruleid: return False
                ruleid = ruleid[0]
                check = (select(Join_ZonesRules.id)
                        .filter(Join_ZonesRules.rule_id == ruleid)
                        .filter(Join_ZonesRules.zone_id == zoneid)
                )
                if self.c.execute(check).first(): return False

                stmt = (insert(Join_ZonesRules)
                        .values(
                            zone_id = zoneid,
                            rule_id = ruleid,
                            value = data[name]
                        )
                )
                self.c.execute(stmt)
                self.c.commit()
            return True
        except Exception as e:
            logging.error('Assignment rules to zones in database is fail')
            if isinstance(e,(exc.PendingRollbackError, exc.OperationalError)):
                AccessDB.drop(self)
            return False
            


# --- Direct Access to file ---



    
