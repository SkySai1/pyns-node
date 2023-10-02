import datetime
import logging
import uuid
import sys
import psycopg2
import dns.rdataclass
import dns.rdatatype
from sqlalchemy import engine, UUID, BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, ARRAY, create_engine, delete, insert, select, or_, not_, update
from sqlalchemy.orm import declarative_base, Session, relationship
from backend.functions import getnow
from backend.rulesmaker import makerules
from backend.recursive import QTYPE, CLASS

# --- DB structure
Base = declarative_base()

def checkconnect(engine:engine.base.Engine, conf):
    engine.connect()
    Base.metadata.create_all(engine)
    data = makerules()
    db = AccessDB(engine, conf)
    try:
        db.NewRules(data)
    except psycopg2.errors.UniqueViolation:
        print('ha')




def enginer(_CONF):
    try:  
        engine = create_engine(
            f"postgresql+psycopg2://{_CONF['DATABASE']['dbuser']}:{_CONF['DATABASE']['dbpass']}@{_CONF['DATABASE']['dbhost']}:{int(_CONF['DATABASE']['dbport'])}/{_CONF['DATABASE']['dbname']}",
            connect_args={'connect_timeout': 5},
            pool_pre_ping=True
        )
        checkconnect(engine, _CONF)
        return engine
    except Exception as e: 
        logging.critical('bad connect to data base')
        sys.exit()



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
    ttl = Column(Integer)
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

    def __init__(self, engine, _CONF):
        self.engine = engine
        self.conf = _CONF
        self.timedelta = int(_CONF['GENERAL']['timedelta'])


    # -- Get from Domains
    def GetFromDomains(self, qname = None, qclass = 'IN', qtype = None, zone=None):
        with Session(self.engine) as conn:
            try:
                if zone:
                    stmt = (select(Domains).join(Zones).filter(Zones.name == zone))
                    return conn.execute(stmt).all()
                
                if not qname and not qtype:
                    result = conn.execute(select(Domains, Zones).join(Zones)).fetchall()
                    return result

                #for obj in result: print(obj)
                if not qtype:
                    stmt = (select(Domains)
                            .filter(or_(Domains.name == qname, Domains.name == qname[:-1]))
                            .filter(Domains.cls == qclass)
                    )                
                else:
                    stmt = (select(Domains)
                        .filter(or_(Domains.name == qname, Domains.name == qname[:-1]))
                        .filter(Domains.cls == qclass)
                        .filter(Domains.type == qtype)
                    )
                result = conn.execute(stmt).all()
                return result
            except Exception as e:
                logging.error('retrieve domains data from database is fail')
                return None


    # -- Cache functions
    def PutInCache(self, data):
        with Session(self.engine) as conn:
            try:
                for record in data:
                    ttl = record.get('ttl')
                    if ttl > 0:
                        name = record.get('name')
                        stmt = (select(Cache)
                            .filter(Cache.name == name)
                            .filter(Cache.cls == record.get('cls'))
                            .filter(Cache.type == record.get('type'))
                        )
                        result = conn.execute(stmt).first()
                        if not result:
                            record.update(cached=getnow(self.timedelta, 0), expired=getnow(self.timedelta, ttl))
                            conn.execute(insert(Cache),record)
                conn.commit()
            except:
                logging.error('putting cache data to database is fail')

             
    def GetFromCache(self, qname = None, qclass = None, qtype = None):
        with Session(self.engine) as conn:
            try:
                if not qname and not qclass and not qtype:
                    result = conn.execute(select(Cache)).fetchall()
                    return result
                if qtype == 'A':
                    stmt = (select(Cache)
                        .filter(or_(Cache.name == qname, Cache.name == qname[:-1]))
                        .filter(Cache.cls == qclass)
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
                            .filter(Cache.cls == qclass)
                            .filter(Cache.type == qtype)
                    )
                    result = conn.execute(stmt).fetchall()
                return result
            except:
                logging.error('getting up cache data from database is fail')

    def CacheExpired(self, expired):
        with Session(self.engine) as conn:
            try:
                stmt = (delete(Cache)
                        .filter(Cache.expired <= expired)
                        .filter(Cache.freeze == False)
                        .returning(Cache.name, Cache.type)
                )
                result = conn.scalars(stmt).all()
                conn.commit()
            except:
                logging.error('clean cache data in database is fail')

    # -- Zones
    def ZoneCreate(self, data):
        with Session(self.engine) as conn:
            stmt = insert(Zones).values(
                    name = data['name'],
                    type = data['type'],
                ).returning(Zones.id)                
            try:
                result = conn.scalars(stmt).one()
                conn.commit()
                return result
            except Exception as e:
                logging.error('zone create is fail')
                return False

    def ZoneExpired(self, now):
        with Session(self.engine) as conn:
            stmt = (conn.query(Zones, Rules)
                    .join(Join_ZonesRules)
                    .filter(Join_ZonesRules.zone_id)
            )

    def getZones(self, name = None):
        with Session(self.engine) as conn:
            try:
                if not name:
                    stmt = (select(Zones))
                    result = conn.execute(stmt).all()
                else:
                    stmt = select(Zones).filter(Zones.name == name)
                    result = conn.execute(stmt).fetchone()
                return result
            except Exception as e:
                logging.error('retrieve zones from database is fail')
                return None

    # -- Domains
    def NewDomains(self, data:list):
        with Session(self.engine) as conn:
            try:
                for rr in data:
                    if rr['type'] in ['SOA', 'CNAME']:
                        if AccessDB.GetFromDomains(self,rr['name'],rr['cls'],rr['type']):
                            return False
                conn.execute(insert(Domains), data)
                conn.commit()
            except:
                logging.error('adding new domains into database is fail')

    # -- Rules
    def NewRules(self, data:list):
        with Session(self.engine) as conn:
            try:
                for row in data:
                    check = conn.execute(
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
                    conn.execute(stmt)
                conn.commit()
            except:
                logging.error('creating new rules is fail')
    
    def NewZoneRules(self, zoneid, data:list):
        with Session(self.engine) as conn:
            try:
                for name in data:
                    stmt_ruleid = (select(Rules.id)
                                .filter(Rules.name == name)
                                .filter(Rules.iszone == True)
                    )
                    ruleid = conn.execute(stmt_ruleid).fetchone()
                    if not ruleid: return False
                    ruleid = ruleid[0]
                    check = (select(Join_ZonesRules.id)
                            .filter(Join_ZonesRules.rule_id == ruleid)
                            .filter(Join_ZonesRules.zone_id == zoneid)
                    )
                    if conn.execute(check).first(): return False

                    stmt = (insert(Join_ZonesRules)
                            .values(
                                zone_id = zoneid,
                                rule_id = ruleid,
                                value = data[name]
                            )
                    )
                    conn.execute(stmt)
                    conn.commit()
                return True
            except:
                logging.error('assignment rules to zones is fail')
                return False
            


# --- Direct Access to file ---



    
