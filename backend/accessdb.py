import datetime
import logging
import uuid
import sys
import psycopg2
from sqlalchemy import engine, UUID, BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, create_engine, delete, insert, select, or_, not_, update
from sqlalchemy.orm import declarative_base, Session, relationship
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
        logging.exception('ERROR with engine init')
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

    rules = relationship("Rules", secondary="zones_rules", back_populates="zones", cascade='delete')

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

class Rules(Base):
    __tablename__ = "rules"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    iszone = Column(Boolean, default=False)

    zones = relationship("Zones", secondary="zones_rules", back_populates="rules", cascade='delete', single_parent=True)

class Join_ZonesRules(Base):
    __tablename__ = "zones_rules"
    id = Column(Integer, primary_key=True, autoincrement=True)
    zone_id = Column(Integer, ForeignKey('zones.id'))
    rule_id = Column(Integer, ForeignKey('rules.id'))
    value = Column(Text, nullable=False)

class AccessDB:

    def __init__(self, engine, _CONF):
        self.engine = engine
        self.conf = _CONF
        self.timedelta = int(_CONF['DATABASE']['timedelta'])


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
    def GetDomain(self, qname, qclass, qtype = None):
        #if type(qtype) is not list: qtype = [qtype]
        with Session(self.engine) as conn:
            stmt = (select(Zones)
                    .filter(Zones.name.in_(qname.split('.')))

            )
            result = conn.execute(stmt).fetchall()
            #for obj in result: print(obj)
            if not qtype:
                stmt = (select(Domains)
                        .filter(or_(Domains.name == qname, Domains.name == qname[:-1]))
                        .filter(Domains.dclass == qclass)
                )                
            else:
                stmt = (select(Domains)
                    .filter(or_(Domains.name == qname, Domains.name == qname[:-1]))
                    .filter(Domains.dclass == qclass)
                    .filter(Domains.type == qtype)
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
    



    # -- Cache functions
    def PutInCache(self, data):
        with Session(self.engine) as conn:
            for result in data:
                if int(result.rcode()) == 0 and result.answer:
                    for records in result.answer:
                        for rr in records:
                            rdata= str(rr)
                            ttl = int(records.ttl)
                            if ttl > 0 and rdata:  # <- ON FUTURE, DYNAMIC CACHING BAD RESPONCE
                                rname = str(records.name)
                                rclass = CLASS[records.rdclass]
                                rtype = QTYPE[records.rdtype]
                        if rname and rclass and rtype:
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
                                    cached = getnow(self.timedelta, 0),
                                    expired = getnow(self.timedelta, ttl)
                                )
                                conn.execute(stmt)
            conn.commit()
             
    def GetFromCache(self, qname = None, qclass = None, qtype = None):
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

    def CacheExpired(self, expired):
        with Session(self.engine) as conn:
            stmt = (delete(Cache)
                    .filter(Cache.expired <= expired)
                    .filter(Cache.freeze == False)
                    .returning(Cache.name, Cache.type)
            )
            result = conn.scalars(stmt).all()
            conn.commit()

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
                #logging.exception('Zone Create')
                return False

    def ZoneExpired(self, now):
        with Session(self.engine) as conn:
            stmt = (conn.query(Zones, Rules)
                    .join(Join_ZonesRules)
                    .filter(Join_ZonesRules.zone_id)
            )


    # -- Domains
    def addDomain(self, d, qtype, rdata):
        with Session(self.engine) as conn:
            stmt = insert(Domains).values(
                name = d,
                type = qtype,
                data = rdata,
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
                logging.exception('NewRules')
    
    def NewZoneRules(self, zoneid, data:list):
        with Session(self.engine) as conn:
            for name in data:
                try:
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
                except:
                    #logging.exception('New Zone-Rules')
                    return False
            return True




def getnow(delta, rise):
    offset = datetime.timedelta(hours=delta)
    tz = datetime.timezone(offset)
    now = datetime.datetime.now(tz=tz)
    return now + datetime.timedelta(0,rise) 

# --- Direct Access to file ---



    
