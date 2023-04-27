#!./dns/bin/python3
import datetime
from functools import lru_cache
import os
import sys
from sqlalchemy import BigInteger, Column, DateTime, Float, Integer, String, create_engine, delete, insert, select, or_, not_
from sqlalchemy.orm import declarative_base, Session

from confinit import getconf
# --- DB structure
Base = declarative_base()

def checkconnect(engine:create_engine):
    Base.metadata.create_all(engine)
    engine.connect()



class Domains(Base):  
    __tablename__ = "domains" 
    
    id = Column(BigInteger, primary_key=True)  
    name = Column(String(255), nullable=False)
    ttl = Column(Integer, default=60)
    dclass = Column(String(2), default='IN')   
    type = Column(String(10))
    data = Column(String(255))

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


    # -- Get from Authority zones
    def getA(self, qname, qclass, qtype = None):
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
    def getC(self, qname, qclass, qtype):
        #print(f'{qname} ask to Cache in DB')
        with Session(self.engine) as conn:
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

    def add(d, qtype, rdata):
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

if __name__ == "__main__":
    cpath = f"{os.path.abspath('./')}/dnspy.conf"
    _CONF = getconf(cpath)
    engine = create_engine(
        f"postgresql+psycopg2://{_CONF['dbuser']}:{_CONF['dbpass']}@{_CONF['dbhost']}:{_CONF['dbport']}/{_CONF['dbname']}"
    )
    Base.metadata.create_all(engine)
    try:
        argv = sys.argv[1::]
        d = argv[0]
        qtype = argv[1]
        rdata = argv[2]
    except:
        print('specify in order: domain qtype rdata')
        sys.exit()
    AccessDB.add(d, qtype, rdata)
