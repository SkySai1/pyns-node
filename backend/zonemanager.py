import logging
from backend.accessdb import enginer, AccessDB
import dns.zone
import dns.name

class Zonemaker:
    def __init__(self, conf):
        try:
            self.conf = conf
            self.engine = enginer(self.conf)
            self.db = AccessDB(self.engine, self.conf)
        except:
            logging.critical('initialization of zonemaker module is fail')
    
    def zonecreate(self, zone):
        try:
            id = self.db.ZoneCreate(zone)
            return id
        except:
            logging.error(f"{zone} zone creating is fail")
    
    def zonepolicy(self, zone_id, data):
        try:
            state = self.db.NewZoneRules(zone_id, data)
        except:
            logging.error(f"zone making policu is fail")
    
    def zonefilling(self, data):
        try:
            state = self.db.NewDomains(data)
        except:
            logging.error('zone filling data is fail')

    def zonecontent(self, name:dns.name.Name):
        try:
            rawzones = self.db.GetFromDomains(zone=name.to_text())
            zone = []
            [zone.append((str(obj[0].name), str(obj[0].ttl), str(obj[0].cls), str(obj[0].type), str(obj[0].data[0]))) for obj in rawzones]
            #auth = "\n".join([" ".join(data) for data in zone])
            auth = dns.zone.from_text("\n".join([" ".join(data) for data in zone]), name, relativize=False)
            return auth
        except:
            logging.error('making local zone from database data is fail')