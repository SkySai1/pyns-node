from backend.accessdb import enginer, AccessDB
import dns.zone
import dns.name

class Zonemaker:
    def __init__(self, conf):
        self.conf = conf
        self.engine = enginer(self.conf)
        self.db = AccessDB(self.engine, self.conf)
    
    def zonecreate(self, zone):
        id = self.db.ZoneCreate(zone)
        return id
    
    def zonepolicy(self, zone_id, data):
        state = self.db.NewZoneRules(zone_id, data)
    
    def zonefilling(self, data):
        state = self.db.NewDomains(data)

    def zonecontent(self, name:dns.name.Name):
        rawzones = self.db.GetFromDomains(zone=name.to_text())
        zone = []
        [zone.append((str(obj[0].name), str(obj[0].ttl), str(obj[0].dclass), str(obj[0].type), str(obj[0].data[0]))) for obj in rawzones]
        #auth = "\n".join([" ".join(data) for data in zone])
        auth = dns.zone.from_text("\n".join([" ".join(data) for data in zone]), name, relativize=False)
        return auth