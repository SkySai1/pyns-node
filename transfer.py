
import re
import dns.query
import dns.zone
import dns.rdatatype
import dns.rdtypes
import dns.rdata
import dns.tsigkeyring
from dnslib import CLASS, QTYPE
#from PyDNS import create_engine
from accessdb import AccessDB, enginer

class Transfer:
    def __init__(self, conf, zone, target):
        self.conf = conf
        self.zone = zone
        self.target = target

    def getaxfr(self):
        key = dns.tsigkeyring.from_text({
        "name": "secret"
        })
        xfr = dns.query.xfr(
            self.target,
            self.zone,
            port=53,
            #keyring=key,
            #keyalgorithm='HMAC-SHA256'
        )
        engine = enginer(self.conf)
        db = AccessDB(engine, self.conf)
        zone = dns.zone.from_xfr(xfr)
        #print(zone.to_text())
        if zone:
            soa = str(zone.get_soa()).split(' ')
            data = {
                'name' : str(zone.origin),
                'type' : 'slave',
                'serial' : soa[2],
                'refresh': soa[3],
                'retry': soa[4],
                'expire': soa[5],
                'ttl' : soa[6]
            }
            result = db.addZone(data)
            if result: 
                zid = result[-1].id
                data = []
                for i in zone.iterate_rdatas():
                    name = re.sub('@',str(zone.origin),i[0].to_text())
                    if name[-1] != '.':
                        name += '.'+str(zone.origin)
                    ttl = i[1]
                    rclass = CLASS[i[2].rdclass]
                    rtype = QTYPE[i[2].rdtype]
                    rdata = re.sub('@',str(zone.origin),i[2].to_text())
                    if i[2].rdtype in [2,5,6,12,15,39] and rdata[-1] != '.':
                        rdata = rdata+'.'+str(zone.origin)

                    row = {
                        "zone_id": zid,
                        "name": name,
                        "ttl": ttl,
                        "dclass": rclass,
                        "type": rtype,
                        "data": rdata
                    }
                    data.append(row)    
                    #print(f"{name} {ttl} {rclass} {rtype} {rdata}")
                    pass
                db.NewDomains(data)