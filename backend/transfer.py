
import logging
import re
import dns.query
import dns.zone
import dns.rdatatype
import dns.rdtypes
import dns.rdataclass
import dns.rdata
import dns.tsigkeyring
import dns.name
import dns.message
import dns.tsig
#from PyDNS import create_engine
from backend.accessdb import AccessDB, enginer, getnow
from backend.zonemanager import Zonemaker

QTYPE = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 10:'NULL', 12:'PTR', 13:'HINFO',
        15:'MX', 16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY',
        28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX',
        37:'CERT', 38:'A6', 39:'DNAME', 41:'OPT', 42:'APL',
        43:'DS', 44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC',
        48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM',
        52:'TLSA', 53:'HIP', 55:'HIP', 59:'CDS', 60:'CDNSKEY',
        61:'OPENPGPKEY', 62:'CSYNC', 63:'ZONEMD', 64:'SVCB',
        65:'HTTPS', 99:'SPF', 108:'EUI48', 109:'EUI64', 249:'TKEY',
        250:'TSIG', 251:'IXFR', 252:'AXFR', 255:'ANY', 256:'URI',
        257:'CAA', 32768:'TA', 32769:'DLV'}

CLASS = {1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'}

class Transfer:
    def __init__(self, CONF, zone, target, tsig, keyname):
        self.timedelta = int(CONF['DATABASE']['timedelta'])
        self.conf = CONF
        self.zone = zone
        self.target = target
        self.keyname = keyname
        self.tsig = tsig

    def getaxfr(self):
        try:
            
            qname = dns.name.from_text(self.zone)
            xfr = dns.message.make_query(qname, 'AXFR', 'IN')
            try:
                if self.tsig:
                    key = dns.tsigkeyring.from_text({self.keyname:self.tsig})
                    xfr.use_tsig(key, self.keyname)
                response = dns.query.tcp(xfr, self.target)
            except (dns.tsig.PeerBadKey):
                return False, 'The host doesn\'t knows about this key (bad keyname)'
            
            except:
                logging.exception('TRANSFER')
            Z = Zonemaker(self.conf)
            if response and response.answer:
                data = []
                soa = response.answer[0][0]
                id = Z.zonecreate({
                    'name' : response.question[0].name.to_text(),
                    'type' : 'slave'
                })
                for record in response.answer:
                    data.append({
                        'zone_id': id,
                        'name':record.name.to_text(),
                        'ttl':record.ttl,
                        'dclass': dns.rdataclass.to_text(record.rdclass),
                        'type': dns.rdatatype.to_text(record.rdtype),
                        'data':[rr.to_text() for rr in record]
                    })

                Z.zonefilling(data)
                policy = {
                    "expire": getnow(self.timedelta, soa.expire),
                    "refresh": getnow(self.timedelta, soa.retry),
                    "retry": soa.retry
                }
                Z.zonepolicy(id, policy)
                return True, None
            else:
                return False, "ERROR: Fail with zone transfer for %s" % self.zone
        except:
            logging.exception('GETAXFR FUNCTION')
            pass
            

    def getaxfr_old(self):
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
            result = db.ZoneCreate(data)
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