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
    
    def __del__(self):
        self.db.c.close()
        self.db.engine.dispose()

    def tsigadd(self, keyname, key):
        id, state = self.db.NewTsig(keyname, key)
        return id

    def tsigassignment(self, zone_id, tsig_id):
        self.db.TsigAssign(zone_id,tsig_id)

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

    def zoneupdnssec(self, zone):
     import dns.dnssec
     import dns.rrset
     import dns.rdataset
     import dns.rdatatype
     import dns.rdataclass
     import dns.zone
     import dns.name
     import datetime
     now = datetime.datetime.now()
     soa = zone.get_soa()
     ZKS = self.load_key('ZKS.pem')
     KSK = self.load_key('KSK.pem')
     dnskey = dns.dnssec.make_dnskey(KSK.public_key(), dns.dnssec.RSASHA256)
     dnskey_rr = dns.rrset.from_rdata(zone.origin, 600 , dnskey)
     
     cdnskey = dns.dnssec.make_cdnskey(KSK.public_key(), dns.dnssec.RSASHA256)
     cds = dns.dnssec.make_cds(zone.origin, cdnskey,"sha256")


     sets = []
     sets.append(dnskey_rr)
     sets.append(dns.rrset.from_rdata(zone.origin, 10, cdnskey))
     sets.append(dns.rrset.from_rdata(zone.origin, 10, cds))
     for rr in zone.iterate_rdatasets():
          sets.append(dns.rrset.from_rdata_list(rr[0],rr[1].ttl,rr[1]))

     
     signing = {}
     for rrset in sets:
          name = rrset.name.to_text()
          if not name in signing: signing[name] = []
          rrsig =  dns.dnssec.sign(rrset,ZKS,zone.origin,dnskey,inception=now,lifetime=86400)
          signing[name].append((dns.rrset.from_rdata(rrset.name, rrset.ttl,rrsig)))
          signing[name].append(rrset)


     names = list(signing.keys())
     newzone = []
     for i, name in enumerate(names):
          rdtypes = set([dns.rdatatype.to_text(rrset.rdtype) for rrset in signing[name]])
          nsecdata = " ".join(rdtypes)
          if i < len(names)-1: nextname = names[i+1]
          else: nextname = names[0]
          nsec = dns.rrset.from_text(name,soa.minimum,dns.rdataclass.IN,dns.rdatatype.NSEC,f"{nextname} {nsecdata} NSEC")
          rrsig =  dns.dnssec.sign(nsec,ZKS,zone.origin,dnskey,inception=now,lifetime=86400)
          rrsig =  dns.rrset.from_rdata(nsec.name, nsec.ttl,rrsig)
          newzone.append(nsec.to_text())
          newzone.append(rrsig.to_text())
          for rr in signing[name]:
               newzone.append(rr.to_text())

     newzone = dns.zone.from_text("\n".join(newzone), zone.origin, relativize=False)
     return newzone

    def load_key(self, filename):
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.hazmat.backends import default_backend
        with open(filename, 'rb') as pem_in:
            pemlines = pem_in.read()
        private_key = load_pem_private_key(pemlines, None, default_backend())
        return private_key     

    def zonecontent(self, name:dns.name.Name):
        try:
            rawzones = self.db.GetFromDomains(zone=name.to_text())
            zone = []
            [zone.append((str(obj[0].name), str(obj[0].ttl), str(obj[0].cls), str(obj[0].type), str(obj[0].data[0]))) for obj in rawzones]
            #auth = "\n".join([" ".join(data) for data in zone])
            auth = dns.zone.from_text("\n".join([" ".join(data) for data in zone]), name, relativize=False)
            #auth = self.zoneupdnssec(auth)
            return auth
        except:
            logging.error('making local zone from database data is fail', exc_info=True)