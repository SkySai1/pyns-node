
import asyncio
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
import dns.rrset
import dns.xfr
#from PyDNS import create_engine
from backend.functions import getnow
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
    def __init__(self, CONF, zone, target, tsig:str|dict|None=None, keyname:str|None=None, algorithm=None):
        try:
            self.timedelta = int(CONF['GENERAL']['timedelta'])
            self.conf = CONF
            self.zone = zone
            self.target = target
            self.tsig = tsig
            self.keyname = keyname
            self.alogorithm = algorithm
        except:
            logging.critical('initialization of authority module is fail')

    def writer(self, r:dns.message.Message, transport:asyncio.Transport, tsig_ctx=None):
        data = r.to_wire(multi=True, tsig_ctx=tsig_ctx)
        l = data.__len__().to_bytes(2,'big')
        transport.write(l+data)

    def sendaxfr(self, q:dns.message.Message, transport:asyncio.Transport):
        try:
            Z = Zonemaker(self.conf)
            zone = Z.zonecontent(self.zone)
            r = dns.message.make_response(q)

            soa = zone.get_soa()
            rrsoa = dns.rrset.from_rdata(zone.origin,soa.minimum, soa)

            r.answer = [rrsoa]
            Transfer.writer(self,r,transport)
            
            for data in zone.iterate_rdatasets():
                if data[1].rdtype is not dns.rdatatype.SOA:

                    rrset = dns.rrset.from_rdata_list(data[0], data[1].ttl, data[1])
                    r.answer = [rrset]

                    Transfer.writer(self,r,transport,r.tsig_ctx)

            r.answer = [rrsoa]
            Transfer.writer(self,r,transport,r.tsig_ctx)
            return r.to_wire()
        except:
            logging.error(f"sending AXFR data init by '{q.question[0].to_text()}' querie to '{self.target}' is fail", exc_info=True)



    def getaxfr(self):
        if self.tsig:
            key = dns.tsigkeyring.from_text({self.keyname:self.tsig})
        else:
            key = None
        qname = dns.name.from_text(self.zone)
        if isinstance(self.target, tuple):
            port = self.target[1]
            self.target = self.target[0]
        else:
            port = 53
        i = 0
        while i < 3:
            try:
                zone = dns.zone.Zone(self.zone,relativize=False)
                q,_ = dns.xfr.make_query(zone, keyring=key, keyname=self.keyname)
                dns.query.inbound_xfr(self.target, zone, q)
                soa = zone.get_soa()
                break
            except (dns.tsig.PeerBadKey):
                return False, 'The host doesn\'t knows about this key (bad keyname)'
            except:
                logging.error(f"getting AXFR data from '{self.target}' is fail", exc_info=True)
                i += 1
        try:    
            Z = Zonemaker(self.conf)
            id = Z.zonecreate({
                'name' : zone.origin.to_text(),
                'type' : 'slave'
            })
            if id is False: raise Exception
            data = []
            for part in zone.iterate_rdatasets():
                name = part[0]
                rdata = part[1]
                data.append({
                    'zone_id': id,
                    'name':name.to_text(),
                    'ttl':rdata.ttl,
                    'cls': dns.rdataclass.to_text(rdata.rdclass),
                    'type': dns.rdatatype.to_text(rdata.rdtype),
                    'data':[d.to_text() for d in rdata]
                })

            policy = {
                "expire": getnow(self.timedelta, soa.expire),
                "refresh": getnow(self.timedelta, soa.retry),
                "retry": soa.retry
            }
            Z.zonefilling(data)
            Z.zonepolicy(id, policy)
            return True, None
        except:
            m = f"making AXFR data from '{self.target}' is fail"
            logging.error(m)
            return False, m