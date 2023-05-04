#!./dns/bin/python3

import binascii
import re
import socket
import dns.query
import dns.zone
import dns.tsigkeyring
import dns.message
import dns.wire
from bitstring import BitArray
from prettytable import PrettyTable
from dnslib import DNSRecord

class Decoder:
    def __init__(self) -> None:
        pass

    def Decoder(data, short = False):
        if short is False:
            #HEADER
            print('\nHEADER:')
            id = int.from_bytes(data[:2], 'big')

            row2 = data[2:4]
            row2 = BitArray(row2)

            qr = row2[0:1]
            opcode = row2[1:5]
            aa = row2[5:6]
            tc = row2[6:7]
            rd = row2[7:8]
            ra = row2[8:9]
            z = row2[9:10]
            ad = row2[10:11]
            cd = row2[11:12]
            rcode = row2[12:]

            row3 = BitArray(data[4:6])
            row4 = BitArray(data[6:8])
            row5 = BitArray(data[8:10])
            row6 = BitArray(data[10:12])

            qdcount = row3.int
            ancount = row4.int
            nscount = row5.int
            arcount = row6.int

            
            header = ['Parameter', 'Value']
            t = PrettyTable(header)
            t.add_row(["id", id])
            t.add_row(["qr", qr.bool])
            t.add_row(["opcode", opcode.int])
            t.add_row(["aa", aa.bool])
            t.add_row(["tc", tc.bool])
            t.add_row(["rd", rd.bool])
            t.add_row(["ra", ra.bool])
            t.add_row(["z", z.bool])
            t.add_row(["ad", ad.bool])
            t.add_row(["cd", cd.bool])
            t.add_row(["rcode", rcode.int])
            t.add_row(["qdcount", qdcount])
            t.add_row(["ancount", ancount])
            t.add_row(["nscount", nscount])
            t.add_row(["arcount", arcount])
            if True: print(t)
            start = 12

        else: 
            start = 0
            ancount = 10
        #QUESTION
        print('\nQUESTION SECTION:')

        end, qname = Decoder.walker(data, start)
        end+=1
        qtype = BitArray(data[end:end+2])
        qclass = BitArray(data[end+2:end+4])
        
        header = ['QNAME', 'QTYPE', 'QCLASS']
        t = PrettyTable(header)
        t.align = 'l'
        qname = '.'.join(qname)
        t.add_row([qname, qtype.int, qclass.int])
        if True:  print(t)

        start = end + 4

        # ANSWER
        print('\nANSWER SECTION:')
        header = ['RNAME', 'RTYPE', 'RCLASS', 'TTL', 'RLENGTH', 'RDATA']
        t = PrettyTable(header)
        t.align = 'l'
        for z in range(ancount):
            end, rname = Decoder.walker(data,start)
            rtype = BitArray(data[end:end+2])
            rclass = BitArray(data[end+2:end+4])
            ttl = BitArray(data[end+4:end+8])
            rlength = BitArray(data[end+8:end+10])
            start = end+10
            #print(BitArray(data[start:start+rlength.int]).bin)
            if rtype.int == 1:
                rdata = []
                for o in data[start:start+rlength.int]:
                    rdata.append(str(o))
            else:
                try:
                    end, rdata = Decoder.walker(data, start)
                except: rdata = ['EMPTY']
            start+=rlength.int
            #print(BitArray(data[start:start+1]).bin)
            t.add_row(['.'.join(rname), rtype.int, rclass.int, ttl.int, rlength.int, '.'.join(rdata)])
            #break
        print(t)

        print('\n//////////////////////////////\n')

    def walker(data, start, name = None):
        if not name:
            name = []
        label = BitArray(data[start:start+1])
        #print(label.bin)
        while label.int != 0:
            if label[:2].bin == '00':
                oct = label.int
                end = start + oct + 1
                tempname = str(data[start:end])
                name.append(re.sub(r'^b\'\\x[0-9]+','',tempname).rstrip('\''))
                #print(name)
                label = BitArray(data[end:end+1])
                start = end
            elif label[:2].bin == '11':
                point = BitArray(data[start:start+2])
                point = point[2:]
                _, name = Decoder.walker(data, point.int, name)
                start = start + 2
                break
        
        return start, name
    

def hexdump():
    hinfo = ''
    bt = ''
    print(binascii.hexlify(hinfo).decode().upper())
    print(binascii.unhexlify(bt))


def xfr():
    key = dns.tsigkeyring.from_text({
        "tinirog-waramik": "302faOimRL7J6y7AfKWTwq/346PEynIqU4n/muJCPbs="
    })
    xfr = Q.xfr(
        '95.165.134.11',
        'araish.ru',
        port=53,
        #keyring=key,
        #keyalgorithm='HMAC-SHA256'
    )
    zone = dns.zone.from_xfr(xfr)
    #for i in zone.iterate_rdatas(): print(i[1])
    print(dns.zone.to_text()) 

def alter():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('192.168.1.10', 53))
    while True:
        message, q1, q2 = dns.query.receive_udp(udp)
        #print(q)
        
        print(type(message))
        reply = dns.message.make_response(message, False)
        #print(DNSRecord.parse(reply.to_wire()))
        state = dns.query.send_udp(udp,reply, q2)
        #print(message.question[0])

if __name__ == "__main__":
    alter()
