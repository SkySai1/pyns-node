import socket
import time
import ipaddress
from bitstring import BitArray
from prettytable import PrettyTable
import re

def onlyquestion(data):
    start = 12
    #QUESTION

    end, qname = walker(data, start)
    end+=1
    qtype = BitArray(data[end:end+2])
    qclass = BitArray(data[end+2:end+4])
    #print(qname,qtype.int,qclass.int)

def Decoder(data):
    #parse = DNSRecord.parse(data)
    #parse.header.opcode=2
    #parse.header
    #data = parse.pack()
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
    if False: print(t)
    start = 12
    #QUESTION
    print('\nQUESTION SECTION:')

    end, qname = walker(data, start)
    end+=1
    qtype = BitArray(data[end:end+2])
    qclass = BitArray(data[end+2:end+4])
    
    header = ['QNAME', 'QTYPE', 'QCLASS']
    t = PrettyTable(header)
    t.align = 'l'
    qname = '.'.join(qname)
    t.add_row([qname, qtype.int, qclass.int])
    if False:  print(t)

    start = end + 4

    # ANSWER
    print('\nANSWER SECTION:')
    header = ['RNAME', 'RTYPE', 'RCLASS', 'TTL', 'RLENGTH', 'RDATA']
    t, start = sector(header,start,data,ancount)
    if False: print(t)

    # AUTHORITY
    print('\nAUTHORITY SECTION:')
    header = ['RNAME', 'RTYPE', 'RCLASS', 'TTL', 'RLENGTH', 'RDATA']
    t, start = sector(header,start,data,nscount)
    if False: print(t)

    # ADDITIONAL
    print('\nADDITIONAL SECTION:')
    header = ['RNAME', 'RTYPE', 'RCLASS', 'TTL', 'RLENGTH', 'RDATA']
    t, start = sector(header,start,data,arcount)
    if False: print(t)
    print('\n//////////////////////////////\n')

def sector(header, start, data, count):
    t = PrettyTable(header)
    t.align = 'l'
    for z in range(count):
        end, rname = walker(data,start)
        #print(BitArray(data[end+1:end+2]).bin)
        rtype = BitArray(data[end:end+2])
        while rtype.int == 0:
            end+=1
            rtype = BitArray(data[end:end+2])
        rclass = BitArray(data[end+2:end+4])
        ttl = BitArray(data[end+4:end+8])
        rlength = BitArray(data[end+8:end+10])
        start = end+10
        #print(BitArray(data[start:start+rlength.int]).bin)
        rdata = []
        if rtype.int in [1]:
            ipv4 = str(ipaddress.IPv4Address(data[start:start+rlength.int]))
            rdata.append(ipv4)
        elif rtype.int in [28]:
            ipv6 = str(ipaddress.IPv6Address(data[start:start+rlength.int]))
            rdata.append(ipv6)
        else:
            try:
                end, rdata = walker(data, start)
            except: rdata = ['EMPTY']
        start+=rlength.int
        #print(BitArray(data[start:start+1]).bin)
        t.add_row(['.'.join(rname), rtype.int, rclass.int, ttl.int, rlength.int, '.'.join(rdata)])
    return t, start

def walker(data, start, name = None):
    if not name:
        name = []
    label = BitArray(data[start:start+1])
    while label.int != 0:
        #print(label.bin)
        if label[:2].bin == '00':
            oct = label.int
            end = start + oct+1
            ba = BitArray(data[start:end]).bin
            tempname = decode_binary_string(ba)
            name.append(tempname)
            label = BitArray(data[end:end+1])
            start = end
        elif label[:2].bin == '11':
            point = BitArray(data[start:start+2])
            point = point[2:]
            _, name = walker(data, point.int, name)
            start = start + 2
            break
    return start, name

def decode_binary_string(s):
    line = ''
    for i in range(len(s)//8):
        symbol = chr(int(s[i*8:i*8+8],2))
        if re.match(r'[\w,\-\,_]', symbol):
           line +=symbol
    return line