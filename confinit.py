#!./dns/bin/python3
import os
import configparser
import ipaddress
import netifaces

_OPTIONS =[
    'resolver',
    'allowrecursion',
    'buffertime',
    'listen-ip',
    'listen-port'
]

def getconf(path):
    config = configparser.ConfigParser()
    config.read(path)
    parsed = {}
    for section in config.sections():
        for key in config[section]:
            if key in _OPTIONS:
                parsed[key] = config[section][key]
    parsed = filter(parsed)
    return parsed

def filter(config):
    config['allowrecursion'] = eval(config['allowrecursion'])
    return config


def createconf(where, what:configparser.ConfigParser):
    with open(where, 'w+') as f:
        what.write(f)

def deafultconf():
    config = configparser.ConfigParser()
    config['AUTHORITY'] = {
        "listen-ip": getip(),
        "listen-port": 53,
        "buffertime": 1
    }
    config['RESOLVE'] = {
        "allowrecursion": True,
        "resolver": "127.0.0.53"
    }
    return config

def getip():
    ifaces = netifaces.interfaces()
    ip = []
    config = {
        'eth': [],
        'wlan': [],
        'ens': []
    }
    for i in ifaces:
        if 'eth' in i: config['eth'].append(i)
        if 'wlan' in i: config['wlan'].append(i) 
        if 'ens' in i: config['ens'].append(i)
    for key in config:
        config[key].sort()
        if config[key]:
            ip.append(netifaces.ifaddresses(config[key][0])[netifaces.AF_INET][0]['addr'])
    return ' '.join(ip)

if __name__ == "__main__":
    here = f"{os.path.abspath('./')}/dnspy.conf"
    if not os.path.exists(here):
        conf = deafultconf()
        createconf(here, conf)
    getconf(here)
