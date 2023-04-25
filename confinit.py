#!./dns/bin/python3
import os
import configparser
import ipaddress
import sys
import netifaces

_OPTIONS =[
    'resolver',
    'recursion',
    'buffertime',
    'listen-ip',
    'listen-port',
    'dbuser',
    'dbpass',
    'dbhost',
    'dbport',
    'dbname'
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
    config['recursion'] = eval(config['recursion'])
    config['buffertime'] = int(config['buffertime'])
    config['listen-port'] = int(config['listen-port'])
    config['listen-ip'] = config['listen-ip'].split(' ')
    return config


def createconf(where, what:configparser.ConfigParser):
    with open(where, 'w+') as f:
        what.write(f)

def deafultconf():
    config = configparser.ConfigParser()
    DBUser = str(input('Input USER of your Data Base:\n'))
    DBPass = str(input('Input PASSWORD of your Data Base\'s user:\n'))
    DBName = str(input('Input BASENAME of your Data Base\n'))
    config['AUTHORITY'] = {
        "listen-ip": getip(),
        "listen-port": 53,
        "buffertime": 1
    }
    config['RESOLVE'] = {
        "recursion": False,
        "resolver": "8.8.8.8"
    }
    config['DEFAULT'] = {
        "dbuser": DBUser,
        "dbpass": DBPass,
        "dbhost": '127.0.0.1',
        "dbport": 5432,
        "dbname": DBName
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
    if os.path.exists(here):
            while True:
                try:
                    y = str(input(f"{here} is exists, do you wanna to recreate it? (y/n)\n"))
                    if y == "n": sys.exit()
                    elif y == "y": break
                except ValueError:
                    pass
                except KeyboardInterrupt:
                    sys.exit()
    conf = deafultconf()
    createconf(here, conf)
    getconf(here)
