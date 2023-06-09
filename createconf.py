#!./dns/bin/python3
import os
import configparser
import ipaddress
import sys
import netifaces

_OPTIONS =[
    'resolver',
    'recursion',
    'depth',
    'buffertime',
    'listen-ip',
    'listen-port',
    'timedelta',
    'printstats',
    'dbuser',
    'dbpass',
    'dbhost',
    'dbport',
    'dbname',
    'timeout',
    'retry'
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
    config['depth'] = int(config['depth'])
    config['buffertime'] = int(config['buffertime'])
    config['listen-port'] = int(config['listen-port'])
    config['listen-ip'] = config['listen-ip'].split(' ')
    config['timedelta'] = int(config['timedelta'])
    config['printstats'] = eval(config['printstats'])
    config['timeout'] = float(config['timeout'])
    config['retry'] = int(config['retry'])
    return config


def createconf(where, what:configparser.ConfigParser):
    with open(where, 'w+') as f:
        what.write(f)

def deafultconf():
    config = configparser.ConfigParser()
    DBHost = str(input('Input HOSTNAME of your Data Base:\n'))    
    DBUser = str(input('Input USER of your Data Base:\n'))
    DBPass = str(input('Input PASSWORD of your Data Base\'s user:\n'))
    DBName = str(input('Input BASENAME of your Data Base\n'))
    config['AUTHORITY'] = {

    }

    config['CACHE'] = {
        "buffertime": 5
    }
    config['RESOLVE'] = {
        "recursion": False,
        "resolver": '',
        "depth": 30,
        "retry": 3,
        "timeout": 0.1
    }

    config['DEFAULT'] = {
        "listen-ip": getip(),
        "listen-port": 53,
        "timedelta": 3,
        "printstats": False
    }
    config['DATABASE'] = {
        "dbuser": DBUser,
        "dbpass": DBPass,
        "dbhost": DBHost,
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
    here = f"{os.path.abspath('./')}/config.conf"
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
