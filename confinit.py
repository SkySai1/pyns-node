#!./dns/bin/python3
import os
import configparser
import ipaddress

_OPTIONS =[
    'resolver',
    'buffertime'
]

def getconf(path):
    config = configparser.ConfigParser()
    config.read(path)
    parsed = {}
    for section in config.sections():
        for key in config[section]:
            if key in _OPTIONS:
                parsed[key] = config[section][key]
    return parsed

def createconf(where, what:configparser.ConfigParser):
    with open(where, 'w+') as f:
        what.write(f)

def deafultconf():
    config = configparser.ConfigParser()
    config['AUTHORITY'] = {
        "buffertime": 1
    }
    config['RESOLVE'] = {
        "resolver": "127.0.0.53"
    }
    return config

if __name__ == "__main__":
    here = f"{os.path.abspath('./')}/dnspy.conf"
    if not os.path.exists(here):
        conf = deafultconf()
        createconf(here, conf)
    getconf(here)
