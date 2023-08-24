#!/home/dnspy/server/dns/bin/python3
import os
import configparser
import sys
import uuid
import logging

_OPTIONS ={
    'GENERAL': ['listen-ip', 'listen-port', 'printstats'],
    'AUTHORITY': [],
    'CACHING': ['refresh'],
    'RECURSION': ['enable', 'white-list', 'black-list', 'maxdepth', 'timeout', 'retry'],
    'DATABASE': ['dbuser', 'dbpass', 'dbhost', 'dbport', 'dbname', 'timedelta'],
}

def getconf(path):
    config = configparser.ConfigParser()
    config.read(path)
    bad = []
    try:
        for section in _OPTIONS:
            for key in _OPTIONS[section]:
                if config.has_option(section, key) is not True: bad.append(f'Bad config file: missing key - {key} in {section} section')
        if bad: raise Exception("\n".join(bad))
        return config
    except Exception as e:
        print(e)
        sys.exit()

def createconf(where, what:configparser.ConfigParser):
    with open(where, 'w+') as f:
        what.write(f)

def deafultconf():
    config = configparser.ConfigParser(allow_no_value=True)
    DBHost = str(input('Input HOSTNAME of your Data Base:\n'))    
    DBUser = str(input('Input USER of your Data Base:\n'))
    DBPass = str(input('Input PASSWORD of your Data Base\'s user:\n'))
    DBName = str(input('Input BASENAME of your Data Base\n'))
    config['GENERAL'] = {
        'listen-ip': '127.0.0.2',
        'listen-port': 53,
        ";Print statistic in console": None,
        'printstats': False,
    }
    config['AUTHORITY'] = {

    }
    config['CACHING'] = {
        ";Time to retake data from Data Base":None,
        'refresh': 5
    }
    config['RECURSION'] = {
        'enable': False,
        ";specify another recursion DNS server": None,
        'resolver': '',
        'white-list': False,
        'black-list': False,
        'maxdepth': 30,
        'timeout': 0.5,
        'retry': 1
    }
    config['DATABASE'] = {
        'dbuser': DBUser,
        'dbpass': DBPass,
        'dbhost': DBHost,
        'dbport': 5432,
        'dbname': DBName,
        ";For mysql better keep timedelta as 0, for pgsql as your region timezone": None,
        'timedelta': 3,
    }
    return config

if __name__ == "__main__":
    here = f"{os.path.abspath('./')}/config.ini"
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