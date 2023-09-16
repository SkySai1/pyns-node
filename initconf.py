#!/home/dnspy/server/dns/bin/python3
import os
import configparser
import sys
import uuid
import logging

_OPTIONS ={
    'GENERAL': ['listen-ip', 'listen-port', 'printstats'],
    'AUTHORITY': [],
    'CACHING': ['maxthreads'],
    'RECURSION': ['enable',  'maxdepth', 'timeout', 'retry'],
    'DATABASE': ['dbuser', 'dbpass', 'dbhost', 'dbport', 'dbname', 'timedelta', 'timesync'],
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
        if checkconf(config) is True:
            return config, True
        else:
            return None, False
    except Exception as e:
        print(e)
        sys.exit()

def checkconf(CONF):
    try:
        eval(CONF['GENERAL']['printstats'])
        eval(CONF['RECURSION']['enable'])
        int(CONF['CACHING']['maxthreads'])
        return True
    except Exception as e:
        print(e)
        return False


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
        ";Max threads at time to DB upload":None,
        'maxthreads': 10
    }
    config['RECURSION'] = {
        'enable': False,
        ";specify another recursion DNS server": None,
        'resolver': '',
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
        ";Time to sync with Data Base":None,
        'timesync': 5,
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