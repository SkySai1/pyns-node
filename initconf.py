#!/home/dnspy/server/dns/bin/python3
import logging
import os
import configparser
import re
import sys
import os, platform
import ipaddress
from netaddr import IPAddress as IP

_OPTIONS ={
    'GENERAL': ['mode','listen-ip', 'listen-port', 'printstats', 'timedelta'],
    'DATABASE': ['dbuser', 'dbpass', 'dbhost', 'dbport', 'dbname',  'timesync', 'node'],
    'AUTHORITY': [],
    'CACHING': ['expire', 'scale', 'size', 'download', 'upload'],
    'RECURSION': ['maxdepth', 'timeout', 'retry'],
    'LOGGING' : ['enable', 'keeping', 'pathway' , 'level', 'separate', 'maxsize','rotation'],
    'ACCESS': [],
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
        logging.critical(str(e))
        sys.exit(1)

def checkconf(CONF:configparser.ConfigParser):
    msg = []
    try:
        for s in CONF:
            for opt in CONF.items(s):
                try:
                    if opt[0] == 'mode' and opt[1] not in ['unit', 'alone', 'proxy']: raise Exception                    
                    if opt[0] == 'listen-ip': [IP(ip) for ip in re.sub('\s','',str(opt[1])).split(',')]
                    if opt[0] == 'listen-port': int(opt[1])
                    if opt[0] == 'printstats': eval(opt[1])
                    if opt[0] == 'expire': float(opt[1])
                    if opt[0] == 'scale': float(opt[1])
                    if opt[0] == 'size': int(opt[1])
                    if opt[0] == 'enable': eval(opt[1])
                    if opt[0] == 'resolver' and opt[1] != '': ipaddress.ip_address(opt[1]).version == 4
                    if opt[0] == 'maxdepth': int(opt[1])
                    if opt[0] == 'timeout': float(opt[1])
                    if opt[0] == 'retry': int(opt[1])
                    if opt[0] == 'timesync': float(opt[1])
                    if opt[0] == 'keeping'and opt[1] not in ['db', 'file', 'both']: raise Exception          
                    if opt[0] == 'level' and opt[1] not in ['debug', 'info', 'warning', 'error', 'critical']: raise Exception
                    if opt[0] == 'maxsize' and not re.match('^[0-9]*[b|k|m|g]$', opt[1].lower()):raise Exception
                    if opt[0] == 'rotation': int(opt[1])
                    if opt[0] == 'download': eval(opt[1])
                    if opt[0] == 'upload': eval(opt[1])

                    if opt[0] == 'pathway':   
                        if not os.path.exists(opt[1]):
                            try:
                                os.mkdir(opt[1])
                            except:
                                msg.append(f"{s}: {opt[0]} = {opt[1]} <- dir do not exist")
                        elif not os.access(opt[1], os.R_OK):
                            msg.append(f"{s}: {opt[0]} = {opt[1]} <- dir without read access ")
                    

                except:
                    msg.append(f"{s}: {opt[0]} = {opt[1]} <- bad statetement")
                    continue
        for opt in CONF.items('ACCESS'):
            try:
                ipaddress.ip_network(opt[0])
                if len(opt[1]) > 5: raise Exception
                for r in set(opt[1]):
                    if r not in ['Q','C','A','R', '+']: raise Exception
                    #if not re.match('^[q|c|a|r][+|-]$', r): raise Exception
            except:
                msg.append(f"ACCESS: {opt[0]} = {opt[1]} <- bad statetement")
                continue                
        if not msg: 
            return True
        else:
            logging.basicConfig(format="%(asctime)s %(levelname)s at %(name)s:: %(message)s", force=True)
            log = logging.getLogger('CONFIG CHECK')
            for m in msg:
                log.critical(m)
            return False
    except Exception as e:
        logging.critical('bad config file, recreate it')
        return False


def createconf(where, what:configparser.ConfigParser):
    with open(where, 'w+') as f:
        what.write(f)

def deafultconf():
    if platform.system() == "Windows":
        hostname = platform.uname().node
    else:
        hostname = os.uname()[1]  # doesnt work on windows

    config = configparser.ConfigParser(allow_no_value=True)
    config.optionxform = str
    DBHost = str(input('Input HOSTNAME of your Data Base:\n'))    
    DBUser = str(input('Input USER of your Data Base:\n'))
    DBPass = str(input('Input PASSWORD of your Data Base\'s user:\n'))
    DBName = str(input('Input BASENAME of your Data Base\n'))
    config['GENERAL'] = {
        ";Possible modes (only work is unit)":None,
        "; 'unit' - as part of PyNS system with database interaction":None,
        "; 'alone' - independent DNS server with load zones from files":None,
        "; 'proxy' - forward all queries (include AXFR) to another DNS server and back":None,
        'mode': 'unit',
        ";For severity listen-ip addresses specify them with comma, like '127.0.0.1, 127.0.0.2, 127.0.0.3'":None,
        'listen-ip': '127.0.0.2',
        'listen-port': 53,
        ";Print statistic in console": None,
        'printstats': False,
        ";For mysql better keep timedelta as 0, for pgsql as your region timezone": None,
        'timedelta': 3
    }

    config['DATABASE'] = {
        'dbuser': DBUser,
        'dbpass': DBPass,
        'dbhost': DBHost,
        'dbport': 5432,
        'dbname': DBName,
        ";Time to sync with Data Base":None,
        'timesync': 5,
        ";To identify themselves in DB":None,
        'node': hostname,
    }

    config['AUTHORITY'] = {

    }
    config['CACHING'] = {
        ";Time to clear of core cache data":None,
        'expire': 5,
        ";Max multimeter of expire in high load":None,
        'scale': 10,
        ";Max size of core cache (cache data per core) in bytes":None,
        'size': 1048576,
        ";Is to download cache data from node into DB = False|True":None,
        'download': True,
        ";Is to upload cache data from DB into node = False|True":None,
        'upload': True
    }
    config['RECURSION'] = {
        ";Specify another recursion DNS server": None,
        'resolver': '',
        'maxdepth': 30,
        'timeout': 0.5,
        'retry': 1
    }
    config['LOGGING'] = {
        ";Enable logging = False|True": None,
        'enable': True, 
        ";Minimum level of log events = debug|info|warning|error|critical":None,
        'level': 'error',
        ";Log storage (in database or in file) = db|file|both": None,
        'keeping': 'both',
        "### Applying only with log keeping as in file or both ###":None, 
        ";Folder where is logfiles placing, actually while 'keeping' is file or both":None,
        'pathway': './logs/' , 
        ";Will separate log files by level = False|True":None, 
        'separate': True,
        ";Max size of each log file = 1048576B|1024K|1M|1G":None,
        'maxsize': '1M',
        ";Rotation, number of backup copies after reach maxsize = 5":None,
        'rotation': 5
    }

    config['ACCESS'] = {
        ";The section is about white and black list together":None,
        ";Each next rule will override previous at the intersection of networks sets":None,
        ";As an options you need to specify IP network or an IP address and as argument is 'Rule'":None,
        ";Possible 'Rules':":None,
        ";\t'Q' - allow incoming QUERIES (if its deny you may don`t specify another rules)":None,
        ";\t'C' - allow query processing by CACHE module (affect on return response from cache)":None,
        ";\t'A' - allow query processing by AUTHORITY module (affect on return response from own zones data)":None,
        ";\t'R' - allow query processing by RECURSIVE module (affect on return response from own zones data)":None,
        ";\t'+' - allow techincal command":None,        
        ";At default all rules for any network set to Deny":None,
        ";If you need to deny all queries from some network just do not specified any 'Rule' (empty argument)":None,
        ";Examples:":None,
        ";127.0.0.0/8 = QCAR":None,
        ";127.0.0.1/32 = ":None,
        ";This means that queries from any networks will be deny except from 127.0.0.0/8 network":None,
        ";but queries from 127.0.0.1 address's will be also deny":None,
        '127.0.0.0/8': 'QCAR+',      
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