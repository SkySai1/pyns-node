import logging
import os
import sys
from logging import LogRecord, StreamHandler
from logging.handlers import RotatingFileHandler
from typing import Any
from backend.functions import getnow

def logsetup(CONF, name):
    try:
        if eval(CONF['LOGGING']['enable']):
            logging.getLogger('asyncio').setLevel(logging.WARNING)
            log = None
            if CONF['LOGGING']['keeping'] in ["file", "both"]:
                path = os.path.abspath(CONF['LOGGING']['pathway'])
                minimum = str(CONF['LOGGING']['minimum'])
                if minimum.lower() not in ['debug','info','warning','error','critical']:
                    raise Exception
                logform = logging.Formatter("%(asctime)s %(levelname)s %(processName)s - %(threadName)s:: %(message)s")
                
                if eval(CONF['LOGGING']['separate']) is True:
                    seperate = {
                        '/debug_pyns.log':   logging.DEBUG,
                        '/info_pyns.log':    logging.INFO,
                        '/warning_pyns.log': logging.WARNING,
                        '/error_pyns.log':   logging.ERROR,
                        '/critical_pyns.log':logging.CRITICAL 
                    }
                    handlers = []
                    for lvl in seperate:
                        statement = RotatingFileHandler(filename=path+lvl, maxBytes=5*1024*1024, backupCount=2)
                        statement.setFormatter(logform)
                        statement.addFilter(LogFilter(seperate[lvl]))
                        handlers.append(statement)
                    logging.basicConfig(handlers=handlers, level=minimum.upper())

                else:
                    statement = RotatingFileHandler(filename=path+'/pyns.log', maxBytes=5*1024*1024, backupCount=2, delay=True)
                    statement.setFormatter(logform)
                    
                    logging.basicConfig(handlers=[statement], level=minimum.upper())
        else:
            logging.disable()
    except:
        logging.critical('Bad loging setup', exc_info=True)
        sys.exit(1)
    

class Logger:
    enable = False
    keeping = None
    path = None
    minimum = None
    isseparate = None
    log = None

      
    def info(msg):
        Logger.log.info(msg)

    def setup(CONF) -> Any:
        Logger.enable = eval(CONF['LOGGING']['enable'])
        Logger.keeping = CONF['LOGGING']['keeping']
        Logger.path = os.path.abspath(CONF['LOGGING']['pathway'])
        Logger.minimum = str(CONF['LOGGING']['minimum'])
        Logger.isseparate = eval(CONF['LOGGING']['separate'])

    def handler(name):
        try:
            logging.getLogger('asyncio').setLevel(logging.WARNING)
            if Logger.enable is True:
                log = None
                if Logger.keeping in ["file", "both"]:
                    if Logger.minimum.lower() not in ['debug','info','warning','error','critical']:
                        raise Exception
                    
                    log = logging.getLogger(name)

                    log.setLevel(Logger.minimum.upper())
                    logform = logging.Formatter("%(asctime)s %(name)s %(levelname)s %(threadName)s:: %(message)s")
                    
                    if Logger.isseparate is True:
                        seperate = {
                            '/debug_pyns.log':   logging.DEBUG,
                            '/info_pyns.log':    logging.INFO,
                            '/warning_pyns.log': logging.WARNING,
                            '/error_pyns.log':   logging.ERROR,
                            '/critical_pyns.log':logging.CRITICAL 
                        }
                        handlers = []
                        for lvl in seperate:
                            statement = RotatingFileHandler(filename=Logger.path+lvl, maxBytes=5*1024*1024, backupCount=2)
                            statement.setFormatter(logform)
                            statement.addFilter(LogFilter(seperate[lvl]))
                            handlers.append(statement)
                            log.addHandler(statement)

                    else:
                        statement = RotatingFileHandler(filename=Logger.path+'/pyns.log', maxBytes=5*1024*1024, backupCount=2, delay=True)
                        statement.setFormatter(logform)
                        log.addHandler(statement)
                        
                Logger.log = log
        except:
            logging.critical('Bad loging setup', exc_info=True)
            sys.exit(1)        

    
class LogFilter(object):
    def __init__(self, level):
        self.__level = level

    def filter(self, logRecord):
        return logRecord.levelno == self.__level   