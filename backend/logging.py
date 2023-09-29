import logging
import os
from logging import LogRecord
from backend.functions import getnow

def logsetup(CONF):
    if CONF['LOGGING']['keeping'] in ["file", "both"]:
        if eval(CONF['LOGGING']['separate']) is True:
            pass
        else:
            path = os.path.abspath(CONF['LOGGING']['pathway'])
            logging.basicConfig(filename=path+'/pyns.log',
                format="%(asctime)s %(levelname)s %(threadName)s:: %(message)s")
    '''log = logging.getLogger('CONFIG CHECK')
    logging.basicConfig()
    info = logging.FileHandler('logs/info.log')
    info.setLevel(logging.INFO)
    info.addFilter(LogFilter(logging.INFO))
    error = logging.FileHandler('logs/error.log')
    error.setLevel(logging.ERROR)
    #logging.getLogger('').addHandler(mylog)
    log = logging.getLogger('Z')
    log.addHandler(mylog)
    log.addHandler(info)
    log.addHandler(error)
    log.setLevel('DEBUG')
    log.error('AAAAAA')
    log.info('NOT SO BAD')'''

class Logger(logging.Handler):

    def __init__(self, CONF):
        logging.Handler.__init__(self)
        self.timedelta = int(CONF['GENERAL']['timedelta'])
        self.node = CONF['DATABASE']['node']
    
    def emit(self, record: LogRecord) -> None:
        dt = getnow(self.timedelta, 0)#.strftime('%Y-%m-%d %T%z')
        msg = record.msg
        lvl = record.levelname
        tr = record.threadName
        print(self.node, dt, lvl, tr, msg)

class LogFilter(object):
    def __init__(self, level):
        self.__level = level

    def filter(self, logRecord):
        return logRecord.levelno <= self.__level   