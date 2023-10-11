import logging
import os
import sys
from logging import LogRecord, StreamHandler
from logging.handlers import RotatingFileHandler
from typing import Any
from backend.functions import getnow

class Rotate(RotatingFileHandler):
    def __init__(self, filename, mode: str = "a", maxBytes: int = 0, backupCount: int = 0, encoding: str | None = None, delay: bool = False, errors: str | None = None) -> None:
        super().__init__(filename, mode, maxBytes, backupCount, encoding, delay, errors)
    
    def doRollover(self):
        """
        Do a rollover, as described in __init__().
        """
        if self.stream:
            self.stream.close()
            self.stream = None
        if self.backupCount > 0:
            for i in range(self.backupCount - 1, 0, -1):
                sfn = self.rotation_filename("%s.%d" % (self.baseFilename, i))
                dfn = self.rotation_filename("%s.%d" % (self.baseFilename,
                                                        i + 1))
                if os.path.exists(sfn):
                    if os.path.exists(dfn):
                        os.remove(dfn)
                    os.rename(sfn, dfn)
            dfn = self.rotation_filename(self.baseFilename + ".1")
            if os.path.exists(dfn):
                os.remove(dfn)
            self.rotate(self.baseFilename, dfn)
        if not self.delay:
            self.stream = self._open()

    def rotate(self, source, dest):
        #print('ROTATION:',source,'->',dest)
        if not callable(self.rotator):
            # Issue 18940: A file may not have been created if delay is True.
            if os.path.exists(source):
                try:
                    os.rename(source, dest)
                except: 
                    pass
        else:
            self.rotator(source, dest)

def logsetup(CONF, name):
    try:
        if eval(CONF['LOGGING']['enable']):
            logging.getLogger('asyncio').setLevel(logging.WARNING)
            log = None
            if CONF['LOGGING']['keeping'] in ["file", "both"]:
                size = str(CONF['LOGGING']['maxsize']).upper()
                if size[-1] == 'B': x = 1
                elif size[-1] == 'K': x = 1024
                elif size[-1] == 'M': x = 1024*1024
                elif size[-1] == 'G': x = 1024*1024*1024
                size = int(size[:-1]) * x
                path = os.path.abspath(CONF['LOGGING']['pathway'])
                minimum = str(CONF['LOGGING']['level'])
                rotation = int(CONF['LOGGING']['rotation'])
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
                        statement = RotatingFileHandler(filename=path+lvl, maxBytes=size, backupCount=rotation, delay=True)
                        statement.setFormatter(logform)
                        statement.addFilter(LogFilter(seperate[lvl]))
                        handlers.append(statement)
                    logging.basicConfig(handlers=handlers, level=minimum.upper())

                else:
                    #statement = RotatingFileHandler(filename=path+'/pyns.log', maxBytes=size, backupCount=rotation)
                    statement = Rotate(filename=path+'/pyns.log', maxBytes=size, backupCount=rotation)
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