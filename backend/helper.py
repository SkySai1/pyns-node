import threading
import time
import logging

from backend.accessdb import AccessDB, enginer
from backend.caching import Caching
from backend.authority import Authority

class Helper:

    def __init__(self, CONF, CACHE:Caching, AUTH:Authority) -> None:
        self.conf = CONF
        self.cache = CACHE
        self.auth = AUTH
        self.sync = float(CONF['DATABASE']['timesync'])

    def connect(self, engine):
        self.db = AccessDB(engine, self.conf)

    def watcher(self):
        try:
            threading.Thread(target=Helper.cacheupdate, args=(self,)).start()
            #threading.Thread(target=Helper.domainupdate, args=(self,)).start()
            pass
        except KeyboardInterrupt: 
            pass

    def cacheupdate(self):
        while True:
            try:
                self.cache.upload(self.db)
                self.cache.download(self.db)
            except:
                logging.error('update cache data is fail')
            finally:
                time.sleep(self.sync)

    def domainupdate(self):
        while True:
            try:    
                self.auth.download(self.db)
            except:
                logging.exception('update zones data is fail')
            finally:
                time.sleep(self.sync)

    def unslave(self, db:AccessDB):
        try:
            while True:
                pass
        except:
            logging.exception('Unslave')

