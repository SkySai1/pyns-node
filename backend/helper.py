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

    def watcher(self):
        try:
            threading.Thread(target=Helper.cacheupdate, args=(self, enginer(self.conf))).start()
            threading.Thread(target=Helper.domainupdate, args=(self, enginer(self.conf))).start()
            pass
        except KeyboardInterrupt: 
            pass

    def cacheupdate(self, engine:enginer):
        try:
            while True:
                self.cache.upload(engine)
                self.cache.download(engine)
                time.sleep(self.sync)
        except:
            logging.exception('Uncache:')

    def domainupdate(self, engine:enginer):
        try:
            while True:
                self.auth.download(engine)
                time.sleep(self.sync)
        except:
            logging.exception('Uncache:')

    def unslave(self, db:AccessDB):
        try:
            while True:
                pass
        except:
            logging.exception('Unslave')

