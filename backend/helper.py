import threading
import time
import logging

from backend.accessdb import AccessDB, getnow
from backend.caching import Caching

class Helper:

    def __init__(self, engine, CONF, CACHE:Caching) -> None:
        self.engine = engine
        self.conf = CONF
        self.cache = CACHE
        self.timedelta = int(CONF['DATABASE']['timedelta'])
        self.sync = float(CONF['DATABASE']['timesync'])

    def watcher(self):
        db = AccessDB(self.engine, self.conf)
        try:
            threading.Thread(target=Helper.cacheupdate, args=(self, db)).start()
            pass
        except KeyboardInterrupt: 
            pass

    def cacheupdate(self, db:AccessDB):
        try:
            while True:
                db.CacheExpired(expired=getnow(self.timedelta, 0))
                self.cache.upload()
                self.cache.download()
                time.sleep(self.sync)
        except:
            logging.exception('Uncache:')

    def unslave(self, db:AccessDB):
        try:
            while True:
                pass
        except:
            logging.exception('Unslave')

