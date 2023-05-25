import threading
import time
import logging

from backend.accessdb import AccessDB, getnow

class Helper:

    def __init__(self, engine, conf) -> None:
        self.engine = engine
        self.conf = conf

    def watcher(self):
        db = AccessDB(self.engine, self.conf)
        try:
            threading.Thread(target=Helper.uncache, args=(self, db)).start()
        except KeyboardInterrupt: 
            pass
    
    def uncache(self, db:AccessDB):
        try:
            while True:
                db.CacheExpired(expired=getnow(self.conf['timedelta'], 0))
                time.sleep(1)
        except:
            logging.exception('Uncache:')

    def unslave(self, db:AccessDB):
        try:
            while True:
                pass
        except:
            logging.exception('Unslave')

