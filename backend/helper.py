import threading
import time
import logging

from backend.accessdb import AccessDB, getnow

class Helper:

    def __init__(self, engine, _CONF) -> None:
        self.engine = engine
        self.conf = _CONF
        self.timedelta = int(_CONF['DATABASE']['timedelta'])

    def watcher(self):
        db = AccessDB(self.engine, self.conf)
        try:
            threading.Thread(target=Helper.uncache, args=(self, db)).start()
        except KeyboardInterrupt: 
            pass
    
    def uncache(self, db:AccessDB):
        try:
            while True:
                db.CacheExpired(expired=getnow(self.timedelta, 0))
                time.sleep(1)
        except:
            logging.exception('Uncache:')

    def unslave(self, db:AccessDB):
        try:
            while True:
                pass
        except:
            logging.exception('Unslave')

