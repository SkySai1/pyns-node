import threading
import time
import logging

from accessdb import AccessDB

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
                db.CacheExpired(expired=db.getnow(0))
                time.sleep(1)
        except:
            logging.exception('Uncache:')

