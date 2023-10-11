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
            while True:
                Stream = []
                Stream.append(threading.Thread(target=Helper.cacheupdate, args=(self,)))
                Stream.append(threading.Thread(target=Helper.nodecheck, args=(self,)))
                for t in Stream:
                    t.start()
                #for t in Stream:
                    t.join()
                #threading.Thread(target=Helper.domainupdate, args=(self,)).start()
                time.sleep(self.sync)
            pass
        except KeyboardInterrupt: 
            pass

    def nodecheck(self):
        try:
            self.db.NodeUpdate()
        except:
            logging.error('Update node info is fail.')
    def cacheupdate(self):
        try:
            self.cache.upload(self.db)
            #self.cache.download(self.db)
            pass
        except:
            logging.error('Update cache data is fail.')

    def domainupdate(self):
        try:    
            self.auth.download(self.db)
        except:
            logging.exception('Update zones data is fail.')

    def unslave(self, db:AccessDB):
        try:
            while True:
                pass
        except:
            logging.exception('Unslave')

