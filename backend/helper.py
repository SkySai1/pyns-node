import asyncio
from logging.handlers import DEFAULT_UDP_LOGGING_PORT
import threading
import time
import logging
from multiprocessing import Pipe
from backend.accessdb import AccessDB, enginer
from backend.caching import Caching
from backend.authority import Authority
from backend.objects import ThisNode
from backend.logger import LogServer

class Helper:
    logs = []

    def __init__(self, CONF, CACHE:Caching, AUTH:Authority, logreciever:Pipe) -> None:
        self.conf = CONF
        self.cache = CACHE
        self.auth = AUTH
        self.logkeep = CONF['LOGGING']['keeping']
        self.logreciever = logreciever
        self.sync = float(CONF['DATABASE']['timesync'])

    def connect(self, engine):
        self.db = AccessDB(engine, self.conf)

    def watcher(self):
        try:
            Stream = []
            Stream.append(threading.Thread(target=Helper.dbwork, args=(self,),name='DatabaseWorker'))
            if self.logkeep in ["db", "both"]:
                Stream.append(threading.Thread(target=Helper.logchannel, args=(self,),name='LogChannel'))

            for t in Stream:
                t.start()
            for t in Stream:
                t.join()
            pass
        except KeyboardInterrupt: 
            pass

    def dbwork(self):
        while True:
            self.nodecheck()
            self.cacheupdate()
            self.logload()
            time.sleep(self.sync)

    def nodecheck(self):
        try:
            node = self.db.NodeUpdate()
            if node:
                for obj in node:
                    ThisNode.id = obj.id
                    pass
        except:
            logging.error('Update node info is fail.', exc_info=(logging.DEBUG >= logging.root.level))
    def cacheupdate(self):
        try:
            self.cache.upload(self.db)
            #self.cache.download(self.db)
            pass
        except:
            logging.error('Update cache data is fail.', exc_info=(logging.DEBUG >= logging.root.level))

    def logload(self):
        try:
            "%(asctime)s %(levelname)s %(processName)s - %(threadName)s:: %(message)s"
            logdata = [self.logs.pop(0) for i in range(len(self.logs))]
            if ThisNode.id and logdata:
                data = []
                for record in logdata:
                    data.append({
                        'node_id': ThisNode.id,
                        'dt': record.asctime,
                        'level': record.levelname,
                        'prcoess': record.processName,
                        'thread': record.threadName,
                        'message': record.msg
                    })
                self.db.LogsInsert(data)
        except Exception as e:
            print(e.with_traceback())

    def domainupdate(self):
        try:    
            self.auth.download(self.db)
        except:
            logging.exception('Update zones data is fail.', exc_info=(logging.DEBUG >= logging.root.level))

    def unslave(self, db:AccessDB):
        try:
            while True:
                pass
        except:
            logging.exception('Unslave')



    def logchannel(self):
        try:
            while True:
                data = self.logreciever.recv()
                self.logs.append(data)
        except Exception as e:
            print(e.with_traceback())  