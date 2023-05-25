
import logging
from backend.transfer import Transfer


class Tech():

    def __init__(self, conf, data, address):
        self.conf = conf
        self.data = data
        self.addr = address

    def worker(self):
        try:
            data = self.data.decode("utf-8")
        except:
            logging.exception('ENCODE')
        c1,c2,c3 = data.split('/')
        if c1 == 'axfr':
            zone, target = c3.split(':')
            T = Transfer(self.conf, zone,target)
            if c2 == 'get':
                T.getaxfr_old()

