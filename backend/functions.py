import datetime
import logging
import dns.message
import dns.rcode

def echo(m:dns.message.Message|bytes, state:dns.rcode=dns.rcode.NOERROR, flags:list=None):
    try:
        if isinstance(m,bytes):
            m = dns.message.from_wire(m,ignore_trailing=True)
        result = dns.message.make_response(m)
        result.set_rcode(state)
        if flags:
            for f in flags:
                result.flags += f
        return result
    except:
        logging.error('making echo dns answer is fail',exc_info=True)

def getnow(delta, rise):
    '''
    *delta* is timedelta of timezone \n
    *rise* is seconds which need to add to current time
    '''
    try:
        offset = datetime.timedelta(hours=delta)
        tz = datetime.timezone(offset)
        now = datetime.datetime.now(tz=tz)
        return now + datetime.timedelta(0,rise) 
    except:
        logging.error('making date is fail')