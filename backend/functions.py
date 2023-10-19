import datetime
import logging
import time
import dns.message
import dns.rcode
import dns.renderer
import dns.flags

def echo(m:dns.message.Message|bytes, state:dns.rcode=dns.rcode.NOERROR, flags:list=None):
    try:
        if isinstance(m,bytes):
            m = dns.message.from_wire(m,ignore_trailing=True,continue_on_error=True)
        result = dns.message.make_response(m)
        result.set_rcode(state)
        if flags:
            result.flags = dns.flags.Flag(sum(flags))
        return result
    except:
        logging.error('Making echo dns answer is fail.', exc_info=(logging.DEBUG >= logging.root.level))

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
        logging.error('Making date is fail', exc_info=(logging.DEBUG >= logging.root.level))
