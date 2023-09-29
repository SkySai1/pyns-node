import datetime
import dns.message
import dns.rcode

def echo(m:dns.message.Message|bytes, state:dns.rcode=dns.rcode.NOERROR, flags:list=[]):
    if isinstance(m,bytes):
        m = dns.message.from_wire(m,ignore_trailing=True)
    result = dns.message.make_response(m)
    result.set_rcode(state)
    return result

def getnow(delta, rise):
    '''
    *delta* is timedelta of timezone \n
    *rise* is seconds which need to add to current time
    '''
    offset = datetime.timedelta(hours=delta)
    tz = datetime.timezone(offset)
    now = datetime.datetime.now(tz=tz)
    return now + datetime.timedelta(0,rise) 