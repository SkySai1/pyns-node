import dns.message
import dns.rcode

def echo(m:dns.message.Message|bytes, state:dns.rcode=dns.rcode.NOERROR, flags:list=[]):
    if isinstance(m,bytes):
        m = dns.message.from_wire(m)
    result = dns.message.make_response(m)
    result.set_rcode(state)
    return result