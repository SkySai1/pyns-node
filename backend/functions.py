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
        result.flags = dns.flags.Flag(sum(flags))
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

def toobig(r:dns.message.Message):
    raw = dns.renderer.Renderer(r.id, r.flags, origin=r.origin)
    opt_reserve = r._compute_opt_reserve()
    raw.reserve(opt_reserve)
    tsig_reserve = r._compute_tsig_reserve()
    raw.reserve(tsig_reserve)
    for rrset in r.question:
        raw.add_question(rrset.name, rrset.rdtype, rrset.rdclass)
    for rrset in r.answer:
        raw.add_rrset(dns.renderer.ANSWER, rrset)
    for rrset in r.authority:
        raw.add_rrset(dns.renderer.AUTHORITY, rrset)
    for rrset in r.additional:
        raw.add_rrset(dns.renderer.ADDITIONAL, rrset)
    raw.release_reserved()
    if r.opt is not None:
        raw.add_opt(r.opt, r.pad, opt_reserve, tsig_reserve)
    raw.write_header()
    if r.tsig is not None:
        (new_tsig, ctx) = dns.tsig.sign(
            raw.get_wire(),
            r.keyring,
            r.tsig[0],
            int(time.time()),
            r.request_mac,
            None,
            False,
        )
        r.tsig.clear()
        r.tsig.add(new_tsig)
        raw.add_rrset(dns.renderer.ADDITIONAL, r.tsig)
        raw.write_header()
    return raw.get_wire()