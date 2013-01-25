
import os, dpkt
from pcap import pcap
from .log import HttpReplayLog

CREATE_ALREADY_ESTAB_CNX = True

WAY_CS = 0
WAY_SC = 1

def fmt_ipv4_addr(addr):
    return '%d.%d.%d.%d' % \
        (ord(addr[0]), ord(addr[1]), ord(addr[2]), ord(addr[3]))

def fmt_flow(fl):
    return '%s:%d -> %s:%d' % \
        (fmt_ipv4_addr(fl[0]), fl[1], fmt_ipv4_addr(fl[2]), fl[3])

def rev_flow(fl):
    sip, sport, dip, dport = fl
    return (dip, dport, sip, sport)

def read_flows_from_cap(fname, filt = None):
    flows = {}
    ig_fl = []
    if not os.path.isfile(fname):
        raise Exception('%s: file not found' % fname)
    pc = pcap(fname)
    if filt:
        pc.setfilter(filt)
    for ts, data in pc:
        ether = dpkt.ethernet.Ethernet(data)
        if ether.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = ether.data
        if ip.v != 4 or ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        if (ip.off & (dpkt.ip.IP_MF|dpkt.ip.IP_OFFMASK)) != 0:
            HttpReplayLog.warning('Unsupported fragment packet')
            continue
        tcp = ip.data
        fl = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if fl in flows:
            way = WAY_CS
        elif rev_flow(fl) in flows:
            way = WAY_SC
            fl = rev_flow(fl)
            if tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK:
                flows[fl]['iss-s'] = tcp.seq + 1
            if CREATE_ALREADY_ESTAB_CNX and 'iss-s' not in flows[fl]:
                flows[fl]['iss-s'] = tcp.seq
        elif tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
            HttpReplayLog.debug('new flow %s' % fmt_flow(fl))
            flows[fl] = {'iss-c': tcp.seq + 1, 'pkts': []}
            way = WAY_CS
        else:
            if CREATE_ALREADY_ESTAB_CNX:
                HttpReplayLog.debug('Creating flow %s (already-estab)' % fmt_flow(fl))
                flows[fl] = {'iss-c': tcp.seq, 'pkts': []}
                way = WAY_CS
            else:
                if fl not in ig_fl:
                    HttpReplayLog.warning('Ignoring already-established TCP connection %s' % \
                        fmt_flow(fl))
                    ig_fl.append(fl)
                    ig_fl.append(rev_flow(fl))
                continue
        if len(tcp.data) == 0:
            continue
        flows[fl]['pkts'].append((way, tcp.seq, tcp.data))
    rc = []
    for fl in flows:
        data = flows[fl]
        if 'iss-s' not in data:
            HttpReplayLog.warning('Missing SYN-ACK packet for %s' % fmt_flow(fl))
            continue
        if len(data['pkts']) == 0:
            HttpReplayLog.debug('Ignoring empty flow %s' % fmt_flow(fl))
            continue
        rc.append((fl, (data['iss-c'], data['iss-s']), data['pkts']))
    return rc

def reassemble_tcp_flow(fl, iss, pkts):
    rc = []
    seq = list(iss)
    way, data = WAY_CS, ''
    for w, s, d in pkts:
        if w != way and len(data):
            rc.append((way, data))
            data = ''
        way = w
        #print w, s - iss[w], len(d), seq[w] - iss[w]
        if s + len(d) <= seq[way]:
            HttpReplayLog.debug('Ignoring duplicate packet [%s]' % fmt_flow(fl))
            continue
        if s < seq[way]:
            i = s + len(d) - seq[way]
            assert(i > 0 and i < len(d))
            HttpReplayLog.debug('Ignoring %d/%d bytes in packet' % (len(d) - i, len(d)))
            s, d = seq[way], d[-i:]
        if s != seq[way]:
            HttpReplayLog.warning('Unsupported unsequenced packet for %s, missing %d bytes' % (fmt_flow(fl), s - seq[way]))
            continue
        data += d
        seq[way] = s + len(d)
    else:
        if len(data):
            rc.append((way, data))
    return rc

def parse_cap_file(fname, filt = ''):
    print('Parsing cap file \'%s\' [%s]' % (fname, filt))
    flows = read_flows_from_cap(fname, filt)
    print('%d TCP connection(s) found in \'%s\'' % (len(flows), fname))

    http_req_rep = []
    for fl, iss, pkts in flows:
        pkts = reassemble_tcp_flow(fl, iss, pkts)
        for i in xrange(0, len(pkts), 2):
            if (i + 1 >= len(pkts)):
                HttpReplayLog.warning('Missing reply in HTTP flow %s' % fmt_flow(fl))
                continue
            req, rep = pkts[i], pkts[i+1]
            if req[0] != WAY_CS:
                HttpReplayLog.warning('HTTP flow does not start with request [%s, %d]' % \
                    fmt_flow(fl), i)
                continue
            if rep[0] != WAY_SC:
                HttpReplayLog.warning('HTTP flow does not continue with reply [%s, %d]' % \
                    fmt_flow(fl), i+1)
                continue
            try:
                req = dpkt.http.Request(req[1])
            except Exception, e:
                HttpReplayLog.warning("Error during HTTP request parsing: %s" % e)
                continue
            try:
                rep = dpkt.http.Response(rep[1])
            except Exception, e:
                HttpReplayLog.warning("Error during HTTP response parsing: %s" % e)
                HttpReplayLog.warning("Related request is %s %s" % (req.method, req.uri))
                continue

            http_req_rep.append((req, rep))

    return http_req_rep

class HttpReplayPcapParser:
    def __init__(self, fname, filt=''):
        self.lst = parse_cap_file(fname, filt)

    def __iter__(self):
        for req_rep in self.lst:
            yield req_rep

