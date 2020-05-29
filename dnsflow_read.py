#!/usr/bin/env python

"""
See dnsflow.c header comment for packet formats.

Utility functions to simplify interface.
"""
import time
import argparse
import gzip
import socket
import dpkt
import pcap
import struct
import ipaddr
from dpkt.ip import IP_PROTO_UDP
from dpkt.udp import UDP

DNSFLOW_FLAG_STATS = 0x0001
DEFAULT_PCAP_FILTER = "udp and dst port 5300"
SNAPLEN = 65535
TIMEOUT = 100  # milliseconds
DNSFLOW_PORT = 5300


def get_pcap(fspec):
    if fspec.endswith(".gz"):
        f = gzip.open(fspec, "rb")
    else:
        f = open(fspec, "rb")

    pcap_reader = dpkt.pcap.Reader(f)
    return pcap_reader


def pkt_iter(**kwargs):
    """ Iterate over dnsflow pkts. """
    rdr = Reader(**kwargs)
    res = rdr.pcap.iter_interface() if rdr.live_capture else rdr.pcap.iter_pcap()
    return res


# Top-level interface for reading/capturing dnsflow. Instantiate object,
# then iterate using pkt_iter().
class Reader(object):
    def __init__(self, interface=None, pcap_file=None,
                 pcap_filter=DEFAULT_PCAP_FILTER, stats_only=False):
        if interface is None and pcap_file is None:
            raise Exception("Specify interface or pcap_file")
        if interface is not None and pcap_file is not None:
            raise Exception("Specify only interface or pcap_file")

        self.interface = interface
        self.pcap_file = pcap_file
        self.pcap_filter = pcap_filter
        self.stats_only = stats_only
        self.live_capture = bool(not self.pcap_file)
        self.pcap = None

        if self.pcap_file:
            self.pcap = get_pcap(self.pcap_file)
            if pcap_filter != DEFAULT_PCAP_FILTER:
                msg = "Only support default filter {} when reading from PCAP.".format(DEFAULT_PCAP_FILTER)
                raise ValueError(msg)  # TODO: add handler for this
        else:
            # Interface
            self.pcap = pcap.pcap(name=interface, snaplen=SNAPLEN, promisc=True, timeout_ms=TIMEOUT)
            # TODO: prev passed netmask=0 in self._pcap.setfilter(self.pcap_filter, 1, 0)
            self.pcap.setfilter(self.pcap_filter, optimize=1)

    # TODO: make sure exit on Timeout or KeyboardInterrupt
    def iter_interface(self):
        """ Live-capture packets and process them. """
        print('Listening on %s: %s' % (self.pcap.name, self.pcap.filter))
        while True:
            raw = self.pcap.next()
            if raw is not None:
                ts, frame = raw  # TODO: confirm this?
                res = self.handle_frame(ts, frame)
                if res:
                    yield res

    def iter_pcap(self):
        """ Iterate through pcap file and process packets. """
        for ts, frame in self.pcap:
            res = self.handle_frame(ts, frame, filter=True)
            if res:
                yield res

    def handle_frame(self, ts, frame, filter=False):  # TODO: change filter arg name
        pkt, err = process_pkt(
            self.pcap.datalink(), ts, frame, stats_only=self.stats_only, filter=filter
        )
        if err is not None:
            print(err)
            pkt = None

        return pkt


# Returns a tuple(pkt_contents, error_string).
# error_string is None on success; on failure it contains a message
# describing the error.
# pkt_contents is a dict containing the unmarshaled data from the packet. It
# may be incomplete or empty on error.
# stats_only - set to True to parse stats pkts and headers only of data pkts.
def process_pkt(dl_type, ts, buf, stats_only=False, filter=False):
    # TODO: validate filtering
    # TODO: refactor
    pkt = {}
    err = None
    ip_pkt = None
    if dl_type == dpkt.pcap.DLT_NULL:
        # Loopback
        try:
            lo = dpkt.loopback.Loopback(buf)
        except:
            err = 'LOOPBACK-PARSE-FAILED|%s' % (buf)
            return (pkt, err)
        if lo.family == socket.AF_UNSPEC:
            # dnsflow dumped straight to pcap
            if filter:
                # Dont process in this case if 'filter on' since no way to filter
                return (None, None)
            dnsflow_pkt = lo.data
            src_ip = '0.0.0.0'
            src_port = 0
        elif lo.family == socket.AF_INET:
            # dl, ip, udp, dnsflow_pkt
            udp = lo.data.data
            if filter:
                if not type(udp) == UDP:
                    return (None, None)  # TODO: log num filtered?
                udp = lo.data.data
                if udp.dport != DNSFLOW_PORT:
                    return (None, None)

            dnsflow_pkt = udp.data
            ip_pkt = lo.data
            src_ip = socket.inet_ntop(socket.AF_INET, ip_pkt.src)
            src_port = ip_pkt.data.sport
    elif dl_type == dpkt.pcap.DLT_EN10MB:
        # Ethernet
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            err = 'ETHERNET-PARSE-FAILED|%s' % (buf)
            return (pkt, err)
        if filter:
            # TODO: play with on live-capture to validate
            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                return (None, None)
            ip = eth.data
            if ip.p != IP_PROTO_UDP:
                return (None, None)
            udp = ip.data
            # TODO: check this live
            if udp.dport != DNSFLOW_PORT:
                return (None, None)

        dnsflow_pkt = eth.data.data.data
        ip_pkt = eth.data
        src_ip = socket.inet_ntop(socket.AF_INET, ip_pkt.src)
        src_port = ip_pkt.data.sport

    cp = 0

    # vers, sets_count, flags, seq_num
    fmt = '!BBHI'
    try:
        vers, sets_count, flags, seq_num = struct.unpack(fmt,
                dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
    except struct.error as e:
        err = 'PARSE_ERROR|%s|%s' % (fmt, e)
        return (pkt, err)
    cp += struct.calcsize(fmt)

    if (vers not in [0, 1, 2, 3, 4]) or sets_count == 0:
        err = 'BAD_PKT|%s' % (src_ip)
        return (pkt, err)
   
    hdr = {}
    hdr['src_ip'] = src_ip
    hdr['src_port'] = src_port
    hdr['timestamp'] = ts
    hdr['sets_count'] = sets_count
    hdr['flags'] = flags
    hdr['sequence_number'] = seq_num
    pkt['header'] = hdr
    hdr['src_ip_str'] = str(ipaddr.IPAddress(src_ip))

    if flags & DNSFLOW_FLAG_STATS:
        if vers == 2 or vers == 3:
            fmt = '!5I'
        else:
            # vers 0 or 1
            fmt = '!4I'
        try:
            stats = struct.unpack(fmt,
                    dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
        except struct.error as e:
            err = 'HEADER_PARSE_ERROR|%s|%s' % (fmt, e)
            return (pkt, err)
        sp = {}
        sp['pkts_captured'] = stats[0]
        sp['pkts_received'] = stats[1]
        sp['pkts_dropped'] = stats[2]
        sp['pkts_ifdropped'] = stats[3]
        if vers == 2:
            sp['sample_rate'] = stats[4]
        pkt['stats'] = sp

    elif not stats_only:
        # data pkt
        pkt['data'] = []
        
        for i in range(sets_count):

            client_ip = 0
            resolver_ip = 0
            
            try:
                if vers == 4:
                    #ipvers
                    fmt = '!B'
                    ipvers = struct.unpack(fmt,
                            dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
                    cp += struct.calcsize(fmt)

                    # names_count, ips_count, ip6s_count, names_len, padding, client_ip(v4/v6), resolver_ip(v4/v6)
                    if ipvers[0] == 4:
                        fmt = '!BBBHHIIIIIIII'
                        vals = struct.unpack(fmt,
                                dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
                        names_count, ips_count, ip6s_count, names_len, padding, client_ip, padding2, padding3, padding4, resolver_ip, rpadding2, rpadding3, rpadding4 = vals
                    else :
                        fmt = '!BBBHHIIIIIIII'
                        vals = struct.unpack(fmt,
                               dnsflow_pkt[cp:cp + struct.calcsize(fmt)])

                        names_count, ips_count, ip6s_count, names_len, padding, ip1, ip2, ip3, ip4, rip1, rip2, rip3, rip4 = vals
                        ipoctets = [ip4, ip3, ip2, ip1]
                        for i, val in enumerate(ipoctets):
                            val <<= 8* struct.calcsize('I') * i
                            client_ip = client_ip | val

                        ipoctets = [rip4, rip3, rip2, rip1]
                        for i, val in enumerate(ipoctets):
                            val <<= 8* struct.calcsize('I') * i
                            resolver_ip = resolver_ip | val
                            
                elif vers == 3 :
                    #ipvers
                    fmt = '!B'
                    ipvers = struct.unpack(fmt,
                            dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
                    cp += struct.calcsize(fmt)

                    # names_count, ips_count, ip6s_count, names_len, padding, client_ip(v4/v6)
                    if ipvers[0] == 4:
                        fmt = '!BBBHHI'
                        vals = struct.unpack(fmt,
                                dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
                        names_count, ips_count, ip6s_count, names_len, padding, client_ip = vals
                    else :
                        fmt = '!BBBHHIIII'
                        vals = struct.unpack(fmt,
                               dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
                        names_count, ips_count, ip6s_count, names_len, padding, ip1, ip2, ip3, ip4 = vals
                        ipoctets = [ip4, ip3, ip2, ip1]
                        client_ip = 0
                        for i, val in enumerate(ipoctets):
                            val <<= 8* struct.calcsize('I') * i
                            client_ip = client_ip | val

                else :
                    # client_ip, names_count, ips_count, names_len
                    fmt = '!IBBH'
                    ipvers = 4
                    vals = struct.unpack(fmt,
                            dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
                    client_ip, names_count, ips_count, names_len = vals

            except struct.error as e:
                err = 'DATA_PARSE_ERROR|%s|%s' % (fmt, e)
                return (pkt, err)
            cp += struct.calcsize(fmt)

            client_ip = str(ipaddr.IPAddress(client_ip))
            resolver_ip = str(ipaddr.IPAddress(resolver_ip))

            fmt = '%ds' % (names_len)

            try:
                name_set = struct.unpack(fmt,
                        dnsflow_pkt[cp:cp + struct.calcsize(fmt)])[0].decode("utf-8")
            except struct.error as e:
                err = 'DATA_PARSE_ERROR|%s|%s' % (fmt, e)
                return (pkt, err)
            cp += struct.calcsize(fmt)
            if vers in [1, 2, 3, 4] :
                # Each name is in the form of an uncompressed dns name.
                # names are root domain (Nul) terminated, and padded with Nuls
                # on the end to word align. 
                names = []
                np = 0
                try:
                    for x in range(names_count):
                        name = []
                        label_len = ord(name_set[np])
                        np += 1
                        while label_len != 0:
                            name.append(name_set[np: np + label_len])
                            np += label_len
                            label_len = ord(name_set[np])
                            np += 1
                        name = '.'.join(name)
                        names.append(name)
                except IndexError as e:
                    # Hit the end of the name_set buffer.
                    err = 'NAMES_PARSE_ERROR|%s|%d|%s' % (repr(name_set),
                            names_count, e)
                    return (pkt, err)
            else:
                # vers = 0
                # names are Nul terminated, and padded with Nuls on the end to
                # word align.
                names = name_set.split('\0')
                names = names[0:names_count]

            fmt = '!%dI' % (ips_count)
            try:
                ips = struct.unpack(fmt,
                        dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
            except struct.error as e:
                err = 'DATA_PARSE_ERROR|%s|%s' % (fmt, e)
                return (pkt, err)
            cp += struct.calcsize(fmt)
            ips = [str(ipaddr.IPAddress(x)) for x in ips]

            ip6s = []
            if vers in [3, 4]:
                fmt = '!IIII' 
                for x in range(ip6s_count):
                    try:
                        ipval = list(struct.unpack(fmt,
                                dnsflow_pkt[cp:cp + struct.calcsize(fmt)]))
                    except struct.error as e:
                        err = 'DATA_PARSE_ERROR|%s|%s' % (fmt, e)
                        return (pkt, err)
                    cp += struct.calcsize(fmt)

                    ipval.reverse()
                    ip6_val = 0
                    for i, val in enumerate(ipval):
                        val <<= 8* struct.calcsize('I') * i
                        ip6_val = ip6_val | val
                    
                    ip6s.append(ip6_val)
                ip6s = [str(ipaddr.IPAddress(x, 6)) for x in ip6s]

            data = {}
            data['client_ip'] = client_ip
            data['resolver_ip'] = resolver_ip
            data['names'] = names
            data['ips'] = ips
            data['ip6s'] = ip6s
            pkt['data'].append(data)

    return (pkt, err)


def _print_parsed_pkt(pkt):
    hdr = pkt['header']
    ts = hdr['timestamp']
    tstr = time.strftime('%H:%M:%S', time.gmtime(ts))

    if 'stats' in pkt:
        stats = pkt['stats']
        print("STATS|%s" % ('|'.join(['%s:%d' % (x[0], x[1]) for x in list(stats.items())])))
    else:
        for data in pkt['data']:
            print('%s|%s|%s|%s|%s|%s|%s' % (hdr['src_ip_str'], data['resolver_ip'], data['client_ip'], tstr,
                    ','.join(data['names']), ','.join(data['ips']), ','.join(data['ip6s'])))


class SrcTracker(object):
    def __init__(self):
        self.srcs = {}

    def update(self, pkt):
        hdr = pkt['header']
        src_id = (hdr['src_ip'], hdr['src_port'])
        src = self.srcs.get(src_id)
        if src is None:
            src = {
                    'n_records': 0,
                    'n_data_pkts': 0,
                    'n_stats_pkts': 0,
                    'first_timestamp': hdr['timestamp'],
                    'seq': {
                        'seq_last': None,
                        'seq_total': 0,
                        'seq_lost': 0,
                        'seq_ooo': 0,
                        }
                    }
            self.srcs[src_id] = src
        src['last_timestamp'] = hdr['timestamp']
        if 'stats' in pkt:
            src['n_stats_pkts'] += 1
            if 'stats_last' not in src:
                # First stats for src
                src['stats_last'] = pkt['stats']
                src['stats_delta_last'] = {}
                src['stats_delta_total'] = {}
                for k in pkt['stats'].keys():
                    if k == 'sample_rate':
                        continue
                    src['stats_delta_total'][k] = 0
            for k in pkt['stats'].keys():
                if k == 'sample_rate':
                    continue
                src['stats_delta_last'][k] = pkt['stats'][k] - src['stats_last'][k]
                src['stats_delta_total'][k] += src['stats_delta_last'][k]
            src['stats_last'] = pkt['stats']
        else:
            src['n_data_pkts'] += 1
            src['n_records'] += hdr['sets_count']

        # Track lost packets. Won't work if there are duplicates.
        src_seq = src['seq']
        src_seq['seq_total'] += 1
        seq_num = hdr['sequence_number']
        if src_seq['seq_last'] is None:
            src_seq['seq_last'] = seq_num
        elif seq_num == src_seq['seq_last'] + 1:
            src_seq['seq_last'] = seq_num
        elif seq_num > src_seq['seq_last'] + 1:
            src_seq['seq_lost'] += seq_num - src_seq['seq_last'] - 1
            src_seq['seq_last'] = seq_num
        elif seq_num < src_seq['seq_last']:
            src_seq['seq_lost'] -= 1
            src_seq['seq_ooo'] += 1
            # Don't update seq_last.

        return src_id

    def print_summary_src(self, src_id):
        src = self.srcs[src_id]
        ts_delta = src['last_timestamp'] - src['first_timestamp']
        print('%s:%s' % (src_id[0], src_id[1]))
        print('  %s' % (' '.join(['%s=%d' % (k, src[k])
            for k in ['n_data_pkts', 'n_records', 'n_stats_pkts']])))
        if ts_delta > 0:
            print('  %s' % (' '.join(['%s/s=%.2f' % (k, src[k]/ts_delta)
                for k in ['n_data_pkts', 'n_records', 'n_stats_pkts']])))
        if 'stats_delta_total' in src:
            print('  %s' % (' '.join(['%s=%d' % (x[0], x[1])
                for x in list(src['stats_delta_total'].items())])))
            if ts_delta > 0:
                print('  %s' % (' '.join(['%s/s=%.2f' %
                    (x[0], x[1]/ts_delta)
                    for x in list(src['stats_delta_total'].items())])))
        print('  %s' % (' '.join(['%s=%d' % (x[0], x[1])
            for x in list(src['seq'].items())])))


    def print_summary(self):
        for src_id in self.srcs.keys():
            self.print_summary_src(src_id)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-f', dest='extra_filter')
    p.add_argument('-F', dest='complete_filter')
    p.add_argument('-s', dest='stats_only', action='store_true', 
        help="show only status packets")
    p.add_argument('-S', dest='src_summary', action='store_true', 
        help="show source summaries")
    input_group = p.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-r', dest='pcap_file')
    input_group.add_argument('-i', dest='interface')
    args = p.parse_args()

    return args


def main():
    args = parse_args()

    pcap_filter = DEFAULT_PCAP_FILTER
    if args.extra_filter:
        pcap_filter = '(%s) and (%s)' % (DEFAULT_PCAP_FILTER, args.extra_filter)
    elif args.complete_filter:
        pcap_filter = args.complete_filter
    
    if args.stats_only or args.src_summary:
        # Only parse headers and stats pkts. I.e., skip payload of data pkts.
        parse_stats = True
    else:
        parse_stats = False

    if args.pcap_file:
        diter = pkt_iter(
            pcap_file=args.pcap_file,
            pcap_filter=pcap_filter,
            stats_only=parse_stats
        )
    else:
        diter = pkt_iter(
            interface=args.interface,
            pcap_filter=pcap_filter,
            stats_only=parse_stats
        )

    srcs = SrcTracker()

    print('%s|%s|%s|%s|%s|%s|%s' % ("dnsflow server", "resolver ip", "client ip", "time", "names", "ipv4", "ipv6"))

    try:
        for cnt, pkt in enumerate(diter):
            src_id = srcs.update(pkt)
            if args.stats_only:
                if 'stats' in pkt:
                    _print_parsed_pkt(pkt)
                    # XXX This is just printing the total so far, not since
                    # the last stats pkt.
                    srcs.print_summary_src(src_id)
            elif args.src_summary:
                if cnt != 0 and cnt % 100000 == 0:
                    srcs.print_summary()
                    print('-'*40)
            else:
                _print_parsed_pkt(pkt)
    except KeyboardInterrupt:
        print('\nSummary:')
        srcs.print_summary()
    else:
        print('\nSummary:')
        srcs.print_summary()


if __name__ == '__main__':
    main()

