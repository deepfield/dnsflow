#!/usr/bin/env python

'''
See dnsflow.c header comment for packet formats.
'''

import os, sys, time, json, pprint, getopt, signal, re
import traceback, tempfile, stat
import urllib2
import socket
import gzip
import dpkt, pcap
import dns, dns.message
import json
import commands
import subprocess
import random
import urllib
import struct
import ipaddr

verbosity = 0
ts_level = 0    # timestamp level
summary = {
        'senders': {}
        }

DNSFLOW_FLAG_STATS = 0x0001

def process_pkt(dl_type, ts, buf):
    global summary, verbosity, ts_level

    if dl_type == dpkt.pcap.DLT_NULL:
        # Loopback
        try:
            lo = dpkt.loopback.Loopback(buf)
        except:
            print 'Loopback parse failed: %s' % (buf)
            return
        if lo.family == socket.AF_UNSPEC:
            # dnsflow dumped straight to pcap
            dnsflow_pkt = lo.data
            ip_pkt = None
            src_ip = '0.0.0.0'
        elif lo.family == socket.AF_INET:
            # dl, ip, udp, dnsflow_pkt
            dnsflow_pkt = lo.data.data.data
            ip_pkt = lo.data
            src_ip = socket.inet_ntop(socket.AF_INET, ip_pkt.src)
    elif dl_type == dpkt.pcap.DLT_EN10MB:
        # Ethernet
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            print 'Ethernet parse failed: %s' % (buf)
            return
        dnsflow_pkt = eth.data.data.data
        ip_pkt = eth.data
        src_ip = socket.inet_ntop(socket.AF_INET, ip_pkt.src)

    if src_ip not in summary['senders']:
        summary['senders'][src_ip] = {
                'pkts_recv':    0,
                'pkts_invalid': 0,
                'pkts_missing': 0,
                'pkts_ooo':     0,
                'seq_max':      0
                }
    sender = summary['senders'][src_ip]
    sender['pkts_recv'] += 1

    cp = 0

    # vers, sets_count, flags, seq_num
    fmt = '!BBHI'
    vers, sets_count, flags, seq_num = struct.unpack(fmt,
            dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
    cp += struct.calcsize(fmt)

    # Only Version 0, so far
    if vers != 0 or sets_count == 0:
        print 'BAD_PKT|%s' % (src_ip)
        sender['pkts_invalid'] += 1
        return
   
    # Track missing pkts.
    if sender['seq_max'] == 0:
        # Startup
        sender['seq_max'] = seq_num
    elif sender['seq_max'] + 1 == seq_num:
        # Normal case
        sender['seq_max'] = seq_num
    elif sender['seq_max'] < seq_num:
        # Missing pkts
        sender['pkts_missing'] += seq_num - sender['seq_max']
        sender['seq_max'] = seq_num
    elif sender['seq_max'] > seq_num:
        # Missing pkt arrived
        sender['pkts_missing'] -= 1
        sender['pkts_ooo'] += 1
    else:
        # seq_max == seq_num, shouldn't happen (maybe weird duplicate)
        pass

    if ts_level >= 2:
        tstr = time.strftime('%Y%m%d:%H:%M:%S', time.gmtime(ts))
    else:
        tstr = time.strftime('%H:%M:%S', time.gmtime(ts))

    print 'HEADER|%s|%s|%d|%d|%d' % (src_ip, tstr, sets_count, flags, seq_num)
    
    if flags & DNSFLOW_FLAG_STATS:
        fmt = '!4I'
        stats = struct.unpack(fmt, dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
        print "STATS|%s" % ('|'.join([str(x) for x in stats]))
    else:
        # data pkt
        if ts_level >= 1:
            data_ts = '%s|' % (tstr)
        else:
            data_ts = ''
        for i in range(sets_count):
            # client_ip, names_count, ips_count, names_len
            fmt = '!IBBH'
            client_ip, names_count, ips_count, names_len = struct.unpack(fmt,
                    dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
            cp += struct.calcsize(fmt)
            client_ip = str(ipaddr.IPAddress(client_ip))

            # names are Nul terminated, and padded with Nuls on the end to word
            # align.
            fmt = '%ds' % (names_len)

            name_set = struct.unpack(fmt,
                    dnsflow_pkt[cp:cp + struct.calcsize(fmt)])[0]
            cp += struct.calcsize(fmt)
            names = name_set.split('\0')
            names = names[0:names_count]

            fmt = '!%dI' % (ips_count)
            ips = struct.unpack(fmt,
                    dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
            cp += struct.calcsize(fmt)
            ips = [str(ipaddr.IPAddress(x)) for x in ips]

            print 'DATA|%s|%s%s|%s' % (client_ip, data_ts,
                    ','.join(names), ','.join(ips))

                
def read_pcapfile(pcap_files, filter):
    for pcap_file in pcap_files:
        # XXX dpkt pcap doesn't support filters and there's no way to pass
        # a gzip fd to pylibpcap. Bummer.
        p = pcap.pcapObject()
        p.open_offline(pcap_file)
        # filter, optimize, netmask
        # XXX This doesn't work with dump straight to pcap.
        # For now use -F "" in that case.
        p.setfilter(filter, 1, 0)

        print 'Parsing file: %s' % (pcap_file)
        while 1:
            rv = p.next()
            if rv == None:
                break
            pktlen, buf, ts = rv
            process_pkt(p.datalink(), ts, buf)

def mode_livecapture(interface, filter):
    print 'Capturing on', interface
    p = pcap.pcapObject()
    p.open_live(interface, 65535, 1, 100)
    # filter, optimize, netmask
    p.setfilter(filter, 1, 0)

    try:
        while 1:
            rv = p.next()
            if rv != None:
                pktlen, buf, ts = rv
                process_pkt(p.datalink(), ts, buf)
    except KeyboardInterrupt:
        print '\nshutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
   

def main(argv):
    global verbosity, ts_level

    usage = ('Usage: %s [-stv] [-f filter] [-F filter] -r pcap_file or -i interface' % (argv[0]))

    try:
        opts, args = getopt.getopt(argv[1:], 'f:F:i:r:stv')
    except getopt.GetoptError:
        print >>sys.stderr, usage
        return 1

    filename = None
    interface = None
    print_summary = False

    base_filter = 'udp and dst port 5300'
    filter = base_filter
    
    for o, a in opts:
        if o == '-v':
            verbosity += 1
        elif o == '-t':
            ts_level += 1
        elif o == '-r':
            filename = a
        elif o == '-i':
            interface = a
        elif o == '-s':
            print_summary = True
        elif o == '-f':
            # extra filter
            filter = '(%s) and (%s)' % (base_filter, a)
        elif o == '-F':
            # complete filter
            filter = a

    if filename is not None:
        read_pcapfile([filename], filter)
    elif interface is not None:
        mode_livecapture(interface, filter)
    else:
        print usage
        sys.exit(1)

    if print_summary:
        print '\nSender Summary:'
        for src_ip, info in summary['senders'].iteritems():
            print '  %s' % (src_ip)
            for k, v in info.iteritems():
                print '    %-15s %15s' % (k, v)

if __name__ == '__main__':
    main(sys.argv)

    
