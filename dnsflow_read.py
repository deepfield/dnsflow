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

cfg = {
        'verbosity':    0,
        'ts_level':     0,    # timestamp level
        'track_subs':   False,
        'regex':        None  # stores the compiled regex
        }

DNSFLOW_FLAG_STATS = 0x0001

#
# Returns a tuple(pkt_contents, error_string).
# error_string is None on success; on failure it contains a message
# describing the error.
# pkt_contents is a dict containing the unmarshaled data from the packet. It
# may be incomplete or empty on error.
def process_pkt(dl_type, ts, buf):
    pkt = {}
    err = None

    if dl_type == dpkt.pcap.DLT_NULL:
        # Loopback
        try:
            lo = dpkt.loopback.Loopback(buf)
        except:
            err = 'LOOPBACK-PARSE-FAILED|%s' % (buf)
            return (pkt, err)
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
            err = 'ETHERNET-PARSE-FAILED|%s' % (buf)
            return (pkt, err)
        dnsflow_pkt = eth.data.data.data
        ip_pkt = eth.data
        src_ip = socket.inet_ntop(socket.AF_INET, ip_pkt.src)

    cp = 0

    # vers, sets_count, flags, seq_num
    fmt = '!BBHI'
    try:
        vers, sets_count, flags, seq_num = struct.unpack(fmt,
                dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
    except struct.error, e:
        err = 'PARSE_ERROR|%s|%s' % (fmt, e)
        return (pkt, err)
    cp += struct.calcsize(fmt)

    # Version 0 or 1
    if (vers != 0 and vers != 1) or sets_count == 0:
        err = 'BAD_PKT|%s' % (src_ip)
        return (pkt, err)
   
    hdr = {}
    hdr['src_ip'] = src_ip
    hdr['timestamp'] = ts
    hdr['sets_count'] = sets_count
    hdr['flags'] = flags
    hdr['sequence_number'] = seq_num
    pkt['header'] = hdr
    
    if flags & DNSFLOW_FLAG_STATS:
        fmt = '!4I'
        try:
            stats = struct.unpack(fmt,
                    dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
        except struct.error, e:
            err = 'HEADER_PARSE_ERROR|%s|%s' % (fmt, e)
            return (pkt, err)
        sp = {}
        sp['pkts_captured'] = stats[0]
        sp['pkts_received'] = stats[1]
        sp['pkts_dropped'] = stats[2]
        sp['pkts_ifdropped'] = stats[3]
        pkt['stats'] = sp

    else:
        # data pkt
        pkt['data'] = []
        for i in range(sets_count):
            # client_ip, names_count, ips_count, names_len
            fmt = '!IBBH'
            try:
                vals = struct.unpack(fmt,
                        dnsflow_pkt[cp:cp + struct.calcsize(fmt)])
                client_ip, names_count, ips_count, names_len = vals
            except struct.error, e:
                err = 'DATA_PARSE_ERROR|%s|%s' % (fmt, e)
                return (pkt, err)
            cp += struct.calcsize(fmt)
            client_ip = str(ipaddr.IPAddress(client_ip))

            fmt = '%ds' % (names_len)

            try:
                name_set = struct.unpack(fmt,
                        dnsflow_pkt[cp:cp + struct.calcsize(fmt)])[0]
            except struct.error, e:
                err = 'DATA_PARSE_ERROR|%s|%s' % (fmt, e)
                return (pkt, err)
            cp += struct.calcsize(fmt)
            if vers == 1:
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
            except struct.error, e:
                err = 'DATA_PARSE_ERROR|%s|%s' % (fmt, e)
                return (pkt, err)
            cp += struct.calcsize(fmt)
            ips = [str(ipaddr.IPAddress(x)) for x in ips]

            data = {}
            data['client_ip'] = client_ip
            data['names'] = names
            data['ips'] = ips
            pkt['data'].append(data)

    return (pkt, err)

def print_parsed_pkt(pkt):
    global cfg

    hdr = pkt['header']
    ts = hdr['timestamp']
    if cfg['ts_level'] >= 2:
        tstr = time.strftime('%Y%m%d:%H:%M:%S', time.gmtime(ts))
    else:
        tstr = time.strftime('%H:%M:%S', time.gmtime(ts))

    print 'HEADER|%s|%s|%d|%d|%d' % (hdr['src_ip'], tstr,
            hdr['sets_count'], hdr['flags'], hdr['sequence_number'])

    if 'stats' in pkt:
        stats = pkt['stats']
        print "STATS|%s" % ('|'.join([str(x) for x in stats.values()]))
    else:
        if cfg['ts_level'] >= 1:
            data_ts = '%s|' % (tstr)
        else:
            data_ts = ''
        
        for data in pkt['data']:
            print 'DATA|%s|%s%s|%s' % (data['client_ip'], data_ts,
                    ','.join(data['names']), ','.join(data['ips']))

                
def read_pcapfiles(pcap_files, pcap_filter, callback):
    for pcap_file in pcap_files:
        print 'FILE|%s' % (pcap_file)
        # XXX dpkt pcap doesn't support filters and there's no way to pass
        # a gzip fd to pylibpcap. Bummer.
        p = pcap.pcapObject()
        p.open_offline(pcap_file)
        # filter, optimize, netmask
        # XXX This doesn't work with dump straight to pcap.
        # For now use -F "" in that case.
        p.setfilter(pcap_filter, 1, 0)

        while 1:
            rv = p.next()
            if rv == None:
                break
            pktlen, buf, ts = rv
            pkt, err = process_pkt(p.datalink(), ts, buf)
            if err is not None:
                print err
                continue
            callback(pkt)

def mode_livecapture(interface, pcap_filter, callback):
    print 'Capturing on', interface
    p = pcap.pcapObject()
    p.open_live(interface, 65535, 1, 100)
    # filter, optimize, netmask
    p.setfilter(pcap_filter, 1, 0)

    try:
        while 1:
            rv = p.next()
            if rv != None:
                pktlen, buf, ts = rv
                pkt, err = process_pkt(p.datalink(), ts, buf)
                if err is not None:
                    print err
                    continue
                callback(pkt)

    except KeyboardInterrupt:
        print '\nshutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
   

def main(argv):
    global cfg

    usage = ('Usage: %s [-sStv] ' % (argv[0]) +
        '[-f filter] [-F filter] [-x regex] -r pcap_file or -i interface')

    try:
        opts, args = getopt.getopt(argv[1:], 'f:F:i:r:sStvx:')
    except getopt.GetoptError:
        print >>sys.stderr, usage
        return 1

    pcap_files = []
    interface = None
    print_summary = False

    base_filter = 'udp and dst port 5300'
    pcap_filter = base_filter
    
    for o, a in opts:
        if o == '-v':
            cfg['verbosity'] += 1
        elif o == '-t':
            cfg['ts_level'] += 1
        elif o == '-r':
            pcap_files.append(a)
        elif o == '-i':
            interface = a
        elif o == '-s':
            print_summary = True
        elif o == '-S':
            cfg['track_subs'] = True
        elif o == '-f':
            # extra filter
            pcap_filter = '(%s) and (%s)' % (base_filter, a)
        elif o == '-F':
            # complete filter
            pcap_filter = a
        elif o == '-x':
            cfg['regex'] = re.compile(a)

    pcap_files.extend(args)

    if len(pcap_files) > 0:
        read_pcapfiles(pcap_files, pcap_filter, print_parsed_pkt)
    elif interface is not None:
        mode_livecapture(interface, pcap_filter, print_parsed_pkt)
    else:
        print usage
        sys.exit(1)

if __name__ == '__main__':
    main(sys.argv)

