/*
 * dnsflow.c
 *
 * Copyright (c) 2011, DeepField Networks, Inc. <info@deepfield.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of DeepField Networks, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * 
 */

/* DNS Flow Packet Format
   Header:
     version		[1 bytes]
     sets_count		[1 bytes]
     flags		[2 bytes]
     sequence_number	[4 bytes]
     sets		[variable]

   Data Set:
     ip_vers		[1 byte]
     client_ip		[4 bytes]/[16 bytes]
     resolver_ip	[4 bytes]/[16 bytes]
     names_count	[1 byte]
     ips_count		[1 byte]
     ip6s_count		[1 byte]
     names_len		[2 bytes]
     names		[variable] Each is a Nul terminated string.
     ips		[variable] Word-aligned, starts at names + names_len, each is 4 bytes
     ip6s		[variable] Word-aligned, starts at names + names_len, each is 16 bytes

    Stats Set:
      pkts_captured	[4 bytes]
      pkts_received	[4 bytes]
      pkts_dropped	[4 bytes]
      pkts_ifdropped	[4 bytes] Only supported on some platforms.
      sample_rate	[4 bytes]
 */
#include <sys/file.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#if __linux__
#include <sys/prctl.h>
#endif
#include <inttypes.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <err.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#include <ldns/ldns.h>
#include <event.h>

#include "dcap.h"


/* Define a MAX/MIN macros, if we don't already have then. */
#ifndef MAX
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#endif
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif


#define DNSFLOW_MAX_PARSE		255
#define DNSFLOW_PKT_BUF_SIZE		65535
#define DNSFLOW_PKT_MAX_SIZE 		1500
#define DNSFLOW_PKT_TARGET_SIZE		1200
#define DNSFLOW_VERSION			4
#define DNSFLOW_PORT			5300
#define DNSFLOW_UDP_MAX_DSTS		10

#define DNSFLOW_FLAG_STATS		0x0001

#define DNSFLOW_SETS_COUNT_MAX		255
#define IP6VERSION                      0x60 
#define IP6VERSIONMASK                  0xf0
#define IP6PACKETHDRLEN			40
struct dnsflow_hdr {
	uint8_t			version;
	uint8_t			sets_count;
	uint16_t		flags;
	uint32_t		sequence_number;
};

#define DNSFLOW_NAMES_COUNT_MAX		255
#define DNSFLOW_IPS_COUNT_MAX		255
#define DNSFLOW_IP4_SET_HDR		40
#define DNSFLOW_IP6_SET_HDR		40
struct dnsflow_set_hdr {
	uint8_t			ip_vers;
	uint8_t			names_count;
	uint8_t			ips_count;
	uint8_t			ip6s_count;
	uint16_t		names_len;
	union {
		struct in_addr		client_ip4;
		struct in6_addr		client_ip6;
	} client_ip;
	union {
		struct in_addr		resolver_ip4;
		struct in6_addr		resolver_ip6;
	} resolver_ip;
};
struct dns_data_set {
	uint8_t			*names[DNSFLOW_MAX_PARSE];
	int				name_lens[DNSFLOW_MAX_PARSE];
	int				num_names;
	struct in_addr	ips[DNSFLOW_MAX_PARSE];
	struct in6_addr	ip6s[DNSFLOW_MAX_PARSE];
	int				num_ips;
	int				num_ip6s;
};

struct dnsflow_data_pkt {
	/* Variable sized pkt, allocate maximum size when it's a data pkt. */
	char				pkt[1]; /* DNSFLOW_PKT_BUF_SIZE */
};


struct dnsflow_stats_pkt {
	uint32_t	pkts_captured;
	uint32_t	pkts_received;
	uint32_t	pkts_dropped;
	uint32_t	pkts_ifdropped; /* according to pcap, only supported
					   on some platforms */
	uint32_t	sample_rate;
};

enum dnsflow_buf_type {
	DNSFLOW_DATA,
	DNSFLOW_STATS,
};
struct dnsflow_buf {
	uint32_t		db_type;	/* What's in the union */
	uint32_t		db_len;		/* Size of what's in the pkt,
						   db_pkt_hdr and below. */

	uint32_t		db_loop_hdr;	/* Holds PF_ type when dumping
						   straight to pcap file. */
	struct dnsflow_hdr	db_pkt_hdr;
	union {
		struct dnsflow_data_pkt		data_pkt;
		struct dnsflow_stats_pkt	stats_pkt;
	} DB_dat;
};

/* pcap record headers for saved files */
struct pcap_timeval {
    bpf_int32 tv_sec;		/* seconds */
    bpf_int32 tv_usec;		/* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;	/* time stamp */
    bpf_u_int32 caplen;		/* length of portion present */
    bpf_u_int32 len;		/* length this packet (off wire) */
};

/* From http://www.juniper.net/techpubs/en_US/junos/topics/concept/subscriber-management-subscriber-secure-policy-radius-header.html 
 * Note: looks like juniper has another slightly different mirror format:
 * https://www.juniper.net/techpubs/en_US/junos/topics/concept/subscriber-management-subscriber-secure-policy-dtcp-header.html. Not sure when that would be 
 * used. */
struct jmirror_hdr {
	uint32_t	intercept_id;
	uint32_t	session_id;
};

#define db_data_pkt	DB_dat.data_pkt
#define db_stats_pkt	DB_dat.stats_pkt

/*** Globals ***/
/* pkt building */
static uint32_t			sequence_number = 1;
static struct dnsflow_buf	*data_buf = NULL;
static time_t			last_send = 0;

static struct event		push_ev;
static struct timeval		push_tv = {1, 0};

static struct event		stats_ev;
static struct timeval		stats_tv = {10, 0};

#if !__linux__
static struct event		check_parent_ev;
static struct timeval		check_parent_tv = {1, 0};
#endif

static struct event		sigterm_ev, sigint_ev, sigchld_ev;

/* config */

/* pcap-record dest port (*network* byte order) */
static int pcap_record_dst_port_enabled = 0;
static uint16_t pcap_record_dst_port = 0;

/* jmirror dest port (*network* byte order) - typically 30030 */
static int jmirror_dst_port_enabled = 0;
static uint16_t jmirror_dst_port = 0;

static int 			udp_num_dsts = 0;
static struct sockaddr_in	dst_so_addrs[DNSFLOW_UDP_MAX_DSTS];

static pcap_t			*pc_dump = NULL;
static pcap_dumper_t		*pdump = NULL;

#define MAX_MPROC_CHILDREN	64
static pid_t			mproc_children[MAX_MPROC_CHILDREN];
static int			n_mproc_children = 0;
static pid_t			my_pid;


static void
_log(const char *format, ...)
{
	char		buf[1024];
	va_list		args;

	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	fprintf(stderr, "[%d]: %s\n", my_pid, buf);
}


/* Add up to 1 sec of jitter. */
static struct timeval *
jitter_tv(struct timeval *tv)
{
	tv->tv_usec = random() % 1000000;
	return (tv);
}

static void
dnsflow_print_stats(struct dcap_stat *ds)
{
	_log("%u packets captured", ds->captured);
	if (ds->ps_valid) {
		_log("%u packets received by filter", ds->ps_recv);
		_log("%u packets dropped by kernel", ds->ps_drop);
		_log("%u packets dropped by interface", ds->ps_ifdrop);
	}
}

static void
clean_exit(struct dcap *dcap)
{
	struct dcap_stat		*ds;
	int				i;

	if (n_mproc_children != 0) {
		/* Tell children to exit. */
		for (i = 0; i < n_mproc_children; i++) {
			kill(mproc_children[i], SIGTERM);
		}
	}

	_log("Shutting down.");
	ds = dcap_get_stats(dcap);
	dnsflow_print_stats(ds);
	if (pdump != NULL) {
		pcap_dump_close(pdump);
		pcap_close(pc_dump);
	}

	exit(0);
}

#if !__linux__
static void
check_parent_cb(int fd, short event, void *arg) 
{
	struct dcap			*dcap = (struct dcap *)arg;

	if (getppid() == 1) {
		/* orphaned */
		_log("parent exited");
		clean_exit(dcap);
	}
	evtimer_add(&check_parent_ev, &check_parent_tv);
}
#endif

/* When running in multi-proc mode, if the parent dies, want to make sure the
 * children exit. */
static void
check_parent_setup(struct dcap *dcap)
{
#if __linux__
	/* Linux provides a more efficient way to check for parent exit. */
	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1) {
		errx(1, "prctl failed");
	}
#else
	bzero(&check_parent_ev, sizeof(check_parent_ev));
	evtimer_set(&check_parent_ev, check_parent_cb, dcap);
	evtimer_add(&check_parent_ev, &check_parent_tv);
#endif
}

/* Returns the proc number for this process. The parent is always 1. */
static int
mproc_fork(int num_procs)
{
	int	proc_i;
	pid_t	pid;

	if ((num_procs < 1) || (num_procs > MAX_MPROC_CHILDREN)) {
		errx(1, "num_procs (%d) is not in range [1, %d]. "
		     "Recompile dnsflow.c with a larger value for "
		     "MAX_MPROC_CHILDREN to utilize more processes.",
		     num_procs, MAX_MPROC_CHILDREN);
	}
	if (num_procs > get_nprocs()) {
		errx(1, "num_procs (%d) is more than "
		     "the number of available processors (%d). "
		     "This degrades performance, so it is not allowed.",
		     num_procs, get_nprocs());
	}

	/* proc_i is 1-based. 1 is parent; start at 2. */
	for (proc_i = 2; proc_i <= num_procs; proc_i++) {
		if((pid = fork()) < 0) {
			errx(1, "fork error");
		} else if (pid == 0) {
			/* child */
			n_mproc_children = 0;
			return (proc_i);
		} else {
			/* parent */
			/* XXX Use process group instead? */
			mproc_children[n_mproc_children++] = pid;
		}
	}

	/* parent gets slot 1. */
	return (1);
}

/* encap_offset is the number of bytes between the end of the udp header
 * and the start of the encapsulated ip header.
 * Ie., the length of foo bar: ip udp (foo bar) ip udp dns
 * 
 * proc_i and num_procs use 1-based numbering.
 * */
static char *
build_pcap_filter(int encap_offset, int proc_i, int num_procs, int enable_mdns, int enable_ipv4_checksum_mproc_filter)
{
	/* Note: according to pcap-filter(7), udp offsets only work for ipv4.
	 * (Would have to use ip6 offsets.) */

	/* Offsets from start of udp. */
	int udp_offset = 0;	/* Offset from udp to encap udp. */
	/* Label offsets used. */
	int dns_flags_offset = 10;

	/* Offsets from start of ip. */
	int ip_offset = 0;	/* Offset from ip to encap ip. */
	int ip6_offset = 40;	/* Offset of udp from ip6. */
	/* Label offsets used. */
	int dst_ip_offset = 16;
	int checksum_udp_offset = 6;


	/* Buffers to build pcap filter */
	char port_filter[1024];
	char dns_resp_filter[1024];
	char multi_proc_filter[1024];
	/* The final filter returned in static buf. */
	static char full_filter_ret[1024];

	if (encap_offset != 0) {
		/* udp, encap, ip, udp */
		udp_offset = sizeof(struct udphdr) + encap_offset +
			sizeof(struct ip);
		/* ip, udp, encap, ip */
		ip_offset = sizeof(struct ip) + sizeof(struct udphdr) +
			encap_offset;
	}

	/* Port filter - Match src port 53 (and optionally 5353). */
	if (enable_mdns) {
		snprintf(port_filter, sizeof(port_filter),
			 "(src port 53 or src port 5353)");
	} else {
		snprintf(port_filter, sizeof(port_filter),
			 "src port 53");
	}

	/* Base dns filter - combine port and flag filters. */
	/* Match valid recursive response flags.
	 * qr=1, rd=1, ra=1, rcode=0.
	 * XXX Could also pull out just A/AAAA. */
	snprintf(dns_resp_filter, sizeof(dns_resp_filter),
		 "(udp and %s and (ip6 or (ip and udp[%d:1] & 0x80 = 0x80)))", port_filter, dns_flags_offset + udp_offset);

	if (num_procs > 1) {
		char *cp = NULL;
		/* Multi-process filter:
		 *  - For ip6, select based on modulo of udp checksum. Note that
		 *    the 'udp' shorthand does not work in the ip6 context for the
		 *    pcap filter language, so the checksum is found by offsetting
		 *    appropriately from the ip6 accessor.
		 *  - For ip4, since the udp checksum is optional (0 when not computed),
		 *    the default filter selects based on modulo of client ip,
		 *    which is the dst ip for dns responses. It does so using offset
		 *    from ip, so ip options will break view into encap. Using the client
		 *    ip as the load balance key may be useful to keep each client
		 *    in same stream. Optionally, one can activate an ip4 filter
		 *    that selects based on module of udp checksum when it is available,
		 *    falling back to default ip4 filter when it is not.
		 */
		/* Note about performance:
		 *  - We avoid explicit use of the % operator, and instead
		 *    express (x % y) as (x - x/y*y) for integers x, y. According
		 *    to the pcap-filter(7) man page, the % and ^ operators
		 *    have limited support in some kernels (older or non-linux),
		 *    which can have severe performance impacts.
		 */
		if (!enable_ipv4_checksum_mproc_filter) {
			snprintf(multi_proc_filter, sizeof(multi_proc_filter),
				 "(ip and (%s) and ((ip[%d:4] - ip[%d:4]/%u*%u) = %u)) or ",
				 dns_resp_filter, dst_ip_offset + ip_offset,
				 dst_ip_offset + ip_offset, num_procs, num_procs, proc_i - 1);
			cp = multi_proc_filter;
			cp += strlen(multi_proc_filter);
		} else {
			snprintf(multi_proc_filter, sizeof(multi_proc_filter),
				 "(ip and (%s) and (((udp[%d:2] != 0) and ((udp[%d:2] - udp[%d:2]/%u*%u) = %u)) or ((udp[%d:2] = 0) and ((ip[%d:4] - ip[%d:4]/%u*%u) = %u)))) or ",
				 dns_resp_filter,
				 checksum_udp_offset, checksum_udp_offset, checksum_udp_offset, num_procs, num_procs, proc_i - 1,
				 checksum_udp_offset, dst_ip_offset + ip_offset, dst_ip_offset + ip_offset, num_procs, num_procs, proc_i - 1);
			cp = multi_proc_filter;
			cp += strlen(multi_proc_filter);
		}
		snprintf(cp, sizeof(multi_proc_filter) - (cp - multi_proc_filter),
			 "(ip6 and (%s) and ((ip6[%d:2] - ip6[%d:2]/%u*%u) = %u))",
			 dns_resp_filter, ip6_offset + checksum_udp_offset,
			 ip6_offset + checksum_udp_offset, num_procs, num_procs, proc_i - 1);
	} else {
		/* Just copy base dns filter. */
		snprintf(multi_proc_filter, sizeof(multi_proc_filter), "%s", dns_resp_filter);
	}


	/* The final filter returned in static buf. Incorporates one level
	 * of vlan encapsulation. */
	bzero(full_filter_ret, sizeof(full_filter_ret));
	snprintf(full_filter_ret, sizeof(full_filter_ret),
			"(%s) or (vlan and (%s))",
			multi_proc_filter, multi_proc_filter);

	return (full_filter_ret);
}

char *
ts_format(struct timeval *ts)
{
	int		sec, usec;
	static char	buf[256];

       	sec = ts->tv_sec % 86400;
	usec = ts->tv_usec;

	snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%06u",
		 sec / 3600, (sec % 3600) / 60, sec % 60, usec);

	return buf;
}

/**
 * Write and lock pid file.
 *
 * return 1 on success, 0 on failure.
 */
static int
write_pid_file(char *pid_file)
{
	int	fd;
	FILE	*fp;	

	fd = open(pid_file, O_CREAT | O_RDWR, 0666);
	if (fd == -1) {
		perror(pid_file);
		return 0;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		if (errno != EWOULDBLOCK) {
			perror(pid_file);
		}
		return 0;
	}

	if (ftruncate(fd, 0) < 0) {
		perror(pid_file);
		return 0;
	}
	fp = fdopen(fd, "w");

	fprintf(fp, "%u\n", getpid());

	fflush(fp);
	fsync(fileno(fp));

	return 1;
}

static struct ip6_hdr *
ip6_check(int pkt_len, char *ip_pkt) {
	struct ip6_hdr  *ip6 = (struct ip6_hdr *)ip_pkt;
	if (pkt_len < sizeof(struct ip6_hdr)) {
		return (NULL);
	}    
	if ((ip6->ip6_vfc & IP6VERSIONMASK) != IP6VERSION) {
		return (NULL);
	}    
	if (pkt_len < IP6PACKETHDRLEN) {
		return (NULL);
	}    
	if (pkt_len < ntohs(ip6->ip6_plen)) {
		return (NULL);
	}    
	return (ip6);
}

/* IP checks - version, header len, pkt len. */
static struct ip *
ip4_check(int pkt_len, char *ip_pkt) {
	struct ip	*ip = (struct ip *)ip_pkt;

	if (pkt_len < sizeof(struct ip)) {
		return (NULL);
	}
	if (ip->ip_v != IPVERSION) {
		return (NULL);
	}
	
	if (pkt_len < (ip->ip_hl << 2)) {
		return (NULL);
	}
	if (pkt_len < ntohs(ip->ip_len)) {
		return (NULL);
	}
	if (ntohs(ip->ip_len) < (ip->ip_hl << 2)) {
		return (NULL);
	}

	return (ip);
}

static struct udphdr *
udp_check(int pkt_len, struct ip *ip, struct ip6_hdr *ip6)
{
	struct udphdr	*udphdr;
	struct ip6_ext  *ip6_ext;
	int		ip_hdr_len;
	int		next_hdr;
	int		offset;

	if (ip && ip->ip_p == IPPROTO_UDP) {
		ip_hdr_len = ip->ip_hl << 2;
		if (pkt_len < sizeof(struct ip) + sizeof(struct udphdr)) {
			return (NULL);
		}
		udphdr = (struct udphdr *) (((u_char *) ip) + ip_hdr_len);
	} else if (ip6) {
		// Note that this loop does not provide much utility
		// when the default base filter using `src port 53` is
		// in use because the pcap-filter does not know to
		// offset to the correct location to check for
		// UDP.src_port when additional extension headers
		// appear before the UDP section. Thus, we would
		// likely never encounter a valid IPv6/UDP packet that
		// would need to enter the while-loop
		// below. Fortunately, most (if not all) IPv6/UDP/DNS
		// responses that we are collecting do not have
		// additional extension headers. We leave this loop in
		// for exploratory analysis with custom filters.
		next_hdr = ip6->ip6_nxt;
		ip_hdr_len = sizeof(struct ip6_hdr);
		ip6_ext = (struct ip6_ext *)((struct ip6_hdr *)(ip6 + 1));
		while (next_hdr != IPPROTO_UDP) {
			if (pkt_len < ip_hdr_len + sizeof(struct ip6_ext)) {
				return (NULL);
			}
			next_hdr = ip6_ext->ip6e_nxt;
			offset = (ip6_ext->ip6e_len + 1)*8;
			// this may occur if we are dealing with garbage data,
			// which may cause this loop to run forever
			if (offset <= 0) {
				return (NULL);
			}
			ip_hdr_len +=offset;
			ip6_ext = (struct ip6_ext *)(((caddr_t)ip6_ext) + offset);
		}
		if (next_hdr == IPPROTO_UDP) {
			if (pkt_len < ip_hdr_len + sizeof(struct udphdr)) {
				return (NULL);
			}
			udphdr = (struct udphdr *)ip6_ext;
		} else {
			return (NULL);
		}
	} else {
		return (NULL);
	}

	if (pkt_len < ip_hdr_len + ntohs(udphdr->uh_ulen)) {
		return (NULL);
	}

	return (udphdr);
}

/* Sanity/buffer-len checks.
 * Returns pointer to udp data, or NULL on error.
 * On success, ip_ret and udphdr_ret will point to the headers. */
static char *
ip_udp_check(int pkt_len, char *ip_pkt,
		struct ip **ip_ret, struct ip6_hdr **ip6_ret, struct udphdr **udphdr_ret)
{
	char			*udp_data = NULL;
	struct ip		*ip = NULL;
	struct ip6_hdr	*ip6 = NULL;
	struct udphdr		*udphdr = NULL;

	*ip_ret = NULL;
	*ip6_ret = NULL;
	*udphdr_ret = NULL;

	/* XXX Count/log number of bad pkts. */
	/* XXX Need to pull in ip/udp checksumming and fragment handling. */

	if (((ip = ip4_check(pkt_len, ip_pkt)) == NULL) && 
		((ip6 = ip6_check(pkt_len, ip_pkt)) == NULL)) {
		return NULL;
	}

	if ((udphdr = udp_check(pkt_len, ip, ip6)) == NULL) {
		return NULL;
	}
	udp_data = (char *)udphdr + sizeof(struct udphdr);

	*ip_ret = ip;
	*ip6_ret = ip6;
	*udphdr_ret = udphdr;
	return (udp_data);
}

/* Handle encapsulated ip pkts.
 * encap_hdr should point to the start of encapsulated pkt.
 * ip_encap_offset is the number of bytes to reach the ip header.
 * Returns pointer to udp data, or NULL on error.
 * On success, ip_ret and udphdr_ret will point to the headers. */
static char *
ip_encap_check(int pkt_len, char *encap_hdr, int ip_encap_offset,
		struct ip **ip_ret, struct ip6_hdr **ip6_ret, struct udphdr **udphdr_ret)
{
	*ip_ret = NULL;
	*ip6_ret = NULL;
	*udphdr_ret = NULL;

	if (pkt_len < ip_encap_offset) {
		return (NULL);
	}

	return (ip_udp_check(pkt_len - ip_encap_offset,
			encap_hdr + ip_encap_offset, ip_ret, ip6_ret, udphdr_ret));
}

static ldns_pkt *
dnsflow_dns_check(int pkt_len, char *dns_pkt)
{
	ldns_status		status;
	ldns_pkt		*lp;
	ldns_rr			*q_rr;

	status = ldns_wire2pkt(&lp, (uint8_t *)dns_pkt, pkt_len);
	if (status != LDNS_STATUS_OK) {
		_log("Bad DNS pkt: %s", ldns_get_errorstr_by_id(status));
		return (NULL);
	}

	/* Looking for valid recursive replies */
	if (ldns_pkt_qr(lp) != 1 ||
	    ldns_pkt_rd(lp) != 1 ||
	    ldns_pkt_ra(lp) != 1 ||
	    ldns_pkt_get_rcode(lp) != LDNS_RCODE_NOERROR) {
		ldns_pkt_free(lp);
		return (NULL);
	}

	/* Check that there's only one question. Generally, this should be true
	 * as there's no way to reply to more than one question prior to
	 * proposals in EDNS1. */
	if (ldns_pkt_qdcount(lp) != 1) {
		ldns_pkt_free(lp);
		return (NULL);
	}

	/* Only look at replies to A queries. Could possibly look at
	 * CNAME queries as well, but those aren't generally used. */
	q_rr = ldns_rr_list_rr(ldns_pkt_question(lp), 0);
	if (ldns_rr_get_type(q_rr) != LDNS_RR_TYPE_A && 
		ldns_rr_get_type(q_rr) != LDNS_RR_TYPE_AAAA) {
		ldns_pkt_free(lp);
		return (NULL);
	}

	return (lp);
}

/* NOTE: The names in the returned dns_data_set point to data inside the
 * ldns_pkt. So, don't free the packet until the names have been copied. */
static struct dns_data_set *
dnsflow_dns_extract(ldns_pkt *lp)
{
	/* Statics */
	static struct dns_data_set	data[1];

	ldns_rr_type			rr_type;
	ldns_rr				*q_rr, *a_rr;
	ldns_rdf			*rdf;

	int				i, j;
	struct in_addr			*ip_ptr;
	struct in6_addr			*ip6_ptr;


	data->num_names = 0;
	data->num_ips = 0;
	data->num_ip6s = 0;

	q_rr = ldns_rr_list_rr(ldns_pkt_question(lp), 0);

	if (ldns_rdf_size(ldns_rr_owner(q_rr)) > LDNS_MAX_DOMAINLEN) {
		/* I believe this should never happen for valid DNS. */
		_log("Invalid query string");
		return (NULL);
	}
	data->names[data->num_names] = ldns_rdf_data(ldns_rr_owner(q_rr));
	data->name_lens[data->num_names] = ldns_rdf_size(ldns_rr_owner(q_rr));
	data->num_names++;

	for (i = 0; i < ldns_pkt_ancount(lp); i++) {
		a_rr = ldns_rr_list_rr(ldns_pkt_answer(lp), i);
		rr_type = ldns_rr_get_type(a_rr);

		/* XXX Not necessary, remove when we have more confidence. */
		/*
		str = ldns_rdf2str(ldns_rr_owner(a_rr));
		if (strcmp(str, data->names[data->num_names - 1])) {
			_log("XXX msg not in sequence");
			ldns_pkt_print(stdout, lp);
		}
		LDNS_FREE(str);
		*/

		for (j = 0; j < ldns_rr_rd_count(a_rr); j++) {
			rdf = ldns_rr_rdf(a_rr, j);

			if (rr_type == LDNS_RR_TYPE_CNAME) {
				if (data->num_names == DNSFLOW_MAX_PARSE) {
					_log("Too many names");
					continue;
				}
				if (ldns_rdf_size(rdf) > LDNS_MAX_DOMAINLEN) {
					/* Again, I believe this should never
					 * happen. */
					_log("Invalid name");
					continue;
				}
				data->names[data->num_names] =
					ldns_rdf_data(rdf);
				data->name_lens[data->num_names] =
					ldns_rdf_size(rdf);
				data->num_names++;
			} else if (rr_type == LDNS_RR_TYPE_A) {
				if (data->num_ips == DNSFLOW_MAX_PARSE) {
					_log("Too many ips");
					continue;
				}
				ip_ptr = (struct in_addr *) ldns_rdf_data(rdf);
				data->ips[data->num_ips++] = *ip_ptr;
			} else if (rr_type == LDNS_RR_TYPE_AAAA) {
				if (data->num_ip6s == DNSFLOW_MAX_PARSE) {
					_log("Too many ips");
					continue;
				}
				ip6_ptr = (struct in6_addr *) ldns_rdf_data(rdf);
				data->ip6s[data->num_ip6s++] = *ip6_ptr;
			} else {
				/* XXX Only looking at A queries, so this is
				 * unexpected rdata. */
			}
		}
	}
	
	/* Sanity checks */
	if (data->num_names == 0) {
		return (NULL);
	}
	if (data->num_ips == 0 && data->num_ip6s == 0) {
		return (NULL);
	}

	return (data);
}

static void
dnsflow_pkt_send(struct dnsflow_buf *dnsflow_buf)
{
	static int 		udp_socket = 0;
	struct pcap_pkthdr 	pkthdr;
	int			i;

	if (pdump != NULL) {
		uint8_t			tmp[4096];
		struct iphdr		*ip;
		struct udphdr		*udp;
		uint8_t			*data;
		struct sockaddr_in	saddr, daddr;
		u_int32_t		*link;

		uint32_t		pf_type;	/* Loopback "header" */
		int			linkheader_size = sizeof(pf_type);

		memset(tmp, 0, sizeof(tmp));

		pf_type = PF_INET;

		link = (u_int32_t *) tmp;
		ip = (struct iphdr *) (link + 1);
		udp = (struct udphdr *) (ip+1);
		data = (uint8_t *) (udp+1);


		daddr.sin_family = AF_INET;
		saddr.sin_family = AF_INET;
		daddr.sin_port = htons(5300);
		saddr.sin_port = htons(0);
		inet_pton(AF_INET, "127.0.0.1", (struct in_addr *)&daddr.sin_addr.s_addr);
		inet_pton(AF_INET, "127.0.0.1", (struct in_addr *)&saddr.sin_addr.s_addr);

		ip->ihl      = 5; /* header length, number of 32-bit words */
		ip->version  = 4;
		ip->tos      = 0x0;
		ip->id       = 0;
		ip->frag_off = htons(0x4000); /* Don't fragment */
		ip->ttl      = 64;
		ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + dnsflow_buf->db_len);
		ip->protocol = IPPROTO_UDP;
		ip->saddr    = saddr.sin_addr.s_addr;
		ip->daddr    = daddr.sin_addr.s_addr;

		udp->uh_sport = saddr.sin_port;
		udp->uh_dport = daddr.sin_port;
		udp->uh_ulen = htons(sizeof(struct udphdr) + dnsflow_buf->db_len);
		udp->uh_sum = 0;

		memcpy(link, &pf_type, linkheader_size);
		memcpy(data, &dnsflow_buf->db_pkt_hdr, sizeof(tmp) - (data - tmp));

		gettimeofday(&pkthdr.ts, NULL);
		pkthdr.len = dnsflow_buf->db_len + 20 + 8 + 4; /* ip=20, udp=8, 4=loopback */
		pkthdr.caplen = pkthdr.len;
		pcap_dump((u_char *)pdump, &pkthdr, (u_char *) tmp);
		return;
	}

	if (udp_num_dsts == 0) {
		return;
	}

	if (udp_socket == 0) {
		if ((udp_socket = socket(PF_INET, SOCK_DGRAM, 0)) < 1) {
			err(1, "socket failed");
		}
	}
	for (i = 0; i < udp_num_dsts; i++) {
		if (sendto(udp_socket, &dnsflow_buf->db_pkt_hdr, dnsflow_buf->db_len, 0,
				(struct sockaddr *)&dst_so_addrs[i],
				sizeof(struct sockaddr_in)) < 0) {
			warnx("send failed");
		}
	}
}

static void
dnsflow_pkt_send_data()
{
	if (data_buf->db_len == 0) {
		return;
	}
	data_buf->db_pkt_hdr.sequence_number = htonl(sequence_number++);
	dnsflow_pkt_send(data_buf);
	data_buf->db_len = 0;
	last_send = time(NULL);
}

static void
dnsflow_push_cb(int fd, short event, void *arg) 
{
	time_t		now = time(NULL);

	if (now - last_send >= push_tv.tv_sec) {
		dnsflow_pkt_send_data();
	}
	evtimer_add(&push_ev, jitter_tv(&push_tv));
}

/* XXX Need more care to prevent buffer overruns. */
static void
dnsflow_pkt_build(struct in_addr* client_ip, struct in6_addr* client_ip6, struct in_addr* resolver_ip, struct in6_addr* resolver_ip6, struct dns_data_set *dns_data)
{
	struct dnsflow_hdr		*dnsflow_hdr;
	struct dnsflow_set_hdr		*set_hdr;
	char				*pkt_start, *pkt_cur, *pkt_end, *names_start;
	int				i, j;
	int				header_len = 0;
	struct in_addr			*ip_ptr;
	struct in6_addr			*ip6_ptr;
	int 				set_len, ips_len_total, ip6s_len_total;
	int 				name_len_total = 0;
	uint8_t 			names_count, ips_count, ip6s_count;

	dnsflow_hdr = &data_buf->db_pkt_hdr;
	pkt_start = (char *)dnsflow_hdr;
	if (data_buf->db_len == 0) {
		/* Starting a new pkt. */
		bzero(dnsflow_hdr, sizeof(struct dnsflow_hdr));
		data_buf->db_len += sizeof(struct dnsflow_hdr);
		dnsflow_hdr->version = DNSFLOW_VERSION;
		dnsflow_hdr->sets_count = 0;
	}
	pkt_cur = pkt_start + data_buf->db_len;
	pkt_end = pkt_start + DNSFLOW_PKT_MAX_SIZE - 1;

	/* Estimate length of set to see if it fits in this pkt*/
	set_len = sizeof(struct dnsflow_set_hdr);

	names_count = 
		MIN(dns_data->num_names, DNSFLOW_NAMES_COUNT_MAX);
	ips_count = 
		MIN(dns_data->num_ips, DNSFLOW_IPS_COUNT_MAX);
	ip6s_count = 
		MIN(dns_data->num_ip6s, DNSFLOW_IPS_COUNT_MAX);
	for (j = 0; j < names_count; j++) {
		name_len_total += dns_data->name_lens[j];
	}
	set_len += name_len_total;
	ips_len_total = ips_count * sizeof(struct in_addr);
	ip6s_len_total = ip6s_count * sizeof(struct in6_addr);
	set_len += ips_len_total;
	set_len += ip6s_len_total;

	/* This set will not fit in any dnsflow pkt*/
	if (set_len > DNSFLOW_PKT_MAX_SIZE - sizeof(dnsflow_hdr) + 1) {
		return;
	}
	/* This set will fit in the remainder of this dnsflow pkt*/
	if (set_len < pkt_end - pkt_cur + 1) {
		/* Start building new set. */
		set_hdr = (struct dnsflow_set_hdr *)pkt_cur;
		bzero(set_hdr, sizeof(struct dnsflow_set_hdr));
		/* XXX Not warning if we're truncating names, ips. */
		if (client_ip) {
			header_len = DNSFLOW_IP4_SET_HDR;
			set_hdr->ip_vers = 4;
			set_hdr->client_ip.client_ip4 = *client_ip;
			set_hdr->resolver_ip.resolver_ip4 = *resolver_ip;
		} else {
			header_len = DNSFLOW_IP6_SET_HDR;
			set_hdr->ip_vers = 6;
			set_hdr->client_ip.client_ip6 = *client_ip6;
			set_hdr->resolver_ip.resolver_ip6 = *resolver_ip6;
		}
		set_hdr->names_count = names_count;
		set_hdr->ips_count = ips_count;
		set_hdr->ip6s_count = ip6s_count;
		data_buf->db_len += header_len;
		pkt_cur = pkt_start + data_buf->db_len;

		names_start = pkt_cur;
		for (i = 0; i < set_hdr->names_count; i++) {
			if (dns_data->name_lens[i] > pkt_end - pkt_cur) {
				/* Not enough room. Shouldn't happen. */
				_log("Pkt create error");
				data_buf->db_len = 0;
				return;
			}
			memcpy(pkt_cur, dns_data->names[i], dns_data->name_lens[i]);
			data_buf->db_len += dns_data->name_lens[i];
			pkt_cur = pkt_start + data_buf->db_len;
		}
		while (data_buf->db_len % 4 != 0) {
			/* Pad to word boundary. */
			pkt_start[data_buf->db_len++] = '\0';
		}
		pkt_cur = pkt_start + data_buf->db_len;
		set_hdr->names_len = htons(pkt_cur - names_start);

		for (i = 0; i < set_hdr->ips_count; i++) {
			ip_ptr = (struct in_addr *)pkt_cur;
			*ip_ptr = dns_data->ips[i];
			data_buf->db_len += sizeof(struct in_addr);
			pkt_cur = pkt_start + data_buf->db_len;
		}
		for (i = 0; i < set_hdr->ip6s_count; i++) {
			ip6_ptr = (struct in6_addr *)pkt_cur;
			*ip6_ptr = dns_data->ip6s[i];
			data_buf->db_len += sizeof(struct in6_addr);
			pkt_cur = pkt_start + data_buf->db_len;
		}

		dnsflow_hdr->sets_count++;

		if (data_buf->db_len >= DNSFLOW_PKT_TARGET_SIZE ||
		    dnsflow_hdr->sets_count == DNSFLOW_SETS_COUNT_MAX) {
			/* Send */
			dnsflow_pkt_send_data();
		}
	}
	/* This set will fit in the next dnsflow pkt*/
	else {
		/* Send and reset data buffer len */
		dnsflow_pkt_send_data();
		/* Start a new packet*/
		dnsflow_pkt_build(client_ip, client_ip6, resolver_ip, resolver_ip6, dns_data);
	}

}

static void
dnsflow_dcap_cb(struct timeval *tv, int pkt_len, char *ip_pkt, void *user)
{
	struct ip		*ip;
	struct ip6_hdr		*ip6;
	struct udphdr		*udphdr;
	char			*udp_data;
	int			ip_encap_offset = 0;
	int			remaining = pkt_len;

	ldns_pkt		*lp;
	struct dns_data_set	*dns_data;

	if ((udp_data = ip_udp_check(pkt_len, ip_pkt, &ip, &ip6,  &udphdr)) == NULL) {
		return;
	}
	remaining -= udp_data - ip_pkt;

	/* Handle various encapsulations. */
	if (pcap_record_dst_port_enabled && (udphdr->uh_dport == pcap_record_dst_port)) {
		/* pcap header, eth, ip, udp, dns */
		ip_encap_offset = sizeof(struct pcap_sf_pkthdr)
			+ sizeof(struct ether_header);
	} else if (jmirror_dst_port_enabled && (udphdr->uh_dport == jmirror_dst_port)) {
		/* jmirror, ip, udp, dns */
		ip_encap_offset = sizeof(struct jmirror_hdr);
	}
	if (ip_encap_offset != 0) {

		udp_data = ip_encap_check(remaining, udp_data, ip_encap_offset,
				&ip, &ip6, &udphdr); 
		if (udp_data == NULL) {
			return;
		}
	}

	lp = dnsflow_dns_check(ntohs(udphdr->uh_ulen), udp_data);
	if (lp == NULL) {
		/* Bad dns pkt, or one we're not interested in. */
		return;
	}

	if ((dns_data = dnsflow_dns_extract(lp)) == NULL) {
		ldns_pkt_free(lp);
		return;
	}

	/* Should be good to go. */
	if (ip) {
		dnsflow_pkt_build(&ip->ip_dst, NULL, &ip->ip_src, NULL, dns_data);
	} else if (ip6) {
		dnsflow_pkt_build(NULL, &ip6->ip6_dst, NULL, &ip6->ip6_src, dns_data);
	}
	//ldns_pkt_print(stdout, lp);
	ldns_pkt_free(lp);
	lp = NULL;
}

static void
dnsflow_stats_cb(int fd, short event, void *arg) 
{
	struct dcap			*dcap = (struct dcap *)arg;
	struct dcap_stat		*ds;
	struct dnsflow_buf		buf;

	static int			stats_counter = 0;

	evtimer_add(&stats_ev, jitter_tv(&stats_tv));

	ds = dcap_get_stats(dcap);
	stats_counter++;
	if (stats_counter % 6 == 0) {
		/* Print stats once a minute. */
		dnsflow_print_stats(ds);
	}

	bzero(&buf, sizeof(buf));

	buf.db_type = DNSFLOW_STATS;
	buf.db_len = sizeof(struct dnsflow_hdr) +
		sizeof(struct dnsflow_stats_pkt);

	buf.db_pkt_hdr.version = DNSFLOW_VERSION;
	buf.db_pkt_hdr.sets_count = 1;
	buf.db_pkt_hdr.flags = htons(DNSFLOW_FLAG_STATS);
	buf.db_pkt_hdr.sequence_number = htonl(sequence_number++);

	buf.db_stats_pkt.pkts_captured = htonl(ds->captured);
	buf.db_stats_pkt.pkts_received = htonl(ds->ps_recv);
	buf.db_stats_pkt.pkts_dropped = htonl(ds->ps_drop);
	buf.db_stats_pkt.pkts_ifdropped = htonl(ds->ps_ifdrop);
	buf.db_stats_pkt.sample_rate = htonl(dcap->sample_rate);

	dnsflow_pkt_send(&buf);
}

static void
signal_cb(int signal, short event, void *arg) 
{
	struct dcap			*dcap = (struct dcap *)arg;
	int				stat_loc;
	pid_t				pid;

	switch (signal) {
	case SIGINT:
	case SIGTERM:
		_log("received exit signal: %d", signal);
		clean_exit(dcap);	/* Doesn't return. */
		break;
	case SIGCHLD:
		pid = wait(&stat_loc);
		_log("child exited: %d", pid);
		clean_exit(dcap);
		break;
	default:
		errx(1, "caught unexpected signal: %d", signal);
		break;
	}

}

/* XXX Disable for production */
static void
dnsflow_event_log_cb(int severity, const char *msg)
{
	if (severity == _EVENT_LOG_DEBUG) {
		return;
	}
	_log("event: %d: %s", severity, msg);
}

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "Usage: %s [-hp] [-i interface] [-r pcap_file] "
			"[-f filter_expression] \n", __progname);
	fprintf(stderr, "\t[-P pidfile]  [-m proc_i/n_procs] [-M n_procs] "
			"[-s sample_rate]\n");
	/* Encap options */
	fprintf(stderr, "\t[-X pcap_record_recv_port] "
			"[-J jmirror_port (usually 30030)]\n");
	fprintf(stderr, "\t[-Y] (add mDNS port to filter)\n");
	/* Output options */
	fprintf(stderr, "\t[-u udp_dst] [-w pcap_file_dst]\n");
	/* new improved ipv4 checksum-based filter */
	fprintf(stderr, "\t[-c] (use ipv4 checksum for multi-proc filter, use with -M)\n");
	fprintf(stderr, "\n  Default filter: %s\n",
		build_pcap_filter(0, 1, 1, 0, 0));

	exit(1);
}

int
main(int argc, char *argv[])
{
	int			c, rv, promisc = 1;
	char			*pcap_file_read = NULL, *pcap_file_write = NULL;
	char			*filter = NULL, *intf_name = NULL;
	struct dcap		*dcap = NULL;
	struct dcap_stat	*ds = NULL;
	struct sockaddr_in	*so_addr = NULL;
	int			encap_offset = 0;
	int			enable_mdns = 0;
	int			enable_ipv4_checksum_mproc_filter = 0;
	uint32_t		n_procs = 1, proc_i = 1, auto_n_procs = 0;
	int			is_child = 0;
	uint16_t		sample_rate = 0;

	while ((c = getopt(argc, argv, "i:J:r:f:m:M:pP:s:u:w:X:Yv:h:c")) != -1) {
		switch (c) {
		case 'c':
			enable_ipv4_checksum_mproc_filter = 1;
			break;
		case 'i':
			intf_name = optarg;
			break;
		case 'J':
			jmirror_dst_port_enabled = 1;
			jmirror_dst_port = htons(atoi(optarg));
			if (filter == NULL) {
				/* udp, jmirror, ip, udp, dns */
				encap_offset = sizeof(struct jmirror_hdr);
			}
			break;
		case 'f':
			filter = optarg;
			break;
		case 'm':
			if (sscanf(optarg, "%u/%u", &proc_i, &n_procs) !=2 ) {
				errx(1, "invalid multiproc option -- %s",
						optarg);
			}
			if (n_procs == 0 || proc_i == 0 || proc_i > n_procs) {
				errx(1, "invalid multiproc option -- %s",
						optarg);
			}
			break;
		case 'M':
			auto_n_procs = atoi(optarg);
			// automatically set to half of CPUs if desired
			if (auto_n_procs == 0) {
				auto_n_procs = MAX(1, get_nprocs()/2);
				if (auto_n_procs > MAX_MPROC_CHILDREN) {
					warnx("Reducing num procs (%d) to static limit defined by MAX_MPROC_CHILDREN (%d). "
					      "Recompile dnsflow.c with a larger value for MAX_MPROC_CHILDREN to utilize "
					      "more processes.", auto_n_procs, MAX_MPROC_CHILDREN);
					auto_n_procs = MAX_MPROC_CHILDREN;
				}
			}
			break;
		case 'p':
			promisc = 0;
			break;
		case 'P':
			if (!write_pid_file(optarg)) {
				errx(1, "dnsflow already running");
			}
			break;
		case 'r':
			pcap_file_read = optarg;
			break;
		case 's':
			sample_rate = atoi(optarg);
			break;
		case 'u':
			if (udp_num_dsts == DNSFLOW_UDP_MAX_DSTS) {
				errx(1, "too many udp dsts");
			}
			so_addr = &dst_so_addrs[udp_num_dsts++];
			bzero(so_addr, sizeof(struct sockaddr_in));
			so_addr->sin_family = AF_INET;
			so_addr->sin_port = htons(DNSFLOW_PORT);
			if (inet_pton(AF_INET, optarg,
					&so_addr->sin_addr) != 1) {
				errx(1, "invalid ip: %s", optarg);
			}
			break;
		case 'X':
			pcap_record_dst_port_enabled = 1;
			pcap_record_dst_port = htons(atoi(optarg));
			if (filter == NULL) {
				/* udp, pcap header, eth, ip, udp, dns */
				encap_offset = sizeof(struct pcap_sf_pkthdr) +
					sizeof(struct ether_header);
			}
			break;
		case 'Y':
			enable_mdns = 1;
			break;
		case 'w':
			pcap_file_write = optarg;
			break;
		case 'h':
		default:
			usage();
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	if (udp_num_dsts == 0 && pcap_file_write == NULL) {
		errx(1, "output dst missing");
	}

	/* Fork if requested, and not done manually. */
	if (n_procs == 1 && auto_n_procs > 0) {
		if (pcap_file_write != NULL) {
			errx(1, "can't use -w and -M together");
		}
		if ((proc_i = mproc_fork(auto_n_procs)) != 1) {
			is_child = 1;
		}
		n_procs = auto_n_procs;
	}
	my_pid = getpid();

	/* Need some randomness for jitter. */
	srandom(getpid());

	/* for testing. Note, event debug only available in libevent2. */
	/*
	event_enable_debug_mode();
	event_enable_debug_logging(EVENT_DBG_ALL);
	*/
	/* Init libevent - must happen after fork on os x (kqueue), or use
	 * event_reinit() */
	event_init();
	event_set_log_callback(dnsflow_event_log_cb);

	if (filter == NULL) {
		filter = build_pcap_filter(encap_offset, proc_i, n_procs,
					   enable_mdns, enable_ipv4_checksum_mproc_filter);
	}

	/* Init pcap */
	if (pcap_file_read != NULL) {
		dcap = dcap_init_file(pcap_file_read, filter, dnsflow_dcap_cb);
		_log("reading from file %s, filter %s", pcap_file_read,
				filter);

	} else {
		dcap = dcap_init_live(intf_name, promisc, filter,
				dnsflow_dcap_cb);
		if (dcap == NULL) {
			errx(1, "dcap_init failed");
		}
		if (dcap_event_set(dcap) < 0) {
			errx(1, "dcap_event_set failed");
		}

		_log("listening on %s, filter %s", dcap->intf_name, filter);

		/* Send pcap stats every 10sec. */
		bzero(&stats_ev, sizeof(stats_ev));
		evtimer_set(&stats_ev, dnsflow_stats_cb, dcap);
		evtimer_add(&stats_ev, jitter_tv(&stats_tv));
	}
	if (dcap == NULL) {
		exit(1);
	}

	/* Sampling */
	if (sample_rate > 1) {
		dcap->sample_rate = sample_rate;
		_log("sample_rate set to %u", sample_rate);
	}

	/* Even if the flow pkt isn't full, send any buffered data every
	 * second. */
	bzero(&push_ev, sizeof(push_ev));
	evtimer_set(&push_ev, dnsflow_push_cb, NULL);
	evtimer_add(&push_ev, jitter_tv(&push_tv));

	/* Set signal handlers. Do after dcap_init so dcap can be passed
	 * as arg. */
	bzero(&sigterm_ev, sizeof(sigterm_ev));
	signal_set(&sigterm_ev, SIGTERM, signal_cb, dcap);
	signal_add(&sigterm_ev, NULL);

	bzero(&sigint_ev, sizeof(sigint_ev));
	signal_set(&sigint_ev, SIGINT, signal_cb, dcap);
	signal_add(&sigint_ev, NULL);

	bzero(&sigchld_ev, sizeof(sigchld_ev));
	signal_set(&sigchld_ev, SIGCHLD, signal_cb, dcap);
	signal_add(&sigchld_ev, NULL);

	if (is_child) {
		check_parent_setup(dcap);
	}

	if (pcap_file_write != NULL) {
		pc_dump = pcap_open_dead(DLT_NULL, 65535);
		pdump = pcap_dump_open(pc_dump, pcap_file_write);
		if (pdump == NULL) {
			errx(1, "%s: %s", pcap_file_write,
					pcap_geterr(pc_dump));
		}
	}

	/* B/c of the union, this allocates more than max for the pkt, but
	 * not a big deal. */
	data_buf = calloc(1, sizeof(struct dnsflow_buf) + DNSFLOW_PKT_BUF_SIZE);
	data_buf->db_type = DNSFLOW_DATA;

	/* Pcap/event loop */
	if (pcap_file_read != NULL) {
		dcap_loop_all(dcap);
		dcap_close(dcap);
		dnsflow_pkt_send_data();	/* Send last pkt. */
	} else {
		rv = event_dispatch();
		dcap_close(dcap);
		errx(1, "event_dispatch terminated: %d", rv);
	}

	if (pdump != NULL) {
		pcap_dump_close(pdump);
		pcap_close(pc_dump);
	}

	free(data_buf);

	ds = dcap_get_stats(dcap);
	dnsflow_print_stats(ds);

	return (0);
}

