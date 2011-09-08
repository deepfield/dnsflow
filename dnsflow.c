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
     client_ip		[4 bytes]
     names_count	[1 byte]
     ips_count		[1 byte]
     names_len		[2 bytes]
     names		[variable] Each is a Nul terminated string.
     ips		[variable] Word-aligned, starts at names + names_len,
     			           each is 4 bytes.

    Stats Set:
      pkts_captured	[4 bytes]
      pkts_received	[4 bytes]
      pkts_dropped	[4 bytes]
      pkts_ifdropped	[4 bytes] Only supported on some platforms.
 */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <err.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
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
#define DNSFLOW_PKT_MAX_SIZE		65535
#define DNSFLOW_PKT_TARGET_SIZE		1200
#define DNSFLOW_VERSION			0
#define DNSFLOW_PORT			5300
#define DNSFLOW_UDP_MAX_DSTS		10

#define DNSFLOW_FLAG_STATS		0x0001

#define DNSFLOW_SETS_COUNT_MAX		255
struct dnsflow_hdr {
	uint8_t			version;
	uint8_t			sets_count;
	uint16_t		flags;
	uint32_t		sequence_number;
};

#define DNSFLOW_NAMES_COUNT_MAX		255
#define DNSFLOW_IPS_COUNT_MAX		255
struct dnsflow_set_hdr {
	in_addr_t		client_ip;
	uint8_t			names_count;
	uint8_t			ips_count;
	uint16_t		names_len;
};
struct dns_data_set {
	char 			*names[DNSFLOW_MAX_PARSE];
	int			name_lens[DNSFLOW_MAX_PARSE];
	int			num_names;
	in_addr_t		ips[DNSFLOW_MAX_PARSE];
	int			num_ips;
};

struct dnsflow_data_pkt {
	/* Variable sized pkt, allocate maximum size when it's a data pkt. */
	char				pkt[1]; /* DNSFLOW_PKT_MAX_SIZE */
};


struct dnsflow_stats_pkt {
	uint32_t	pkts_captured;
	uint32_t	pkts_received;
	uint32_t	pkts_dropped;
	uint32_t	pkts_ifdropped; /* according to pcap, only supported
					   on some platforms */
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

static struct event		sigterm_ev, sigint_ev;

static uint32_t			pkts_captured = 0;

/* config */
static char *default_filter =
	"udp and src port 53 and udp[10:2] & 0x8187 = 0x8180";

static int 			udp_num_dsts = 0;
static struct sockaddr_in	dst_so_addrs[DNSFLOW_UDP_MAX_DSTS];

static pcap_t			*pc_dump = NULL;
static pcap_dumper_t		*pdump = NULL;


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
udp4_check(int pkt_len, struct ip *ip)
{
	struct udphdr	*udphdr;
	int		ip_hdr_len = ip->ip_hl << 2;

	if (ip->ip_p != IPPROTO_UDP) {
		return (NULL);
	}
	if (pkt_len < sizeof(struct ip) + sizeof(struct udphdr)) {
		return (NULL);
	}
	udphdr = (struct udphdr *) (((u_char *) ip) + ip_hdr_len);
	if (pkt_len < ip_hdr_len + ntohs(udphdr->uh_ulen)) {
		return (NULL);
	}

	return (udphdr);
}

static ldns_pkt *
dnsflow_dns_check(int pkt_len, uint8_t *dns_pkt)
{
	ldns_status		status;
	ldns_pkt		*lp;
	ldns_rr			*q_rr;

	status = ldns_wire2pkt(&lp, dns_pkt, pkt_len);
	if (status != LDNS_STATUS_OK) {
		printf("Bad DNS pkt: %s\n", ldns_get_errorstr_by_id(status));
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
	if (ldns_rr_get_type(q_rr) != LDNS_RR_TYPE_A) {
		ldns_pkt_free(lp);
		return (NULL);
	}

	return (lp);
}

static void
dnsflow_dns_data_free(struct dns_data_set *data)
{
	int 	i;
	for (i = 0; i < data->num_names; i++) {
		LDNS_FREE(data->names[i]);
	}
}

/* Caller must free the names returned. */
static struct dns_data_set *
dnsflow_dns_extract(ldns_pkt *lp)
{
	/* Statics */
	static struct dns_data_set	data[1];

	ldns_rr_type			rr_type;
	ldns_rr				*q_rr, *a_rr;
	ldns_rdf_type			rdf_type;
	ldns_rdf			*rdf;

	int				i, j;
	char				*str;
	in_addr_t			*ip_ptr;


	data->num_names = 0;
	data->num_ips = 0;

	q_rr = ldns_rr_list_rr(ldns_pkt_question(lp), 0);

	
	/* ldns_rdf_size() returns the uncompressed length of an
	 * encoded name. This happens to exactly equal the lenth of the name
	 * as a Nul-terminated dotted string. */
	if (ldns_rdf_size(ldns_rr_owner(q_rr)) > LDNS_MAX_DOMAINLEN) {
		/* I believe this should never happen for valid DNS. */
		printf("Invalid query string\n");
		return (NULL);
	}
	str = ldns_rdf2str(ldns_rr_owner(q_rr));
	/* XXX remove root dot. */
	data->names[data->num_names] = str;
	data->name_lens[data->num_names] = ldns_rdf_size(ldns_rr_owner(q_rr));
	data->num_names++;

	for (i = 0; i < ldns_pkt_ancount(lp); i++) {
		a_rr = ldns_rr_list_rr(ldns_pkt_answer(lp), i);
		rr_type = ldns_rr_get_type(a_rr);

		str = ldns_rdf2str(ldns_rr_owner(a_rr));
		/* XXX Not necessary, remove when we have more confidence. */
		if (strcmp(str, data->names[data->num_names - 1])) {
			printf("XXX msg not in sequence\n");
			ldns_pkt_print(stdout, lp);
		}
		LDNS_FREE(str);

		/* When do you have more than one rd per rr? */
		for (j = 0; j < ldns_rr_rd_count(a_rr); j++) {
			rdf = ldns_rr_rdf(a_rr, j);
			rdf_type = ldns_rdf_get_type(rdf);

			if (rr_type == LDNS_RR_TYPE_CNAME) {
				if (data->num_names == DNSFLOW_MAX_PARSE) {
					printf("Too many names\n");
					continue;
				}
				if (ldns_rdf_size(rdf) > LDNS_MAX_DOMAINLEN) {
					/* Again, I believe this should never
					 * happen. */
					printf("Invalid name\n");
					continue;
				}
				str = ldns_rdf2str(rdf);
				data->names[data->num_names] = str;
				data->name_lens[data->num_names] =
					ldns_rdf_size(rdf);
				data->num_names++;
			} else if (rr_type == LDNS_RR_TYPE_A) {
				if (data->num_ips == DNSFLOW_MAX_PARSE) {
					printf("Too many ips\n");
					continue;
				}
				ip_ptr = (in_addr_t *) ldns_rdf_data(rdf);
				data->ips[data->num_ips++] = *ip_ptr;
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
	if (data->num_ips == 0) {
		dnsflow_dns_data_free(data);
		return (NULL);
	}

	return (data);
}

static void
dnsflow_pkt_send(struct dnsflow_buf *buf)
{
	static int 		udp_socket = 0;
	struct pcap_pkthdr 	pkthdr;
	int			i;

	if (pdump != NULL) {
		gettimeofday(&pkthdr.ts, NULL);
		buf->db_loop_hdr = PF_UNSPEC;
		pkthdr.len = buf->db_len + 4; /* 4 for loopback hdr. */
		pkthdr.caplen = pkthdr.len;
		pcap_dump((u_char *)pdump, &pkthdr,
				(u_char *)&buf->db_loop_hdr);
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
		if (sendto(udp_socket, &buf->db_pkt_hdr, buf->db_len, 0,
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
	evtimer_add(&push_ev, &push_tv);
}

/* XXX Need more care to prevent buffer overruns. */
static void
dnsflow_pkt_build(in_addr_t client_ip, struct dns_data_set *dns_data)
{
	struct dnsflow_hdr	*dnsflow_hdr;
	struct dnsflow_set_hdr	*set_hdr;
	char			*pkt_start, *pkt_cur, *pkt_end, *names_start;
	int			i;
	in_addr_t		*ip_ptr;
	
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

	/* Start building new set. */
	set_hdr = (struct dnsflow_set_hdr *)pkt_cur;
	bzero(set_hdr, sizeof(struct dnsflow_set_hdr));
	set_hdr->client_ip = client_ip;
	/* XXX Not warning if we're truncating names, ips. */
	set_hdr->names_count =
		MIN(dns_data->num_names, DNSFLOW_NAMES_COUNT_MAX);
	set_hdr->ips_count =
		MIN(dns_data->num_ips, DNSFLOW_IPS_COUNT_MAX);
	data_buf->db_len += sizeof(struct dnsflow_set_hdr);
	pkt_cur = pkt_start + data_buf->db_len;

	names_start = pkt_cur;
	for (i = 0; i < set_hdr->names_count; i++) {
		if (dns_data->name_lens[i] > pkt_end - pkt_cur) {
			/* Not enough room. Shouldn't happen. */
			printf("Pkt create error\n");
			data_buf->db_len = 0;
			return;
		}
		strcpy(pkt_cur, dns_data->names[i]);
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
		ip_ptr = (in_addr_t *)pkt_cur;
		*ip_ptr = dns_data->ips[i];
		data_buf->db_len += sizeof(in_addr_t);
		pkt_cur = pkt_start + data_buf->db_len;
	}

	dnsflow_hdr->sets_count++;

	if (data_buf->db_len >= DNSFLOW_PKT_TARGET_SIZE ||
	    dnsflow_hdr->sets_count == DNSFLOW_SETS_COUNT_MAX) {
		/* Send */
		dnsflow_pkt_send_data();
	}
}


static void
dnsflow_dcap_cb(struct timeval *tv, int pkt_len, char *ip_pkt)
{
	struct ip		*ip;
	struct udphdr		*udphdr;
	uint8_t			*udp_data;

	ldns_pkt		*lp;
	struct dns_data_set	*dns_data;

	pkts_captured++;

	if ((ip = ip4_check(pkt_len, ip_pkt)) == NULL) {
		/* Bad pkt */
		return;
	}

	/* XXX Need to pull in ip/udp checksumming and fragment handling. */

	if ((udphdr = udp4_check(pkt_len, ip)) == NULL) {
		/* Bad pkt */
		return;
	}

	udp_data = (uint8_t *)udphdr + sizeof(struct udphdr);
	lp = dnsflow_dns_check(ntohs(udphdr->uh_ulen), udp_data);
	if (lp == NULL) {
		/* Bad dns pkt, or one we're not interested in. */
		return;
	}

	if ((dns_data = dnsflow_dns_extract(lp)) == NULL) {
		ldns_pkt_free(lp);
		return;
	}
	//ldns_pkt_print(stdout, lp);
	ldns_pkt_free(lp);
	lp = NULL;

	/* Should be good to go. */
	dnsflow_pkt_build(ip->ip_dst.s_addr, dns_data);

	/* Free names */
	dnsflow_dns_data_free(dns_data);

}

static void
dnsflow_stats_cb(int fd, short event, void *arg) 
{
	struct pcap_stat		ps;
	struct dcap			*dcap = (struct dcap *)arg;
	struct dnsflow_buf		buf;

	evtimer_add(&stats_ev, &stats_tv);

	bzero(&ps, sizeof(ps));
	if (pcap_stats(dcap->pcap, &ps) < 0) {
		warnx("pcap_stats: %s", pcap_geterr(dcap->pcap));
		return;
	}

	bzero(&buf, sizeof(buf));

	buf.db_type = DNSFLOW_STATS;
	buf.db_len = sizeof(struct dnsflow_hdr) +
		sizeof(struct dnsflow_stats_pkt);

	buf.db_pkt_hdr.version = DNSFLOW_VERSION;
	buf.db_pkt_hdr.sets_count = 1;
	buf.db_pkt_hdr.flags = htons(DNSFLOW_FLAG_STATS);
	buf.db_pkt_hdr.sequence_number = htonl(sequence_number++);

	buf.db_stats_pkt.pkts_captured = htonl(pkts_captured);
	buf.db_stats_pkt.pkts_received = htonl(ps.ps_recv);
	buf.db_stats_pkt.pkts_dropped = htonl(ps.ps_drop);
	buf.db_stats_pkt.pkts_ifdropped = htonl(ps.ps_ifdrop);

	dnsflow_pkt_send(&buf);
}

static void
signal_cb(int signal, short event, void *arg) 
{
	switch (signal) {
	case SIGINT:
		printf("\nShutting down.\n");
		if (pdump != NULL) {
			pcap_dump_close(pdump);
			pcap_close(pc_dump);
		}
		exit(0);
	case SIGTERM:
		if (pdump != NULL) {
			pcap_dump_close(pdump);
			pcap_close(pc_dump);
		}
		exit(0);
	}

}

/* XXX Disable for production */
static void
dnsflow_event_log_cb(int severity, const char *msg)
{
	if (severity == _EVENT_LOG_DEBUG) {
		return;
	}
	printf("event: %d: %s\n", severity, msg);
}

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "Usage: %s [-h] [-i interface] [-r pcap_file] "
			"[-f filter_expression]\n",
		__progname);
	fprintf(stderr, "\t[-u udp_dst] [-w pcap_file_dst]\n");
	fprintf(stderr, "\n  Default filter: %s\n", default_filter);

	exit(1);
}

int
main(int argc, char *argv[])
{
	int			c, rv;
	char			*pcap_file_read = NULL, *pcap_file_write = NULL;
	char			*filter = NULL, *intf_name = NULL;
	struct dcap		*dcap = NULL;
	struct sockaddr_in	*so_addr = NULL;

	while ((c = getopt(argc, argv, "i:r:f:u:w:h")) != -1) {
		switch (c) {
		case 'i':
			intf_name = optarg;
			break;
		case 'f':
			filter = optarg;
			break;
		case 'r':
			pcap_file_read = optarg;
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

	if (filter == NULL) {
		filter = default_filter;
	}

	//liblog_init("dnsflow");

	// Init libevent 
	event_init();
	event_set_log_callback(dnsflow_event_log_cb);
	
	bzero(&sigterm_ev, sizeof(sigterm_ev));
	signal_set(&sigterm_ev, SIGTERM, signal_cb, NULL);
	signal_add(&sigterm_ev, NULL);

	bzero(&sigint_ev, sizeof(sigint_ev));
	signal_set(&sigint_ev, SIGINT, signal_cb, NULL);
	signal_add(&sigint_ev, NULL);

	/* Even if the flow pkt isn't full, send any buffered data every
	 * second. */
	bzero(&push_ev, sizeof(push_ev));
	evtimer_set(&push_ev, dnsflow_push_cb, NULL);
	evtimer_add(&push_ev, &push_tv);

	if (pcap_file_read != NULL) {
		dcap = dcap_init_file(pcap_file_read, filter, dnsflow_dcap_cb);
	} else {
		dcap = dcap_init_live(intf_name, filter, dnsflow_dcap_cb);

		/* Send pcap stats every 10sec. */
		bzero(&stats_ev, sizeof(stats_ev));
		evtimer_set(&stats_ev, dnsflow_stats_cb, dcap);
		evtimer_add(&stats_ev, &stats_tv);
	}
	if (dcap == NULL) {
		exit(1);
	}

	if (pcap_file_write != NULL) {
		pc_dump = pcap_open_dead(DLT_NULL, 65535);
		pdump = pcap_dump_open(pc_dump, pcap_file_write);
		if (pdump == NULL) {
			errx(1, "%s: %s", pcap_file_write,
					pcap_geterr(dcap->pcap));
		}
	}

	/* B/c of the union, this allocates more than max for the pkt, but
	 * not a big deal. */
	data_buf = calloc(1, sizeof(struct dnsflow_buf) + DNSFLOW_PKT_MAX_SIZE);
	data_buf->db_type = DNSFLOW_DATA;

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
	return (0);
}

