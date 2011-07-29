/*
 * dnsflow
 *
 * Copyright (c) 2011 DeepField Networks <info@deepfield.net>
 */

/* DNS Flow Packet Format

   Header:
     version		[1 bytes]
     sets_count		[1 bytes]
     flags		[2 bytes]
     sequence_number	[4 bytes]
     sets		[variable]

   Set:
     client_ip		[4 bytes]
     names_count	[1 byte]
     ips_count		[1 byte]
     names_len		[2 bytes]
     names		[variable] Each is a Nul terminated string.
     ips		[variable] Word-aligned, starts at names + names_len,
     			           each is 4 bytes.
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

/* Note, for mac, check for __APPLE__ */
#ifdef __linux__
#include <bsd/string.h>
#endif

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

struct dns_pkt_data {
	char 			*names[DNSFLOW_MAX_PARSE];
	int			num_names;
	in_addr_t		ips[DNSFLOW_MAX_PARSE];
	int			num_ips;
};

/* Define so we can dump packets to pcap. */
struct loopback_header {
	uint32_t	pf_type;
	char		pkt[DNSFLOW_PKT_MAX_SIZE];
};

/*** Globals ***/
/* pkt building */
struct loopback_header	loopback_header;
char			*pkt = loopback_header.pkt;
int			pkt_num_bytes = 0;
time_t			last_send = 0;

struct event		push_ev;
struct timeval		push_tv = {1, 0};

struct event		sigterm_ev, sigint_ev;

/* config */
char 			*default_filter =
			  "udp and src port 53 and udp[10:2] & 0x8187 = 0x8180";

int 			udp_num_dsts = 0;
struct sockaddr_in	dst_so_addrs[DNSFLOW_UDP_MAX_DSTS];

pcap_t			*pc_dump = NULL;
pcap_dumper_t		*pdump = NULL;


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
dnsflow_dns_data_free(struct dns_pkt_data *data)
{
	int 	i;
	for (i = 0; i < data->num_names; i++) {
		LDNS_FREE(data->names[i]);
	}
}

/* Caller must free the names returned. */
static struct dns_pkt_data *
dnsflow_dns_extract(ldns_pkt *lp)
{
	/* Statics */
	static struct dns_pkt_data	data[1];

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
	str = ldns_rdf2str(ldns_rr_owner(q_rr));
	/* XXX remove root dot. */
	data->names[data->num_names++] = str;

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
				str = ldns_rdf2str(rdf);
				data->names[data->num_names++] = str;
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
dnsflow_pkt_send()
{
	static int 		udp_socket = 0;
	struct pcap_pkthdr 	pkthdr;
	int			i;

	if (pkt_num_bytes == 0) {
		return;
	}

	if (pdump != NULL) {
		loopback_header.pf_type = PF_UNSPEC;
		gettimeofday(&pkthdr.ts, NULL);
		pkthdr.caplen = pkt_num_bytes + 4; /* 4 for loopback hdr. */
		pkthdr.len = pkt_num_bytes + 4;
		pcap_dump((u_char *)pdump, &pkthdr, (u_char *)&loopback_header);
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
		if (sendto(udp_socket, pkt, pkt_num_bytes, 0,
				(struct sockaddr *)&dst_so_addrs[i],
				sizeof(struct sockaddr_in)) < 0) {
			warnx("send failed");
		}
	}
	pkt_num_bytes = 0;
	last_send = time(NULL);
}

static void
dnsflow_push_cb(int fd, short event, void *arg) 
{
	time_t		now = time(NULL);

	if (now - last_send >= push_tv.tv_sec) {
		dnsflow_pkt_send();
	}
	evtimer_add(&push_ev, &push_tv);
}

static void
dnsflow_pkt_build(in_addr_t client_ip, struct dns_pkt_data *dns_data)
{
	/* Statics */
	static int		pkt_num_sets = 0;
	static uint32_t		sequence_number = 1;

	struct dnsflow_hdr	*dnsflow_hdr;
	struct dnsflow_set_hdr	*set_hdr;
	char			*pkt_cur, *pkt_end, *names_start;
	int			i, len;
	in_addr_t		*ip_ptr;

	dnsflow_hdr = (struct dnsflow_hdr *)pkt;
	if (pkt_num_bytes == 0) {
		/* Starting a new pkt. */
		bzero(dnsflow_hdr, sizeof(struct dnsflow_hdr));
		dnsflow_hdr->version = DNSFLOW_VERSION;
		dnsflow_hdr->sequence_number = htonl(sequence_number++);
		pkt_num_bytes += sizeof(struct dnsflow_hdr);
		pkt_num_sets = 0;
		pkt_end = pkt + DNSFLOW_PKT_MAX_SIZE - 1;
	}
	pkt_cur = pkt + pkt_num_bytes;

	/* Start building new set. */
	set_hdr = (struct dnsflow_set_hdr *)pkt_cur;
	bzero(set_hdr, sizeof(struct dnsflow_set_hdr));
	set_hdr->client_ip = client_ip;
	/* XXX Not warning if we're truncating names, ips. */
	set_hdr->names_count =
		MIN(dns_data->num_names, DNSFLOW_NAMES_COUNT_MAX);
	set_hdr->ips_count =
		MIN(dns_data->num_ips, DNSFLOW_IPS_COUNT_MAX);
	pkt_num_bytes += sizeof(struct dnsflow_set_hdr);
	pkt_cur = pkt + pkt_num_bytes;

	names_start = pkt_cur;
	for (i = 0; i < set_hdr->names_count; i++) {
		/* XXX Not checking that I don't run off the end of the pkt,
		 * but there's no way we ever could (I think). */
		len = strlcpy(pkt_cur, dns_data->names[i], pkt_end - pkt_cur);
		pkt_num_bytes += len + 1; /* len doesn't include Nul byte. */
		pkt_cur = pkt + pkt_num_bytes;
	}
	while (pkt_num_bytes % 4 != 0) {
		/* Pad to word boundary. */
		pkt[pkt_num_bytes++] = '\0';
	}
	pkt_cur = pkt + pkt_num_bytes;
	set_hdr->names_len = htons(pkt_cur - names_start);

	for (i = 0; i < set_hdr->ips_count; i++) {
		ip_ptr = (in_addr_t *)pkt_cur;
		*ip_ptr = dns_data->ips[i];
		pkt_num_bytes += sizeof(in_addr_t);
		pkt_cur = pkt + pkt_num_bytes;
	}

	pkt_num_sets++;
	dnsflow_hdr->sets_count = pkt_num_sets;

	if (pkt_num_bytes >= DNSFLOW_PKT_TARGET_SIZE ||
	    pkt_num_sets == DNSFLOW_SETS_COUNT_MAX) {
		/* Send */
		dnsflow_pkt_send();
	}
}


static void
dnsflow_dcap_cb(struct timeval *tv, int pkt_len, char *ip_pkt)
{
	struct ip		*ip;
	struct udphdr		*udphdr;
	uint8_t			*udp_data;

	ldns_pkt		*lp;
	struct dns_pkt_data	*dns_data;

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

	if (pcap_file_read != NULL) {
		dcap_loop_all(dcap);
		dcap_close(dcap);
		dnsflow_pkt_send();	/* Send last pkt. */
	} else {
		rv = event_dispatch();
		dcap_close(dcap);
		errx(1, "event_dispatch terminated: %d", rv);
	}

	if (pdump != NULL) {
		pcap_dump_close(pdump);
		pcap_close(pc_dump);
	}

	return (0);
}

