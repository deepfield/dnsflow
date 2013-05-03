/*
 * dcap.h
 *
 * Copyright (c) 2011, DeepField Networks, Inc. <info@deepfield.net>
 * All rights reserved.
 *
 */

#ifndef __DCAP_H__
#define __DCAP_H__

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

typedef void (*dcap_handler)(struct timeval *tv, int pkt_len, char *ip_pkt);

struct dcap {
	pcap_t		*pcap;
	char		intf_name[128];
	dcap_handler	callback;
	struct event	ev_pcap[1];
	struct timeval	ev_tv[1];
	uint32_t	pkts_captured;
};

struct dcap_stat {
	int	ps_valid;	/* pcap stats only valid for live capture. */
	/* pcap stats */
	uint32_t ps_recv;
	uint32_t ps_drop;
	uint32_t ps_ifdrop;

	uint32_t captured;
};


struct dcap * dcap_init_file(char *filename, char *filter,
		dcap_handler callback);
struct dcap * dcap_init_live(char *intf_name, int promisc, char *filter,
		dcap_handler callback);
void dcap_loop_all(struct dcap *dcap);
void dcap_close(struct dcap *dcap);

struct dcap_stat * dcap_get_stats(struct dcap *dcap);

#endif /* __DCAP_H__*/

