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
	dcap_handler	callback;
	struct event	ev_pcap[1];
	struct timeval	ev_tv[1];
};


struct dcap * dcap_init_file(char *filename, char *filter,
		dcap_handler callback);
struct dcap * dcap_init_live(char *intf_name, char *filter,
		dcap_handler callback);
void dcap_loop_all(struct dcap *dcap);
void dcap_close(struct dcap *dcap);


#endif /* __DCAP_H__*/

