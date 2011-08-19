/*
 * dcap.c
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
 * sdfdsfsfsdfsdfdsafdsafsdf
 */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <errno.h>
#include <err.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

// Linux is different (and need ifdef)?
#include <net/ethernet.h>
#include <event.h>

#ifdef __linux__
#include <bsd/string.h>
#endif

#include "dcap.h"

static int
dcap_dloff(pcap_t *pd)
{
	int	i;

	switch (pcap_datalink(pd)) {
	case DLT_EN10MB:
		i = 14;
		break;
	case DLT_IEEE802:
		i = 22;
		break;
	case DLT_FDDI:
		i = 21;
		break;
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
		i = 4;
		break;
	default:
		i = -1;
		break;
	}

	return (i);
}


static void 
dcap_pcap_cb(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	struct ether_header	*eh;
	u_int16_t		eth_type;
	pcap_t			*pcap = NULL;
	size_t			dloff;
	struct dcap		*dcap;
	int			datalen;
	char			*ip;

	dcap = (struct dcap *) user;
	pcap = dcap->pcap;
	dloff = dcap_dloff(pcap);

	if (pkthdr->caplen != pkthdr->len) {
		/* XXX warn? */
	}

	datalen = pkthdr->caplen;
	eh = (struct ether_header *)pkt;
	if (dloff == ETHER_ADDR_LEN)
		eth_type = ntohs(eh->ether_type);
	else
		eth_type = ETHERTYPE_IP;

	/* Unencapsulate 802.1Q or ISL VLAN frames */
	if (eth_type == ETHERTYPE_VLAN) {
		/* XXX wtf? this is garbage? */
		/* XXX - skip length of VLAN tag */
		pkt += ETHERTYPE_VLAN;  
		eh = (struct ether_header *)pkt;
		eth_type = ntohs(eh->ether_type);

		/* XXX subtract vlan len from pkt len? */
	} 

	datalen -= dloff;
	ip = (char *)pkt + dloff;
	if (datalen <= 0)
		return;

	dcap->callback((struct timeval *)&pkthdr->ts, datalen, ip);
}

static void
dcap_event_cb(int fd, short event, void *arg) 
{
	struct dcap	*dcap = (struct dcap *)arg;
	
	/* Use pcap_dispatch with cnt of -1 so entire buffer is processed. */
	pcap_dispatch(dcap->pcap, -1, 
			(pcap_handler)dcap_pcap_cb, (u_char *)dcap);
	event_add(dcap->ev_pcap, dcap->ev_tv);
}



struct dcap *
dcap_init_live(char *intf_name, char *filter, dcap_handler callback)
{

	char			errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program      bpf;
	struct dcap		*dcap = NULL;
	pcap_t			*pcap = NULL;
	int			snaplen, to_ms, promisc;
	
	if (intf_name == NULL) {
		if ((intf_name = pcap_lookupdev(errbuf)) == NULL) {
			warnx("no suitable device found");
			return (NULL);
		}
	}

	/* XXX Some parameters we may want to adjust.
	 * Note also, not setting buffer size (pcap_set_buffer_size). It
	 * looks like pcap tries to be smart about picking a default, but
	 * we may need to adjust. */
	snaplen = 65535;	/* Max pkt size? */
	promisc = 0;
	to_ms = 100;		/* In theory, the time for bpf to buffer
				   before marking the fd readable. Although,
				   apparently doesn't work on linux. */
	if ((pcap = pcap_open_live(intf_name, snaplen, promisc,
					to_ms, errbuf)) == NULL) {
		warnx("%s: capture activation failed", intf_name);
		return (NULL);
	}

	if (pcap_compile(pcap, &bpf, filter, 1, 0) < 0) {
		warnx("filter compile failed: %s", pcap_geterr(pcap));
		pcap_close(pcap);
		return (NULL);
	}

	/* XXX There's a race here. The pcap is already activated above,
	 * but we haven't set the filter yet. Could get some unwanted pkts. */
	if (pcap_setfilter(pcap, &bpf) < 0) {
		warnx("filter apply failed: %s", pcap_geterr(pcap));
		pcap_close(pcap);
		return (NULL);
	}

	dcap = calloc(1, sizeof(struct dcap));
	dcap->pcap = pcap;
	dcap->callback = callback;

	/* Not totally sure what's going on, but it seems bpf won't mark the fd
	 * as readable until the whole buffer fills. (Seems weird - isn't that
	 * what to_ms is for? May just be an OS X issue) So, add timeout to
	 * handle low packet rates. pcap_dispatch() seems to grab any waiting
	 * packets, even if the buffer hasn't filled. */
	dcap->ev_tv->tv_usec = to_ms * 1000 * 2;
	/* NOTE: can't use EV_PERSIST with a timeout. */
        event_set(dcap->ev_pcap, pcap_fileno(pcap), EV_READ,
			dcap_event_cb, dcap);
        if (event_add(dcap->ev_pcap, dcap->ev_tv) < 0) {
		warnx("event_add error");
		free(dcap);
		pcap_close(pcap);
		return (NULL);
	}

	printf("listening on %s, filter %s\n", intf_name, filter);

	return (dcap);
}


struct dcap *
dcap_init_file(char *filename, char *filter, dcap_handler callback)
{
	char			pcap_errbuf[PCAP_ERRBUF_SIZE];
        struct bpf_program      bpf;
	struct dcap		*dcap = NULL;
	pcap_t			*pcap = NULL;


	pcap = pcap_open_offline(filename, pcap_errbuf);
	if (pcap == NULL) {
		printf("Could not open file %s (%s)\n", filename, pcap_errbuf);
		return (NULL);
	}

	if (pcap_compile(pcap, &bpf, filter, 1, 0) < 0) {
		printf("filter compile failed: %s\n", pcap_geterr(pcap));
		pcap_close(pcap);
		return (NULL);
	}

	if (pcap_setfilter(pcap, &bpf) < 0) {
		printf("Pcap setfilter failed: %s\n", pcap_geterr(pcap));
		pcap_close(pcap);
		return (NULL);
	}
	
	dcap = calloc(1, sizeof(struct dcap));
	dcap->pcap = pcap;
	dcap->callback = callback;

	return (dcap);
}

void
dcap_loop_all(struct dcap *dcap)
{
	pcap_loop(dcap->pcap, -1, dcap_pcap_cb, (u_char *)dcap);
}

void
dcap_close(struct dcap *dcap)
{
	pcap_close(dcap->pcap);
	free(dcap);
}





