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

#include <net/ethernet.h>
#include <event.h>

#include "dcap.h"

#ifndef ETHERTYPE_VLAN
#define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */
#endif

#define MAXIMUM_SNAPLEN		65535

static int
datalink_offset(int i)
{
	switch (i) {
	case DLT_EN10MB:
		i = sizeof(struct ether_header);
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
	uint16_t		ether_type;
	pcap_t			*pcap = NULL;
	struct dcap		*dcap;
	int			length, dl, dloff;
	char			*p;

	if (pkthdr->caplen != pkthdr->len) {
		/* XXX better warning */
		printf("Invalid caplen: %d %d\n", pkthdr->caplen, pkthdr->len);
		return;
	}

	dcap = (struct dcap *) user;
	pcap = dcap->pcap;

	dl = pcap_datalink(pcap);
	dloff = datalink_offset(dl);
	if(dloff == -1) {
		printf("Unsupported datalink: %d\n", dl);
		return;
	}

	if (pkthdr->len < dloff + sizeof(struct ip)) {
		printf("Invalid packet: length=%d\n", pkthdr->len);
		return;
	}

	p = (char *)pkt;
	length = pkthdr->len;

	p += dloff;
	length -= dloff;

	if(dl != DLT_NULL 
#ifdef DLT_LOOP
		&& dl != DLT_LOOP)
#endif
	{
		eh = (struct ether_header *)p;
		ether_type = ntohs(eh->ether_type);

		/* Unencapsulate 802.1Q or ISL VLAN frames */
		if (ether_type == ETHERTYPE_VLAN) {
			/* XXX - skip length of VLAN tag */
			p += ETHERTYPE_VLAN;  
			eh = (struct ether_header *)p;
			ether_type = ntohs(eh->ether_type);
		} 

		if (ether_type != ETHERTYPE_IP) {
			printf("Non-ip: ether_type=%d\n", ether_type); 
			return;
		}
	}

	dcap->pkts_captured++;
	dcap->callback((struct timeval *)&pkthdr->ts, length, p, dcap->user);
}

/* Returns fd if you want to set up libevent yourself. */
int
dcap_get_fd(struct dcap *dcap)
{
	/* See man page. Apparently it's not always selectable on OS X. */
	return (pcap_get_selectable_fd(dcap->pcap));
}

static void
dcap_event_cb(int fd, short event, void *arg) 
{
	struct dcap	*dcap = (struct dcap *)arg;
#if __APPLE__ && __MACH__
	struct timeval	ev_tv[1] = {{1, 0}};
#else
	struct timeval	*ev_tv = NULL;
#endif

	/* Use pcap_dispatch with cnt of -1 so entire buffer is processed. */
	pcap_dispatch(dcap->pcap, -1, 
			(pcap_handler)dcap_pcap_cb, (u_char *)dcap);
	event_add(dcap->ev_pcap, ev_tv);
}
/* Use libevent to check for readiness. */
int
dcap_event_set(struct dcap *dcap)
{
#if __APPLE__ && __MACH__
	/* Not totally sure what's going on, but it seems bpf won't
	 * consistently mark the fd as readable, possibly not until the whole
	 * buffer fills. So, add timeout to handle low packet rates.
	 * pcap_dispatch() seems to grab any waiting packets, even if the
	 * buffer hasn't filled.  man pcap_get_selectable_fd has some notes on
	 * this. */
	struct timeval	ev_tv[1] = {{1, 0}};
#else
	struct timeval	*ev_tv = NULL;
#endif
	event_set(dcap->ev_pcap, dcap_get_fd(dcap), EV_READ,
			dcap_event_cb, dcap);
	if (event_add(dcap->ev_pcap, ev_tv) < 0) {
		warnx("event_add error");
		return (-1);
	}

	return (0);
}

struct dcap *
dcap_init_live(char *intf_name, int promisc, char *filter,
		dcap_handler callback)
{
	char			errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program      bpf_program;
	bpf_u_int32		localnet, netmask;
	struct dcap		*dcap = NULL;
	pcap_t			*pcap = NULL;
	int			status;

	/* Basically mirroring how tcpdump sets up pcap. Exceptions noted. */
	if (intf_name == NULL) {
		if ((intf_name = pcap_lookupdev(errbuf)) == NULL) {
			warnx("%s", errbuf);
			return (NULL);
		}
	}

	if ((pcap = pcap_create(intf_name, errbuf)) == NULL) {
		warnx("%s", errbuf);
		return (NULL);
	}

	/* Try large enough to hold 1 sec of a GigE interface. */
	if ((status = pcap_set_buffer_size(pcap, 1000000000 / 8)) != 0) {
		warnx("%s: Can't set buffer size: %s",
				intf_name, pcap_statustostr(status));
		pcap_close(pcap);
		return (NULL);
	}
	if ((status = pcap_set_snaplen(pcap, MAXIMUM_SNAPLEN)) != 0) {
		warnx("%s: Can't set snapshot length: %s",
				intf_name, pcap_statustostr(status));
		pcap_close(pcap);
		return (NULL);
	}
	if ((status = pcap_set_promisc(pcap, promisc)) !=0) {
		warnx("%s: Can't set promiscuous mode: %s",
				intf_name, pcap_statustostr(status));
		pcap_close(pcap);
		return (NULL);
	}
	/* What should timeout be? tcpdump just sets to 1000. */
	if ((status = pcap_set_timeout(pcap, 1000)) != 0) {
		warnx("%s: pcap_set_timeout failed: %s",
				intf_name, pcap_statustostr(status));
		pcap_close(pcap);
		return (NULL);
	}

	if ((status = pcap_activate(pcap)) != 0) {
		warnx("%s: %s\n(%s)", intf_name, pcap_statustostr(status),
				pcap_geterr(pcap));
		pcap_close(pcap);
		return (NULL);
	}

	/* Using libevent to check for readiness, so set nonblocking. */
	if ((status = pcap_setnonblock(pcap, 1, errbuf)) !=0) {
		warnx("pcap_setnonblock failed: %s: %s",
				pcap_statustostr(status), errbuf);
		pcap_close(pcap);
		return (NULL);
	}

	dcap = calloc(1, sizeof(struct dcap));
	dcap->pcap = pcap;
	dcap->callback = callback;
	dcap->user = NULL;

	/* Get the netmask. Only used for "ip broadcast" filter expression,
	 * so doesn't really matter. */
	if (pcap_lookupnet(intf_name, &localnet, &netmask, errbuf) < 0) {
		/* Not a fatal error, since we don't care. */
		localnet = 0;
		netmask = 0;
		warnx("%s", errbuf);
	}
	if (pcap_compile(pcap, &bpf_program, filter, 1, netmask) < 0) {
		warnx("%s", pcap_geterr(pcap));
		pcap_close(pcap);
		return (NULL);
	}

	/* XXX There's a race here. The pcap is already activated above,
	 * but we haven't set the filter yet. Could get some unwanted pkts. */
	if (pcap_setfilter(pcap, &bpf_program) < 0) {
		warnx("%s", pcap_geterr(pcap));
		pcap_close(pcap);
		return (NULL);
	}

	dcap = calloc(1, sizeof(struct dcap));
	dcap->pcap = pcap;
	snprintf(dcap->intf_name, sizeof(dcap->intf_name), "%s", intf_name);
	dcap->callback = callback;

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
	dcap->user = NULL;

	printf("reading from file %s, filter %s\n", filename, filter);

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

struct dcap_stat *
dcap_get_stats(struct dcap *dcap)
{
	static struct dcap_stat		ds;
	struct pcap_stat		ps;

	bzero(&ds, sizeof(ds));
	ds.captured = dcap->pkts_captured;

	/* pcap stats not valid for file. */
	if (pcap_file(dcap->pcap) == NULL) {
		bzero(&ps, sizeof(ps));
		if (pcap_stats(dcap->pcap, &ps) < 0) {
			warnx("pcap_stats: %s", pcap_geterr(dcap->pcap));
		} else {
			ds.ps_valid = 1;
			ds.ps_recv = ps.ps_recv;
			ds.ps_drop = ps.ps_drop;
			ds.ps_ifdrop = ps.ps_ifdrop;
		}
	}

	return (&ds);
}


