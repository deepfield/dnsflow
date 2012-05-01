#ifndef __DNSFLOW_HEADER_H_
#define __DNSFLOW_HEADER_H_



#define DNSFLOW_PORT 5300
#define DNSFLOW_PKT_MAX_SIZE 65535
#define DNSFLOW_VERISON 0
#define DNSFLOW_FLAG_STATS 0x0001
#define DNSFLOW_HEADER_SIZE 8
#define DNSFLOW_MAX_PARSE 255
#define DNSFLOW_STATS_PKT_SIZE 24
#define DNSFLOW_MAX_DATA_SIZE 255
#define DNSFLOW_TYPE_ERR -1
#define DNSFLOW_TYPE_STATS 0
#define DNSFLOW_TYPE_DATA 1

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <stdint.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/socket.h>
#include <ctype.h>

// DONT CHANGE ORDER ==============================================
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <netdb.h>
#include <net/if.h>
#include <ifaddrs.h>		// NOTE: net/if.h MUST be included BEFORE ifaddrs.h
#include <arpa/inet.h>
//==================================================================


struct dnsflow_hdr {
	uint8_t		version;
	uint8_t		sets_count;
	uint16_t	flags;
	uint32_t	sequence_number;
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
	int32_t			name_lens[DNSFLOW_MAX_PARSE];
	int32_t			num_names;
	in_addr_t		ips[DNSFLOW_MAX_PARSE];
	int32_t			num_ips;
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

#endif /* _DNSFLOW_HEADER_H_ */
