#ifndef __DNSFLOW_PRINT_H_
#define __DNSFLOW_PRINT_H_

#include <time.h>
#include <sys/types.h>
#include <pcap.h>
#include "dnsflow.h"

#define STDIN_FILE 0

//defining my own struct tm
struct tm32 {
	int32_t tm_sec;   /* Seconds..[0-60] (1 leap second) */
	int32_t tm_min;  /* Minutes..[0-59] */
	int32_t tm_hour;   /* Hours..  [0-23] */
	int32_t tm_mday;   /* Day...   [1-31] */
	int32_t tm_mon;   /* Month..  [0-11] */
	int32_t tm_year;   /* Year.- 1900.  */
	int32_t tm_wday;   /* Day of week..[0-6] */
	int32_t tm_yday;   /* Days in year.[0-365].*/
	int32_t tm_isdst;   /* DST...   [-1/0/1]*/

	int32_t tm_gmtoff;
	int32_t not_used_tm_zone_ptr;
	/*
#ifdef. __USE_BSD
	long int tm_gmtoff;   Seconds east of UTC. 
	__const char *tm_zone;   Timezone abbreviation. 
#else
	long int __tm_gmtoff;    Seconds east of UTC. 
	__const char *__tm_zone;  Timezone abbreviation. 
#endif
	*/
};


struct dcap_header {
	struct tm32 timestamp;
	uint32_t data_len;
};

struct tm32 get_timestamp(char * timestamps);
int get_dnsflow_socketfd(int port, char * interface, int32_t verbosity);
pcap_t * get_pcapfile_handle(char * pcapfile, char * filter);
uint32_t get_header(struct dnsflow_hdr *hdr, char * data);
void parse_stats_packet(char * data_ptr, struct dnsflow_stats_pkt *stats);
uint32_t parse_set_hdr(char * data_ptd, struct dnsflow_set_hdr *set_hdr);
uint32_t parse_dns_data_set_pkt(char * data_ptr,
	   struct dns_data_set * data, struct dnsflow_set_hdr * header);
void print_pcap_stats(uint32_t pkt_counter, uint32_t byte_counter, 
		uint32_t file_counter, clock_t start);
void parse_data_packet(struct dnsflow_hdr * header, char * data_ptr, 
		struct dns_data_set	*data, struct dnsflow_set_hdr * set_header,
	   	uint32_t size);
void listen_for_dnsflow_pkt(int socketfd, int32_t (*func)(char*, uint32_t));
int32_t prepare_to_open_dcap_files(char * filename, int32_t write_flag);
int32_t prepare_to_open_dcap_fileh(FILE * file, int32_t type);
char * get_next_dnsflow_packet(struct dcap_header * header);
int32_t get_tm_timestamp_string(struct tm32 * ts, char * buf, uint32_t buf_size);
void print_hex_data(unsigned char * data, uint32_t len);
void swap_ptrs(void ** a, void ** b);
inline int32_t compare_tm(struct tm32 * a, struct tm32 *b);
uint32_t close_dcap_file(void);

void print_dcap_headers(struct dcap_header ** hdrs, int32_t num);

//reading dcaps
int32_t read_dcap_filestream_cb(FILE * handle, int (*callback)(char *, struct dcap_header *));
char * get_next_dnsflow_packet_from_file(struct dcap_header * header, FILE * file);
void read_dcap_header(struct dcap_header *hdr, FILE * file);
int32_t write_dcap_data(FILE * file, char * data, struct dcap_header * header);
int32_t write_dcap_pkt_to_dcap_file(char * data, struct dcap_header * header, char * filename);
int32_t write_dnsflow_pkt_to_dcap_file(char * data, uint32_t total_size, char * filename);
int32_t write_dnsflow_pkt_to_dcap_fileh(char * data, uint32_t total_size, FILE * file);
void init_dnsflow_data_header(struct dnsflow_hdr * hdr);
int32_t write_dcap_set_to_file(struct dcap_header * dc_hdr, char * data, unsigned int data_size, FILE * file);
int32_t write_dnsflow_set_to_file(struct dnsflow_hdr * hdr, char * data, unsigned int data_size, FILE * file);
void host_to_net_dnsflow_hdr(struct dnsflow_hdr * hdr);

//nmsg format
int32_t write_nmsg_dcap_data(char * data, struct dnsflow_hdr * hdr, uint32_t size);
int32_t write_dnsflow_pkt_to_nmsg_file(char * data, uint32_t total_size); 
int init_nmsg(char * filename);
int cleanup_nmsg();

//packet parsing
int32_t parse_packet_type(char * data, uint32_t len);



#endif /* __DNSFLOW_COMMON_H_ */
