#ifndef __DNSFLOW_PRINT_H_
#define __DNSFLOW_PRINT_H_

#include <time.h>
#include <pcap/pcap.h>
#include "dnsflow.h"

//Funtions
void usage(void);
void listen_for_dnsflow_pkt(int sockfd);
int32_t handleRequest(int msgsock);
void print_header(struct dnsflow_hdr *header);
void print_stats_packet(struct dnsflow_stats_pkt  *stats);
void print_set_hdr_packet(struct dnsflow_set_hdr *set_header);
void print_dns_data_set_packet(struct dns_data_set *pkt, 
		struct dnsflow_set_hdr * header);
void print_data_set(struct dnsflow_set_hdr *header, struct dns_data_set * data);
void process_globals(void);
void get_time(void);
void print_default_stats(struct dnsflow_hdr * header,
		struct dnsflow_stats_pkt * stats);
void print_default_data(struct dnsflow_hdr * header, 
						struct dns_data_set *data, 
						struct dnsflow_set_hdr *data_header,
						uint32_t size);
int32_t process_from_pcapfiles(char ** pcapfiles, int32_t length);
int32_t parse_dnsflow_packet(char * data, uint32_t total_data);

int32_t read_from_stdin();
int32_t process_pcap_filename(char * pcapfile, uint32_t *pkt_counter,
	   uint32_t *byte_counter);
void print_argv(char ** a, int32_t c);
int32_t print_dcap_file(char * filename);
int32_t print_dcap_packet(char * data, struct dcap_header * header);

#endif /* __DNSFLOW_PRINT_H_ */
