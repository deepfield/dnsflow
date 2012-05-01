#ifndef _DNSFLOW_CAT_H_
#define _DNSFLOW_CAT_H_

#include <sys/types.h>

#include "dnsflow.h"
#include "dnsflow-common.h"

void usage();
int cat_out_file(char * filename);
void close_files(int num, FILE ** files);
void combine_files(int argc, char ** argv);
int process_stats_packet(struct dcap_header * dcap_hdr, struct dnsflow_hdr * dnsf_hdr,
		struct dnsflow_stats_pkt * stats);

void free_dcaps(struct dcap_header ** hdr, int num);
void cat_out_multiple_files(int num_files, char * files[]);
int parse_dcap_data_packet(struct dcap_header * dcap_hdr, char * data);
int process_data_packet(struct dcap_header * dcap_hdr, struct dnsflow_hdr * dnsf_hdr,
		struct dns_data_set * dnsflow_data, struct dnsflow_set_hdr * dnsflow_data_set_hdr);


#endif /* _DNSFLOW_CAT_H_ */
