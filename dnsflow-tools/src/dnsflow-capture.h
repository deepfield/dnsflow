#ifndef __DNSFLOW_CAPTURE_H_
#define __DNSFLOW_CAPTURE_H_

#include "dnsflow-common.h"

int parse_dnsflow_packets(char * data, unsigned int total_size);
//int write_dcap_to_file(char * data, unsigned int total_size, char * filename);
int write_dnsflow_pkt_to_directory(char * data, unsigned int total_size);
int write_dcap_to_directory(char * data, struct dcap_header * header);
int read_from_stdin(void);
void usage();
void get_directory(char * dir);
void get_filename(char * file, char * num);
void get_tm_time(struct tm32 * time);
int is_next_hour();


#endif /* __DNSFLOW_CAPTURE_H_ */


