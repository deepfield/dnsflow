#ifndef _DNSFLOW_FANOUT_H_
#define _DNSFLOW_FANOUT_H_

void usage();
int fanout_dnsflow_packets(char * data, unsigned int data_len);
int parse_client_string(int argc, char ** argv);

#endif /* +_DNSFLOW_FANOUT_H_ */


