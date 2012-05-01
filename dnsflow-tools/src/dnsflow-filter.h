#ifndef _DNSFLOW_FILTER_H_
#define _DNSFLOW_FILTER_H_


#include "dnsflow.h"
#include <arpa/inet.h>

enum Filter_keyword_e { aip, cip, rip, dname, dlength, unknown_kw };
enum Filter_opt_e { equals, not_equals, less_than, greater_than, unknown_opt };
enum Addr_type_e { ipv4, ipv6 };

//typedef struct in_adder in_addr;
//typedef struct in6_adder in6_addr;

//typedef for storing either a in_addr or in6_addr type
typedef
union {
	struct in_addr addr;
	struct in6_addr addr6;
} ip_addr_any_t;

typedef 
struct {
	enum Addr_type_e type;
	ip_addr_any_t ip;
} ip_addr_entry_t;

//processing filter functions
void filter_parse_fail(char * msg);
enum Filter_keyword_e get_filter_keyword(char * filter_str, int * offset);
enum Filter_opt_e get_filter_opt(char * filter_str, int * offset);
//char * get_filter_value(char * filter_str, int * offset, int * strlen);
char * advance_past_whitespace(char * filter_str, int * offset);
void get_dname_str(char * str, char * buf);
void update_filter(enum Filter_keyword_e kw_e, enum Filter_opt_e opt_e,
		char * str);
void update_length_filter(enum Filter_opt_e opt_e, char * str);
void update_aip_filter(enum Filter_opt_e opt_e, char * str);
void update_dname_filter(enum Filter_opt_e opt_e, char * str);
int dname_filter(struct dns_data_set * data, struct dnsflow_set_hdr * set_hdr);
int aip_filter(struct dns_data_set * data, struct dnsflow_set_hdr * set_hdr);
int dlength_filter(struct dns_data_set * data, struct dnsflow_set_hdr * set_hdr);
int valid_domain_level_length(char * dname, int dlength, int dlevel, enum Filter_opt_e opt);

void get_dlength_and_level(char * str, int * dlength, int * dlevel);
//gint g_ip_addr_comp(gconstpointer a, gconstpointer b)

void read_from_stdin();
void usage();
void read_from_dcap_files(int argc, char * argv[]);
int parse_dcap_packet(char * data, unsigned int total_data, struct dcap_header * dcap_hdr);
int parse_dnsflow_packet(char * data, unsigned int total_data);

int process_dcap_filename(char * pcapfile, unsigned int *pkt_counter_p,
	   unsigned int *byte_counter_p);

int process_dcap_file(char * filename);

//Modular
void process_filter(char * optarg);
void parse_filter_string(char * filter_str);
void print_filter_warning();

int filter_dnsflow_data_packet(struct dcap_header * hdr, char * data, unsigned int len);
int filter_dnsflow_packet(struct dcap_header * hdr, char * dnsflow_data, unsigned int len);
int filter_dnsflow_stats_packet(char * data, unsigned int len);
int read_filenames_from_commandline(char * argv[], int argc);
char * get_next_filename();
int filter_dnsflow_dataset(struct dns_data_set * data, struct dnsflow_set_hdr * set_hdr);

//dlength stuff
int get_level_length(int level, int num_levels, char * dname);
int count_levels(char * dname, int length);

#endif /* _DNSFLOW_FILTER_H_ */


