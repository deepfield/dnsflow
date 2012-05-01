/*

   Filter functionality:
   - listen on interface -i interface
   - listen on port -p port
   - read from dcap file -r filename support glob expansions
   - filter dcap data -f <filter string>
   		- aip = filter for a record ip
		- dname = filter for domain name
		- cip = client ip
		- rip = resolver ip -- not implemented in dnsflow yet
*/

#include "dnsflow.h"
#include "dnsflow-common.h"
#include "dnsflow-filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <string.h>
#include <assert.h>

#define DNSFLOW_MAX_FILTER_LEN 256
#define DNSFLOW_PORT 5300
#define UDP_HEADER_SIZE 8
#define IP_HEADER_SIZE 20
#define ETH_HEADER_SIZE 14
#define KEYWORD_MAX 7
#define DNAME_KEYWORD "dname"
#define DNAME_LEN 5
#define DNAME_MAX_LEN 256
#define AIP_LEN 3
#define AIP_KEYWORD "aip"
#define DLENGTH_KEYWORD "dlength"
#define DLENGTH_LENGTH 30
#define DLENGTH_LEN 7
#define OPERATOR_MAX 2
#define OPERATOR_STR "=!<>"   //operators supported contain == and !=, < or >
#define EQUALS_OPERATOR "=="
#define NOT_EQUALS_OPERATOR "!="
#define LESS_THAN_OPERATOR ">"
#define GREATER_THAN_OPERATOR "<"
#define IP_STRLEN_MAX 15

//#define DO_DEBUG

#ifdef DO_DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#define DBG(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			__LINE__, __func__, __VA_ARGS__); } while (0)

static struct GlobalArgs_t {
	int has_filter;
	char* filter;
	char * outfile;
	FILE * outfile_ptr;
	int has_infiles;
	char * infiles[500];
	int verbosity;
	int filter_stats;
} arguments_g;

//struct for filter 
static struct Filter_t {
	GTree * aip_tree_filter;
	GTree * cip_filter;
	GTree * rip_filter;
	GTree * dname_tree_filter;
	int dlength;
	int dlevel;
	enum Filter_opt_e dlength_operator;
} filter_g;

static char * program_name;

int main(int argc, char *argv[])
{
	DBG("%s\n", "starting filter");
	int c, port = DNSFLOW_PORT;

	program_name = argv[0];
	char opt_string[] = "i:f:p:rv:w:";
	char * interface = 0;

	//init global args
	arguments_g.has_filter = 0;
	arguments_g.outfile = 0;
	arguments_g.has_infiles = 0;
	arguments_g.verbosity = 0;
	arguments_g.filter_stats = 0;
	arguments_g.outfile_ptr = stdout;

	//Get options
	while ((c = getopt(argc, argv, opt_string)) != -1) {
		switch (c) {
			case 'f':
				DBG("%s\n", "filter option enabled");
				process_filter(optarg);
				break;
			case 'i': //interface to listen on default to read from std in
				interface = optarg;
				break;
			case 'p': //port to capture on
				port = atoi(optarg); 
				break;
			case 'r': //input file
				arguments_g.has_infiles = 1;
				break;
			case 's':
				arguments_g.filter_stats = 1;
				break;
			case 'w': //output file
				arguments_g.outfile = optarg;
				break;
			case 'v':
				arguments_g.verbosity = atoi(optarg);
				break;
			case 'h': //intentional fall through
			case '?':
			default:
			  usage();
			  /* NOTREACHED */
		}
	}
	//update where argv and argc point
	//NOTE: Get opt moves files names, or invalid arguments to the end of the
	//argv array. After these lines, argv and argc will point to the filesnames
	//or invalide arguments
	argc -= optind;
	argv += optind;

	//check for output file
	if(arguments_g.outfile)
	{
		DBG("opening output file: %s\n", arguments_g.outfile);
		arguments_g.outfile_ptr = fopen(arguments_g.outfile, "a+");
		if(!arguments_g.outfile_ptr)
		{
			fprintf(stderr, "could not open output file");
			exit(1);
		}
	}

	DBG("%s\n", "input files");
	//check if input files
	if(arguments_g.has_infiles)
	{
		read_from_dcap_files(argc, argv);
		return 0;
	}

	//check for interface
	if(!interface)
	{
		//read from std in
		DBG("%s", "No interface to listen on, reading from stdin\n");
		//FUNCTION TO READ FROM STD IN
		read_from_stdin();
		return 0;
	}


	//process dnsflow data from networks -- default action
	int socketfd = get_dnsflow_socketfd(port, interface, arguments_g.verbosity);
	listen_for_dnsflow_pkt(socketfd, parse_dnsflow_packet);
	return 0;
}


//read a dcap file from std in
void read_from_stdin()
{
	DBG("%s\n", "reading from stdin");
	//prepare to read from stdin
	prepare_to_open_dcap_fileh(stdin, STDIN_FILE);
	arguments_g.outfile_ptr = stdout;

	struct dcap_header dcap_hdr;
	char * data;

	//read in file while we can
	unsigned int counter = 0;
	
	//get data while there's some in the file
	while((data = get_next_dnsflow_packet(&dcap_hdr)))
	{
		parse_dcap_packet(data, dcap_hdr.data_len, &dcap_hdr);
		//write_dcap_data(stdout, data, &dcap_hdr);
		counter += dcap_hdr.data_len + sizeof(struct dcap_header);
	}

	//close file
	close_dcap_file();
}



// -r option allows user to specify one or more files to read from command line
//
// This function will read from dcap files
void read_from_dcap_files(int argc, char * argv[])
{
	//get files on command line
	char * filename;

	DBG("%s\n", "Setting up to read");

	read_filenames_from_commandline(argv, argc);

	DBG("%s\n","trying to read files from command line");

	while((filename = get_next_filename()))
	{
		DBG("read filename %s\n", filename);
		process_dcap_file(filename);

	}
	DBG("%s\n", "done reading files");

}

void print_filter_warning()
{
	DBG("%s\n", "Note: filter is not yet fully implemented");
	DBG("%s\n", "Only options for aip (resolved ip) are currently implemented");
	DBG("%s\n", "try filter strings of the form: aip == 127.0.0.1");
}

/*

	gint compare func for aip, rip, cip


	a :
	a value.
	b :
	a value to compare with.
	Returns :
	negative value if a < b; zero if a = b; positive value if a > b.

 */
//NOTE: Only working for ipv4, not tested with ipv6
gint g_ip_addr_comp(gconstpointer a, gconstpointer b)
{
	DBG("%s\n", "in comparison funciton");
	ip_addr_entry_t * aa = (ip_addr_entry_t *) a;
	ip_addr_entry_t * bb = (ip_addr_entry_t *) b;

	DBG("compare types %d and %d\n", aa->type, bb->type);
	if(aa->type != bb->type)
	{
		if(aa->type < bb->type) 
		{
			return -1;
		} 
		else 
		{
			return 1;
		}
	}

	unsigned char * a_c = (unsigned char *) &aa->ip.addr;
	unsigned char * b_c = (unsigned char *) &bb->ip.addr;

	DBG("comparing a_c:%s and b_c:%s\n", inet_ntoa(*(struct in_addr *)a_c), inet_ntoa(*(struct in_addr *)b_c));

	int diff = 0;
	char max = 4;

	//compare while diff is greater than zero and max (process only 4 times)

	while(!diff && max)
	{
		DBG("diff: a:%hhu, b:%hhu\n", *a_c, *b_c);
		DBG("diff: %d\n", diff);
		DBG("max: %hhd\n", max);
		diff = (*a_c - *b_c);
		a_c++;
		b_c++;
		max--;
	}

	DBG("diff: a:%hhu, b:%hhu\n", *a_c, *b_c);
	DBG("returning diff = %d\n", diff);
	return diff;
}


//compares two domain names and matches the shorter length
gint g_dname_comp(gconstpointer a, gconstpointer b)
{
	const char * d1 = (const char *) a;
	const char * d2 = (const char *) b;
	int len;
	if(strlen(d1) < strlen(d2))len = strlen(d1); else len = strlen(d2);
	//DBG("strcmp, a: %s, and b: %s\n", d1, d2);

	return strncmp(a,b,len);
}

//reads in filter from file and sets up the necessary filter info
void process_filter(char * filter_str)
{
	arguments_g.filter = optarg; // "anything in quotes on command line is one string"
								 // as far as getopt is concered
	arguments_g.has_filter = 1;

	DBG("filter_str: %s\n", filter_str);

	//filter init
	filter_g.aip_tree_filter = 0;
	filter_g.cip_filter = 0;
	filter_g.rip_filter = 0;
	filter_g.dname_tree_filter = 0;
	filter_g.dlength = -1;
	filter_g.dlevel = -1;
	filter_g.dlength_operator = unknown_opt;
	
	//parse filter string
	parse_filter_string(filter_str);
}

//parses out filter string and addes entries to gtrees
void parse_filter_string(char * filter_str)
{
	enum Filter_keyword_e kw_e, unknown_kw_e;
	enum Filter_opt_e opt_e, unknown_opt_e;
	int offset;
	char * str;
	unknown_kw_e = unknown_kw;
	unknown_opt_e = unknown_opt;

	//get keyword
	kw_e = get_filter_keyword(filter_str, &offset);
	if(kw_e == unknown_kw_e)
	{
		filter_parse_fail("Bad keyword used");
	}
	filter_str += offset;

	//get operator
	opt_e = get_filter_opt(filter_str, &offset);
	if(opt_e == unknown_opt_e)
	{
		filter_parse_fail("Bad operator encountered");
	}
	filter_str += offset;
	
	//get next value as string, str is not on malloc'd, null if not parsed
	str = advance_past_whitespace(filter_str, &offset);
	if(offset == 0)
		filter_parse_fail("No rvalue in filter");

	update_filter(kw_e, opt_e, str);
}

//switches on keyword in filter
void update_filter(enum Filter_keyword_e kw_e, enum Filter_opt_e opt_e,
		char * str)
{
	switch(kw_e)
	{
		case aip:
			update_aip_filter(opt_e, str);
			break;
		case dname:
			update_dname_filter(opt_e, str);
			break;
		case dlength:
			update_length_filter(opt_e, str);
			break;
		default:
			filter_parse_fail("unsuported filter keyword");
	}
}

void get_ipstr(char * str, char * ip_buf)
{
	int num_read = 0;
	while((isdigit(*str) || *str == '.') && num_read < IP_STRLEN_MAX)
	{
		ip_buf[num_read] = str[num_read];
		num_read++;
	}

	ip_buf[num_read] = '\0';
}

void get_dname_str(char * str, char * buf)
{
	int num_read = 0;
	while((isalnum(*str) || *str == '.') && num_read < DNAME_MAX_LEN)
	{
		buf[num_read] = str[num_read];
		num_read++;
	}
	buf[num_read] = '\0';
}

//adds domain name to the domain name tree
void update_dname_filter(enum Filter_opt_e opt_e, char * str)
{
	//init
	filter_g.dname_tree_filter = g_tree_new((GCompareFunc)g_dname_comp);

	if(opt_e != equals && opt_e != not_equals)
		filter_parse_fail("Bad operator");

	char * dname_buf;
	char buf[DNAME_MAX_LEN + 1];
	dname_buf = buf;
	DBG("passed in %s to dname filter\n", str);
	get_dname_str(str, dname_buf);
	DBG("parsed dname string: %s\n", dname_buf);

	//take a domain name like www.plus.google.com and add the folowing names
	//to the gtree: www.plus.google.com, plus.google.com, google.com, com
	
	while(dname_buf)
	{
		//allocate space in gtree
		char * key = (char * ) malloc(strlen(dname_buf) + 1);
		strcpy(key, dname_buf);
		char * val = (char *) malloc(sizeof(char));
		switch(opt_e)
		{
			case equals:
				*val = 1;
				break;
			case not_equals:
				*val = 0;
				break;
			default:
				filter_parse_fail("Bad switch operator");
		}

		//add addr struct to gtree
		g_tree_insert(filter_g.dname_tree_filter, key, val);
		//test that the insertion worked
		if(g_tree_lookup(filter_g.dname_tree_filter, key))
			;//DBG("%s\n", "look up worked!!");
		else
			;//DBG("%s\n", "look up did not work... how sad!");
		dname_buf = strchr(dname_buf, '.');
		/*
		if(dname_buf)
			dname_buf += 1;
		else
			break;
			*/
		break;
	}

}

//sets the length to search for in a given level
void update_length_filter(enum Filter_opt_e opt_e, char * str)
{
	if(opt_e != equals && opt_e != less_than && opt_e != greater_than)
		filter_parse_fail("Bad operator");

	filter_g.dlength_operator = opt_e;

	if(strlen(str) > DLENGTH_LENGTH)
		filter_parse_fail("Bad argument");

	DBG("Passed in dlength str: %s\n", str);

	//get the length and level
	get_dlength_and_level(str, &filter_g.dlength, &filter_g.dlevel);

}

//get a string of the form " len,domain_level "
void get_dlength_and_level(char * str, int * dlength, int * dlevel)
{

	//advance to first character
	int offset;
	char * start = advance_past_whitespace(str, &offset);

	//get length string first
	*dlength = atoi(start);
	DBG("parsed dlength: %i\n", *dlength);

	//go to comma
	char * next = strchr(start, ',');
	next++;

	*dlevel = atoi(next);
	DBG("parsed dlevel: %i\n", *dlevel);

}

//adds the ip to the aip tree
void update_aip_filter(enum Filter_opt_e opt_e, char * str)
{
	//init
	filter_g.aip_tree_filter = g_tree_new((GCompareFunc)g_ip_addr_comp);

	if(opt_e != equals && opt_e != not_equals)
		filter_parse_fail("Bad operator");

	char ip_buf[IP_STRLEN_MAX + 1];
	DBG("Passed in ip str: %s\n", str);
	get_ipstr(str, ip_buf);

	//add str to Gtree for aip in equals
	//TODO, FORCES IPV4 ADDRS XXX
	ip_addr_entry_t * addr = (ip_addr_entry_t *) malloc(sizeof(ip_addr_entry_t));
	addr->type = ipv4; 
	if(!inet_pton(AF_INET, ip_buf, &(addr->ip.addr)))
	{
		fprintf(stderr, "%s\n",  str);
		filter_parse_fail("Couldn't parse ip");
	}

	//allocate space for value that will go in tree
	char * val = (char *) malloc(sizeof(char));
	switch(opt_e)
	{
		case equals:
			*val = 1;
			break;
		case not_equals:
			*val = 0;
			break;
		default:
			filter_parse_fail("Bad switch operator");
	}

	//add addr struct to gtree
	g_tree_insert(filter_g.aip_tree_filter, addr, val);
	//test that the insertion worked
	if(g_tree_lookup(filter_g.aip_tree_filter, addr))
		DBG("%s\n", "look up worked!!");
	else
		DBG("%s\n", "look up did not work... how sad!");

}

enum Filter_opt_e get_filter_opt(char * filter_str, int * offset)
{
	*offset = 0;
	enum Filter_opt_e opt_e = unknown_opt;
	char * start = advance_past_whitespace(filter_str, offset);

	DBG("parsed filter_opt start: %s\n", start);

	if(!start)
		filter_parse_fail("Error parsing filter");

	int num_read = 0;

	while(strchr(OPERATOR_STR, start[num_read]) && num_read < OPERATOR_MAX)
	{
		num_read++;
	}
	*offset += num_read;

	if(strncmp(start, EQUALS_OPERATOR, num_read) == 0 && num_read)
	{
		DBG("%s\n", "parsed equals operator");
		opt_e = equals;
	}
	else if(strncmp(start, NOT_EQUALS_OPERATOR, num_read) == 0 && num_read)
	{
		DBG("%s\n", "parsed not equals operator");
		opt_e = not_equals;
	}
	else if(strncmp(start, LESS_THAN_OPERATOR, num_read) == 0 && num_read)
	{
		DBG("%s\n", "parsed less than operator");
		opt_e = less_than;
	}
	else if(strncmp(start, GREATER_THAN_OPERATOR, num_read) == 0 && num_read)
	{
		DBG("%s\n", "parsed greater than operator");
		opt_e = greater_than;
	}

	return opt_e;
}

//Gets the filter keyword from the string if possible and advances 
//the filter str pointer
enum Filter_keyword_e get_filter_keyword(char * filter_str, int * offset)
{
	DBG("%s\n", "getting filter keyword");

	*offset = 0;
	enum Filter_keyword_e kw_e = unknown_kw;
	char * start = advance_past_whitespace(filter_str, offset);

	DBG("parsed keyword start: %s\n", start);

	if(!start)
		filter_parse_fail("Error parsing filter");

	int num_read = 0;
	while(isalpha(start[num_read]) && num_read < KEYWORD_MAX)
	{
		DBG("Read: %c \n", start[num_read]);
		num_read++;
	}
	DBG("%s\n", "");
	*offset += num_read;

	if(strncmp(start, AIP_KEYWORD, num_read) == 0 && num_read == AIP_LEN)
	{
		DBG("%s num read: %d\n", "parsed filter keyword aip", num_read);
		kw_e = aip;
	}
	else if(strncmp(start, DNAME_KEYWORD, num_read) == 0 && num_read == DNAME_LEN)
	{
		DBG("%s num read: %d\n", "parsed filter keyword dname", num_read);
		kw_e = dname;
	}
	else if(strncmp(start, DLENGTH_KEYWORD, num_read) == 0 && num_read == DLENGTH_LEN)
	{
		DBG("%s num read: %d\n", "parsed filter keyword dlength", num_read);
		kw_e = dlength;
	}
	else
	{
		DBG("no match for kw: %s, num read: %d\n", start, num_read);
	}

	return kw_e;
}

//reads past whitespace until a it reaches a null
char * advance_past_whitespace(char * str, int * offset)
{
	*offset = 0;
	while(isspace(*str))
	{
		str++;
		(*offset)++;
	}
	if(*str != '\0') //check that it is not null char
		return str;

	return 0;
}

void filter_parse_fail(char * msg)
{
	fprintf(stderr, "%s\n", "Failed to parse filter:");
	fprintf(stderr, "Message: %s\n", msg);
	exit(1);
}

//process dcap files by reading in a packet and applying a filter
int process_dcap_file(char * filename)
{
	if(!prepare_to_open_dcap_files(filename, 0)) //open for reading
	{
		perror("couldn't open file\n");
		return 0;
	}

	struct dcap_header dcap_hdr;
	char * data;

	//get data while there's some in the file
	while((data = get_next_dnsflow_packet(&dcap_hdr)))
	{
		parse_dcap_packet(data, dcap_hdr.data_len, &dcap_hdr);
	}

	//close file
	return (int) close_dcap_file();

}

//filters dnsflow data packets
//data_ptr points to the start of the data including the header
int filter_dnsflow_data_packet(struct dcap_header * hdr, char * data_ptr, unsigned int len)
{
	DBG("%s\n", "In filter dnsflow-data packet");
	//flags to use for filter returns
	//int ip_flag, domain_flag;
	struct dnsflow_hdr dnsflow_hdr;
	static struct dns_data_set data[DNSFLOW_MAX_DATA_SIZE];
	static struct dnsflow_set_hdr set_header[DNSFLOW_MAX_DATA_SIZE];
	unsigned int offset = 0;
	unsigned int i = 0;
	unsigned int pkt_size = 0;


	offset = get_header(&dnsflow_hdr, data_ptr);
	data_ptr += offset;

	offset = 0;
	//Whats in a data packet?
	//Data sets containing: set header, and data
	for(i = 0; i < dnsflow_hdr.sets_count; i++)
	{
		//parse the data set header
		offset = parse_set_hdr(data_ptr, &set_header[i]);
		data_ptr += offset;
		pkt_size = offset; //start new packet

		//Parse actual data set
		offset = parse_dns_data_set_pkt(data_ptr, &data[i], &set_header[i]);
		data_ptr += offset;
		pkt_size += offset;
		if(!offset)
		{
			warnx("no valid offset when parsing data set");
			return 0;
		}
		//check all the set header and data
		//return 1 if we passed the filter, else after all backs return 0
		if(filter_dnsflow_dataset(&data[i], &set_header[i]))
		{
			DBG("%s\n", "DATA set packet filter WILL BE PRINTED");
			DBG("Data set size: %u\n", pkt_size);
			//print out this data set
			write_dcap_set_to_file(hdr, data_ptr - pkt_size, pkt_size, arguments_g.outfile_ptr);
		}
	}
	return 0;
}

//filters dnsflow data set give the parsed data and header
//return 1 if passes filter and 0 other wise
/*
struct dns_data_set {
	char 			*names[DNSFLOW_MAX_PARSE];
	int32_t			name_lens[DNSFLOW_MAX_PARSE];
	int32_t			num_names;
	in_addr_t		ips[DNSFLOW_MAX_PARSE];
	int32_t			num_ips;
};

struct dnsflow_set_hdr {
	in_addr_t		client_ip;
	uint8_t			names_count;
	uint8_t			ips_count;
	uint16_t		names_len;
};


static struct Filter_t {
	GTree * aip_tree_filter;
	GTree * cip_filter;
	GTree * rip_filter;
	GTree * dname_tree_filter;
} filter_g;
   */
int filter_dnsflow_dataset(struct dns_data_set * data, struct dnsflow_set_hdr * set_hdr)
{
	DBG("filtering packet with %hhu names and %hhu ips\n", set_hdr->names_count, set_hdr->ips_count);
	DBG("FILTER RETURNING: %d\n", aip_filter(data, set_hdr) || dname_filter(data, set_hdr) || dlength_filter(data, set_hdr));

	return aip_filter(data, set_hdr) || dname_filter(data, set_hdr) || dlength_filter(data, set_hdr);
}

//This function checks for A record has a resolved name with a level
//with a certain length
//returns 1 if the packet passes the filter and zero otherwise
int dlength_filter(struct dns_data_set * data, struct dnsflow_set_hdr * set_hdr)
{
	DBG("checking for domain length %d at level %d\n", filter_g.dlength, filter_g.dlevel);
	assert(set_hdr && data);
	//default return 0
	if(set_hdr->ips_count <= 0 || filter_g.dlength_operator == unknown_opt)
	{
		DBG("%s\n", "returning 0");
		DBG("set_hdr->ips_count: %i, filter opt %i\n", set_hdr->ips_count, filter_g.dlength_operator);
		return 0;
	}

	//check if any name's have levels that match
	char * dname;
	dname = 0;
	int i;
	for(i = 0; i < set_hdr->names_count; i++)
	{
		DBG("index is %i, set_hdr->ips_count %i\n", i, set_hdr->ips_count);
		//dbg("\t checking for ip %s\n", inet_ntoa(*(struct in_addr *)&data->ips[i]));
		dname = data->names[i];
		//check domain length
		if(valid_domain_level_length(dname, filter_g.dlength, filter_g.dlevel, filter_g.dlength_operator))
			return 1;
	}
	return 0;
}

//this function takes a domain name of the format xxx.xxx.xx. and checks
//if the domain length at a certain level matches an operator, where the 
//top level domain is indexed at 1
//
//Needs to check operator for ==, <= or >=
int valid_domain_level_length(char * dname, int dlength, int dlevel, enum Filter_opt_e opt)
{
	DBG("passed dname: %s|\n", dname);
	//sanity checks
	assert(dname);
	if(dlength <= 0 || opt == unknown_opt || dlevel <= 0)
		return 0;

	//find number of levels
	int levels = count_levels(dname, (int)strlen(dname));
	DBG("number of levels in string %i\n", levels);

	if(dlevel > levels)
	{
		DBG("dlevel: %i greater than levels %i\n", dlevel, levels);
		return 0;
	}

	int level_length = get_level_length(dlevel, levels, dname);

	DBG("Parsed level length: %i, checking for length: %i\n", level_length, dlength);

	switch(opt)
	{
		case equals:
			return dlength == level_length;
			break;
		case less_than:
			return dlength < level_length;
			break;
		case greater_than:
			return dlength > level_length;
			break;
		default:
			return 0;
	}
}

//counts number of levels in domain name
// expects string of type xxx.xxx.xxx.
int count_levels(char * dname, int length)
{
	DBG("dname: %s, length: %i\n", dname, length);
	int levels = 0;
	assert(dname);
	while((dname = strchr(dname, '.')))
	{
		DBG("dname %s\n", dname);
		dname++;
		levels++;
	}

	return levels;
}

//This function takes in the level we want the length of (indexed at 1)
//the number of levels and the domain name, returns the length of the level
int get_level_length(int level, int num_levels, char * dname)
{
	int level_index = num_levels - level;
	char * level_ptr = dname;
	while(level_index > 0)
	{
		level_ptr = strchr(level_ptr, '.') + 1;
		level_index--;
	}

	char * level_end = strchr(level_ptr, '.');
	assert(level_end); //sanity check, shoudl not be null

	return (level_end - level_ptr);
}


//This function checks for A record ip's that have been resolved
//returns 1 if the packet passes the filter and zero otherwise
int aip_filter(struct dns_data_set * data, struct dnsflow_set_hdr * set_hdr)
{
	assert(set_hdr && data);
	//default return 0
	if(set_hdr->ips_count <= 0 || !filter_g.aip_tree_filter)
		return 0;

	ip_addr_entry_t  addr;
	gpointer key = 0;
	//check if ip's exist in our tree
	int i;
	for(i = 0; i < set_hdr->ips_count; i++)
	{
		//dbg("\t checking for ip %s\n", inet_ntoa(*(struct in_addr *)&data->ips[i]));
		addr.type = ipv4;
		addr.ip.addr = *((struct in_addr *) &data->ips[i]);
		key = g_tree_lookup(filter_g.aip_tree_filter,(gconstpointer) &addr);
		//doesn't check for equality of keys
		if(key)
			return 1;
	}
	return 0;
}

//This function checks for domain names being resolved and returns 1 if there 
//is a match and 0 otherwise
int dname_filter(struct dns_data_set * data, struct dnsflow_set_hdr * set_hdr)
{
	assert(set_hdr && data);
	//default return 0
	if(set_hdr->names_count <= 0 || !filter_g.dname_tree_filter)
		return 0;

	//check for dname from data in tree
	gpointer key = 0;
	//check if ip's exist in our tree
	int i;
	char * next;
	char buffer[DNAME_MAX_LEN + 1];
	DBG("Dname count is: %d\n", set_hdr->names_count);
	for(i = 0; i < set_hdr->names_count; i++)
	{
		strcpy(buffer, data->names[i]);
		DBG("copied buffer for lookup: %s\n", buffer);
		next = buffer;
		while(strlen(next) > 1)
		{
			//DBG("\t checking for name:%s\n", next);
			key = g_tree_lookup(filter_g.dname_tree_filter,(gconstpointer) next);
			//doesn't check for equality of keys
			if(key)
			{
				DBG("%s", "FILTER FOUND DNAME!!!\n");
				return 1;
			}
			//try next level
			next = strchr(next, '.');
			if(next) next += 1;
		}
	}
	return 0;
}


//filters dnflow stat packets
//returns 0 if it fails filter and 1 if passes
int filter_dnsflow_stats_packet(char * data, unsigned int len)
{
	DBG("%s\n", "in filter dnsflow-stats packet");
	//alway capture stats for now
	return arguments_g.filter_stats;
}

int filter_dnsflow_packet(struct dcap_header * hdr, char * dnsflow_data, unsigned int len)
{
	//figure out what kind of packet it is
	int packet_type = parse_packet_type(dnsflow_data, len);
	DBG("\tpacket type: %u\n", packet_type);
	if(packet_type < 0)
	{
		errx(1, "invlid packet type");
	}
	if(packet_type == DNSFLOW_TYPE_STATS)
	{
		DBG("%s\n", "filtering stats packet");
		return filter_dnsflow_stats_packet(dnsflow_data, len);
	}
	else if(packet_type == DNSFLOW_TYPE_DATA)
	{
		DBG("%s\n", "filtering data packet");
		return filter_dnsflow_data_packet(hdr, dnsflow_data, len);
	}
	else
	{
		filter_parse_fail("bad packet type - ignoring packet");
	}

	DBG("%s\n", "failed filter by default");
	return 0;
	
}

static char ** _read_argv;
static int _read_argc;

int read_filenames_from_commandline(char * argv[], int argc)
{
	if(argc < 0)
	{
		fprintf(stderr, "No files passed in\n");
		return 1;
	}
	_read_argv = argv;
	_read_argc = argc;
	return 0;
}

//get next filename on command line
char * get_next_filename()
{
	static int file_count = 0;
	static int index = 0;

	while(index < _read_argc)
	{
		file_count++;
		return _read_argv[index++];
	}
	return 0;
}


//Process a pcap file capture for dnsflow packets
int process_from_pcapfiles(char ** pcapfiles, int length)
{
	unsigned int pkt_counter = 0;   // packet counter 
	unsigned int byte_counter = 0; //total bytes seen in entire trace 
	clock_t start = clock();
	unsigned int file_counter = 0;
	int index = 0;
	

	//for each file try to process
	while(index < length)
	{
		if(pcapfiles[index][0] == '-')
		{
			warnx("invalide filename or option around \"-\"");
			break;
		}
		//gets(temp); //used to pause input between files for debugging
		process_dcap_filename(pcapfiles[index], &pkt_counter, &byte_counter);
		file_counter++;
		index++;
	}

	print_pcap_stats(pkt_counter, byte_counter, file_counter, start);

	return 0;
}

// TODO still needs modification from pcap -> dcap process
int process_dcap_filename(char * pcapfile, unsigned int *pkt_counter_p,
	   unsigned int *byte_counter_p)
{
	int offset = UDP_HEADER_SIZE + IP_HEADER_SIZE + ETH_HEADER_SIZE;
	int dnsflow_size;
	struct pcap_pkthdr header; //header pcap gives
	const unsigned char *packet; //packet given
	char * pkt_ptr, *dnsflow_ptr;
	

	char * filter = 0;

	pcap_t * handle = 0;
	handle = get_pcapfile_handle(pcapfile, filter);

	if(!handle)
	{
		err(1, "bad pcap file handle");
		exit(1);
	}
	sleep(1);

	//get packets
	while((packet = pcap_next(handle, &header))){
		pkt_ptr = (char*)packet; //point to packet data
		dnsflow_ptr = pkt_ptr + offset;
		dnsflow_size = header.len - offset;

		//error check for bad packets
		if(dnsflow_size < DNSFLOW_HEADER_SIZE || dnsflow_size > DNSFLOW_PKT_MAX_SIZE)
		{
			warnx("Bad dnsflow packet!");
			continue;
		}

		//TODO -- test
		parse_dcap_packet(dnsflow_ptr, dnsflow_size, 0);
		*pkt_counter_p += 1;
		*byte_counter_p += header.len;
	}
	pcap_close(handle);
	return 0;
}

int parse_dnsflow_packet(char * data, unsigned int total_data)
{
	//create header and call parse_dcap_packet
	struct dcap_header header;
	header.data_len = total_data;
	header.timestamp = get_timestamp(NULL);
	return parse_dcap_packet(data, total_data, &header);
}

//gets a packet from the network and prints the binary to standard out after
//applying the filter
int parse_dcap_packet(char * data, unsigned int total_data, struct dcap_header * hdr)
{
	DBG("parsing packet of len %u\n", total_data);
	int print_packet;

	//Parse dnsflow packet
	//check if stats or data
	print_packet = 0;
	print_packet = filter_dnsflow_packet(hdr, data, total_data);
	DBG("\tfilter returned: %d\n", print_packet);
	
	//print out packet binary if needed
	if(print_packet)
	{
		if(arguments_g.outfile_ptr)
		{
			//print to file
			DBG("%s\n", "writing data to filehandle");
			write_dcap_data(arguments_g.outfile_ptr, data, hdr);
		}
		else
		{
			DBG("%s\n", "writing data to stdout");
			//print to std out
			write_dcap_data(arguments_g.outfile_ptr, data, hdr);
		}
	}

	return 0;
}




void usage(void)
{
	fprintf(stderr, "\nUsage: %s [-f <filter string>] [-i interface] [-h] "
			"[-p port] [-r filename(s)]\n", program_name);
	fprintf(stderr, "\t[-f]: filter dcap filse based on filter string\n");
	fprintf(stderr, "\t\t aip == 10.10.0.1 //filter on resolved ip\n");
	fprintf(stderr, "\t\t rip == 10.10.0.1/24 //filter on resolver ip\n");
	fprintf(stderr, "\t\t dname == google.com //filter on domain name\n");
	fprintf(stderr, "\t\t dlength == 4,1\n");
	fprintf(stderr, "\t\t - filter on domain name length, format: (opt) name_len, domain_level.\n");
	fprintf(stderr, "\t\t   Valid operators, ==, <, >\n");
	fprintf(stderr, "\t\t   Top level domain indexed at 1\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "\t\t supported operators: ==, !=, and, or\n");
	fprintf(stderr, "\t[-i]: interface to read packets on\n");
	fprintf(stderr, "\t[-h]: print this help message\n");
	fprintf(stderr, "\t[-p]: port number\n");
	fprintf(stderr, "\t[-r]: dcap file(s) to read from to, defaults to stdin\n");
	fprintf(stderr, "\t[-w]: dcap file to write to, defaults to stdout\n");
	fprintf(stderr, "\t[-v]: version\n\n");
	exit(1);
}
