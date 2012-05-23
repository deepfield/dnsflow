/*
 * dnsflow-todb.c
 *
 * contact: jkrez@merit.edu
 *          nmentley@merit.edu
 *  
 *  This program listens to dnsflow messages and stores it into postgresql
 *
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>
#include <glib.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <libpq-fe.h>

#include "dnsflow-common.h"
#include "dnsflow-print.h"
#include "dnsflow-todb.h"

#define BUFSIZE 2048
#define DNSFLOW_PORT 5300
#define DNSFLOW_NAME_FORMAT %.255s
#define DNSFLOW_IP_FORMAT %.15s
#define TIMESTAMP_MAX_LEN 20
#define DNSFLOW_PRINT_VERSION 1
#define MAX_VERBOSITY 2
#define UDP_HEADER_SIZE 8
#define IP_HEADER_SIZE 20
#define ETH_HEADER_SIZE 14
#define PCAP_STDIN_FILENAME "-"
#define WHITESPACE_DELIMS " \n\t\v\f\r"

//#define DO_DEBUG

#ifdef DO_DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#define DBG(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			__LINE__, __func__, __VA_ARGS__); } while (0)

void get_time(void);
void print_dns_data_set_packet(struct dns_data_set *pkt, struct dnsflow_set_hdr *set_header);
void print_set_hdr_packet(struct dnsflow_set_hdr *set_header); 
void print_data_set(struct dnsflow_set_hdr *header, struct dns_data_set * data);
void print_stats_packet(struct dnsflow_stats_pkt *stats);
void print_default_data(struct dnsflow_hdr * header, 
						struct dns_data_set *data, 
						struct dnsflow_set_hdr *data_header,
						uint32_t size);
void print_default_stats(struct dnsflow_hdr * header, 
		struct dnsflow_stats_pkt * dnsflow_stats);


//Globals ----------------------------------------
static char * program_name;

//structure to hold options passed into program
static struct GlobalArgs_t
{
	int32_t verbosity;
	int32_t filter_mode;
	int32_t stats;
	int32_t files;
	int32_t dcap;
	char * dcap_file;
	int32_t write_file_timestamp;
} arguments_g;

static struct tm32 * timeparts_g;
static time_t raw_time_g;
static char timestamp_g[TIMESTAMP_MAX_LEN];

static char filter[] = "udp and dst port 5300";
// -----------------------------------------------

char ** ARGV;
int ARGC;

PGconn* conn;

int32_t dump_to_db(struct dnsflow_hdr* header,
		struct dnsflow_stats_pkt* stats, 
		struct dnsflow_set_hdr* set_hdr,
		struct dns_data_set* data,
		unsigned long long timestamp) {
	char sql[256];
	PGresult* res;
	struct in_addr temp;
	int i, j;

	PGconn* conn = PQconnectdb("user = 'postgres' dbname = 'dnsflow2' hostaddr = '127.0.0.1'");

	if (PQstatus(conn) != CONNECTION_OK){
		printf("Connection to database failed\n");
		exit(1);
	}

	res = PQexec(conn, "BEGIN");
	PQclear(res);

//	printf("\nBEGIN;\n");

	if(timestamp != 0)
		sprintf(sql, "INSERT INTO dcap (timestamp) VALUES (%llu);", timestamp);
	else
		sprintf(sql, "INSERT INTO dcap (timestamp) VALUES (NOW());");
	res = PQexec(conn, sql);
	PQclear(res);
//	printf("%s\n", sql);

	sprintf(sql, "INSERT INTO hdr (version, sets_count, flags, sequence_number, id_dcap) VALUES (%d, %d, %d, %d, currval('dcap_id'));",
			header->version, header->sets_count, header->flags, header->sequence_number);
	res = PQexec(conn, sql);
	PQclear(res);
//	printf("%s\n", sql);

	if(header->flags){ //stats packet
		sprintf(sql, "INSERT INTO stats_pkt (pkts_captured, pkts_received, pkts_dropped, pkts_ifdropped, id_hdr) VALUES (%u, %u, %u, %u, currval('hdr_id'));",
				stats->pkts_captured, stats->pkts_received, stats->pkts_dropped, stats->pkts_ifdropped);
		res = PQexec(conn, sql);
		PQclear(res);
//		printf("%s\n", sql);
	}else{ //data packet
		for(i = 0; i < header->sets_count; i++){
			temp.s_addr = set_hdr[i].client_ip;
			sprintf(sql, "INSERT INTO set_hdr (client_ip, names_count, ips_count, num_names, num_ips, id_hdr) VALUES ('%s', %d, %d, %d, %d, currval('hdr_id'));",
					inet_ntoa(temp), set_hdr[i].names_count, set_hdr[i].ips_count, data[i].num_names, data[i].num_ips);
			res = PQexec(conn, sql);
			PQclear(res);
//			printf("%s\n", sql);

			for(j = 0; j < set_hdr->ips_count; j++){
				temp.s_addr = data[i].ips[j];
				sprintf(sql, "INSERT INTO data_ips (ip, id_set_hdr) VALUES ('%s', currval('set_hdr_id'));",
						inet_ntoa(temp));
				res = PQexec(conn, sql);
				PQclear(res);
//				printf("%s\n", sql);
			}

			for(j = 0; j < set_hdr->names_count; j++){
				if(data[i].names[j][0] != '\0')
					sprintf(sql, "INSERT INTO data_names (name, name_len, id_set_hdr) VALUES ('%s', %d, currval('set_hdr_id'));",
							data[i].names[j], data[i].name_lens[j]);
				else
					sprintf(sql, "ROLLBACK;");
				res = PQexec(conn, sql);
				PQclear(res);
//				printf("%s\n", sql);
			}
			break;
		}
	}

	res = PQexec(conn, "END");
	PQclear(res);
//	printf("END;\n");

	PQfinish(conn);
	return 0;
}

int32_t parse_dnsflow_packet(char * data, uint32_t total_data) {
	uint32_t data_size, header_size;
	struct dnsflow_hdr header;
	char * data_ptr;
	struct dnsflow_stats_pkt dnsflow_stats;

	//parse header
	header_size = get_header(&header, data);
	data_size = total_data - header_size;
	data_ptr = (char*)data + header_size;
	
	//Allocate size of data and set header
	static struct dns_data_set dnsflow_data[DNSFLOW_MAX_DATA_SIZE];
	static struct dnsflow_set_hdr dnsflow_data_set_hdr[DNSFLOW_MAX_DATA_SIZE];

	//Get rest of packet
	if(header.flags) //DNSFLOW STAT PACKET
	{
		parse_stats_packet(data_ptr, &dnsflow_stats);
	//	if(arguments_g.stats)
	//		print_default_stats(&header, &dnsflow_stats);
	}
	else //DNSFLOW DATA PACKET
	{
		parse_data_packet(&header, data_ptr, dnsflow_data, dnsflow_data_set_hdr, data_size);
		//print_default_data(&header, dnsflow_data, dnsflow_data_set_hdr, data_size);
	}

	return dump_to_db(&header, &dnsflow_stats, dnsflow_data_set_hdr, dnsflow_data, 0);
	
	return 0;
}

int32_t process_pcap_filename(char * pcapfile, uint32_t *pkt_counter_p,
	   uint32_t *byte_counter_p)
{
	int32_t offset = UDP_HEADER_SIZE + IP_HEADER_SIZE + ETH_HEADER_SIZE;
	uint32_t dnsflow_size;
	struct pcap_pkthdr header; //header pcap gives
	const unsigned char *packet; //packet given
	char * pkt_ptr, *dnsflow_ptr;
	pcap_t * handle = get_pcapfile_handle(pcapfile, filter);

	if(!handle)
	{
		err(1, "bad pcap file handl");
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

		parse_dnsflow_packet(dnsflow_ptr, dnsflow_size);
		*pkt_counter_p += 1;
		*byte_counter_p += header.len;
	}
	pcap_close(handle);
	return 0;
}


int32_t read_from_stdin()
{
	uint32_t pkts_counter = 0;
	uint32_t bytes_counter = 0;
	clock_t start = clock();
	int32_t files = 1;
	//assume that we are reading a pcap file from stdin
	int32_t ret = process_pcap_filename(PCAP_STDIN_FILENAME, &pkts_counter,
			&bytes_counter);
	if(ret) //check for errors
		files = 0;
	print_pcap_stats(pkts_counter, bytes_counter, files, start);
	return ret;
}

void print_argv(char ** argv, int argc)
{
	int32_t i = 0;
	printf("print argv:\n");
	for(i = 0; i < argc; i++)
		printf("%s\n", argv[i]);
}

//Process a pcap file capture for dnsflow packets
int32_t process_from_pcapfiles(char ** pcapfiles, int32_t length)
{
	uint32_t pkt_counter = 0;   // packet counter 
	uint32_t byte_counter = 0; //total bytes seen in entire trace 
	clock_t start = clock();
	uint32_t file_counter = 0;
	int32_t index = 0;
	
	//for each file try to process
	while(index < length)
	{
		if(pcapfiles[index][0] == '-')
		{
			warnx("invalide filename or option around \"-\"");
			break;
		}
		//gets(temp); //used to pause input between files for debugging
		process_pcap_filename(pcapfiles[index], &pkt_counter, &byte_counter);
		file_counter++;
		index++;
	}

	print_pcap_stats(pkt_counter, byte_counter, file_counter, start);

	return 0;
}


//dcap packet has additional timestamp filed that needs to be printed
int32_t print_dcap_packet(char * data, struct dcap_header * header)
{
	//printing out timestamp from file
	arguments_g.write_file_timestamp = 1;

	//parse timestamp
	if(!get_tm_timestamp_string(&header->timestamp, timestamp_g, TIMESTAMP_MAX_LEN))
	{
		errx(1, "timestamp broken");
		return -1;
	}

	parse_dnsflow_packet(data, header->data_len);

	return 0;
}

void print_header(struct dnsflow_hdr * header)
{
	//verbose
	if(arguments_g.verbosity == 3)
	{
		printf("\n==================================\n");
		printf("======    Dnsflow header    ======\n");
		printf("==================================\n");
		printf("version:         %u\n", header->version);
		printf("sets_count:      %u\n", header->sets_count);
		printf("flags:           %u\n", header->flags);
		printf("sequence number: %u\n", header->sequence_number);
		printf("==================================\n");
	}
	else if(arguments_g.verbosity == 4) //shouldn't print
	{ //note get time already called
		if(arguments_g.write_file_timestamp)
			printf("%.20s ", timestamp_g);
		printf("DNS HDR: version %u, sets_count %u, flags %u, sequence_number %u\n",
			header->version, header->sets_count, header->flags,
			header->sequence_number);
	}

}

void print_default_data(struct dnsflow_hdr * header, 
						struct dns_data_set *data, 
						struct dnsflow_set_hdr *data_header,
						uint32_t size)
{
	uint8_t i = 0;
	if(!arguments_g.write_file_timestamp)
		get_time();
	if(arguments_g.verbosity != 2)
	{
		print_header(header);
		for(i = 0; i < header->sets_count; i++)
		{
			print_data_set(&data_header[i], &data[i]);
		}
	}
	else if(arguments_g.verbosity == 2)
	{
		if(!arguments_g.write_file_timestamp)
			printf("%.20s ", timestamp_g);
		printf("DATA %u bytes from %s, %d data sets\n", size,
			inet_ntoa(*((struct in_addr *)(&(data_header[0].client_ip)))),
			header->sets_count);
	}



}

void print_default_stats(struct dnsflow_hdr * header, 
		struct dnsflow_stats_pkt * dnsflow_stats)
{
	if(!arguments_g.write_file_timestamp)
		get_time();
	print_header(header);
	print_stats_packet(dnsflow_stats);
}


void print_stats_packet(struct dnsflow_stats_pkt *stats)
{
	if(arguments_g.stats && arguments_g.verbosity == 3)
	{
		printf("\n==================================\n");
		printf("======     Dnsflow Stats    ======\n");
		printf("==================================\n");
		printf("pkts_captured     %u\n", stats->pkts_captured);
		printf("pkts_received     %u\n", stats->pkts_received);
		printf("pkts_dropped      %u\n", stats->pkts_dropped);
		printf("pkts_ifdropped    %u\n", stats->pkts_ifdropped);
		printf("==================================\n");
	}
	else if(arguments_g.stats)
	{
		if(arguments_g.write_file_timestamp)
			printf("%.20s ", timestamp_g);
		printf("STATS %d captured, %d received, %d dropped, %d ifdropped\n",
				stats->pkts_captured, 
				stats->pkts_received, stats->pkts_dropped,
				stats->pkts_ifdropped);
	}
	
}

void print_data_set(struct dnsflow_set_hdr *header, struct dns_data_set * data)
{
	print_set_hdr_packet(header);
	print_dns_data_set_packet(data, header);
}

void print_set_hdr_packet(struct dnsflow_set_hdr *set_header) 
{
	if(arguments_g.verbosity == 3)
	{
		printf("\n==================================\n");
		printf("====     Dnsflow Set Header   ====\n");
		printf("==================================\n");
		/*
		 * NOTE: can't cast from (in_addr_t) to (struct in_addr) 
		 * but can cast from (in_addr_t*) to (struct in_addr *) then dereference
		 */
		in_addr_t * tmp = &set_header->client_ip;
		struct in_addr in = *((struct in_addr *) tmp);
		printf("client_ip       %.15s\n", inet_ntoa(in));
		printf("names_count     %u\n", set_header->names_count);
		printf("ips_count       %u\n", set_header->ips_count);
		printf("names_len       %u\n", set_header->names_len);
		printf("==================================\n");
	}
	else if(arguments_g.verbosity == 1)
	{
		if(!arguments_g.write_file_timestamp)
			get_time();
		in_addr_t * tmp = &set_header->client_ip;
		struct in_addr in = *((struct in_addr *) tmp);
		if(arguments_g.write_file_timestamp)
			printf("%.20s ", timestamp_g);
		printf("SET HDR: client_ip %s, names_count %u, ips_count %u,"
			   " names_len %u ", inet_ntoa(in), 
			   set_header->names_count, set_header->ips_count, 
			   set_header->names_len);
	}
}

void print_dns_data_set_packet(struct dns_data_set *pkt, struct dnsflow_set_hdr *set_header)
{
	uint32_t i = 0;
	if(arguments_g.verbosity == 3)
	{
		printf("\n==================================\n");
		printf("===    Dnsflow dns data set    ===\n");
		printf("==================================\n");
		printf("num_names:  %u\n", pkt->num_names);
		printf("num_ips:    %u\n", pkt->num_ips);

		if(pkt->num_names > DNSFLOW_NAMES_COUNT_MAX || pkt->num_names < 0 || 
				pkt->num_ips > DNSFLOW_IPS_COUNT_MAX || pkt->num_ips < 0)
		{
			warnx("Error parsing ips/name count\nAre you using ntohs/ntohl?");
		}

		//Print names
		printf("\n --- host names ---\n");
		for(i = 0; i < set_header->names_count; i++)
		{
			printf("Host name:  %.255s\n", pkt->names[i]);
		}

		//print ips
		printf("\n --- ips ---\n");
		char *ip;
		for(i = 0; i < set_header->ips_count; i++)
		{
			ip = inet_ntoa(*((struct in_addr*)(pkt->ips + i)));
			printf("Ip:         %.15s\n", ip);
		}
		printf("==================================\n");
	}
	if(arguments_g.verbosity == 0 || arguments_g.verbosity == 1)
	{
		if(arguments_g.write_file_timestamp)
			printf("%.20s ", timestamp_g);
		else
			get_time();
		printf("DATA: num_names: %u, num_ips: %u, ", pkt->num_names, pkt->num_ips);

		//Print names
		printf("host names: ");
		for(i = 0; i < set_header->names_count; i++)
		{
			printf("%.255s, ", pkt->names[i]);
		}

		//print ips
		printf("ips: ");
		char *ip;
		for(i = 0; i < set_header->ips_count; i++)
		{
			ip = inet_ntoa(*((struct in_addr*)(pkt->ips + i)));
			if( i + 1 != set_header->ips_count )
				printf("%.15s, ", ip);
			else
				printf("%.15s\n", ip);
		}
	}
}

void get_time(void)
{
	time(&raw_time_g);
	timeparts_g = (struct tm32 *) localtime(&raw_time_g);
	//print into buffer
	strftime (timestamp_g, 20, "%X", (struct tm *) timeparts_g);
}

void process_globals(void)
{
	if(arguments_g.verbosity)
		printf("Verbose output level %d of %d enabled\n", arguments_g.verbosity,
			   MAX_VERBOSITY);
	else
		;//printf("Run with -p<number> to enable verbose output\n");
}

void usage(void)
{
	fprintf(stderr, "\nUsage: %s [-h] [-p<number 0:2>] [-P] [-r pcap_filename]"
			" [-R dcap_filenam] [-v]\n", program_name);
	fprintf(stderr, "\t[-h]: print this help message\n");
	fprintf(stderr, "\t[-p<number>]: verbosity level\n");
	fprintf(stderr, "\t[-P]: pretty print\n");
	fprintf(stderr, "\t[-r <list of files>]: read in dnsflow data from pcap"
		" file\n");

	fprintf(stderr, "\t[-R]: read in and print out from default filename, use '-' to read from stdin\n");
	fprintf(stderr, "\t[-s]: print stats packet\n");
	fprintf(stderr, "\t[-v]: version\n\n");

	exit(1);
}

//read in dcap file and print32_t out data
int32_t read_dcap_filestream(FILE * handle)
{
	DBG("%s\n", "reading in from file handle");

	struct dcap_header header;
	char * data;

	//read in file while we can
	uint32_t byte_counter = 0;
	
	//read header
	read_dcap_header(&header, handle);

	DBG("dnsflow header len %u\n", (unsigned int)sizeof(struct dnsflow_hdr));
	DBG("dcap header len %u\n", (unsigned int)sizeof(struct dcap_header));
	DBG("first dcap header len %u\n", header.data_len);

	//read file while datalen
	while(header.data_len)
	{
		//add to counter
		byte_counter += sizeof(struct dcap_header);

		//get data packet
		data = get_next_dnsflow_packet_from_file(&header, handle);

		//write print to std out
		print_dcap_packet(data, &header);

		//read next header
		read_dcap_header(&header, handle);

		byte_counter += header.data_len;
	}

	//close file
	return byte_counter;
}

//read in dcap file and print out data
int32_t print_dcap_file(char * filename)
{
	DBG("reading in from %s\n", filename);

	if(!prepare_to_open_dcap_files(filename, 0)) //open for reading
	{
		perror("couldn't open file\n");
		return 0;
	}

	struct dcap_header header;
	char * data;
	//read in file while we can
	uint32_t byte_counter = 0;
	
	while((data = get_next_dnsflow_packet(&header)))
	{
		//write print to std out
		print_dcap_packet(data, &header);

		byte_counter += header.data_len + sizeof(struct dcap_header);
	}

	//close file
	return (int) close_dcap_file();
}

int main(int argc, char *argv[])
{
	int c;
	int32_t verb_lvl;
	ARGV = argv;
	ARGC = argc;

	program_name = argv[0];
	char opt_string[] = "hp:PrR:sv?";

	//initalize global arguments
	arguments_g.verbosity = 0;
	arguments_g.filter_mode = 0;
	arguments_g.stats = 0;
	arguments_g.files = 0;
	arguments_g.dcap = 0;
	arguments_g.dcap_file = 0;
	arguments_g.write_file_timestamp = 0;

	DBG("dnsflow header len %u\n", (unsigned int)sizeof(struct dnsflow_hdr));
	DBG("dcap header len %u\n", (unsigned int)sizeof(struct dcap_header));
	DBG("dnsflow_set_hdr %u\n", (unsigned int) sizeof(struct dnsflow_set_hdr));
	DBG("struct tm32 %u\n", (unsigned int) sizeof(struct tm32));

	//Get options
	while ((c = getopt(argc, argv, opt_string)) != -1) {
		switch (c) {
			case 'p': //verbosity level	
				verb_lvl = atoi(optarg);
				arguments_g.verbosity = verb_lvl;
				if(verb_lvl > 2 || verb_lvl < 0)
				{
					printf("Using default verbosity\n");
					arguments_g.verbosity = 0;
				}
				if(arguments_g.verbosity == 2)
					arguments_g.stats = 1;
				break;
			case 'P': //pretty print
				arguments_g.verbosity = 3;
				break;
			case 'r': //reading from pcap file	NOTE: could be flag too
				arguments_g.files = 1;
				arguments_g.filter_mode = 1;
				break;	
			case 'R': //read from dcap file -- no glob expansion supported
				arguments_g.dcap = 1;
				arguments_g.dcap_file = optarg;
				break;
			case 's' :
				arguments_g.stats = 1;
				break;
			case 'v':
				//print version
				printf("Dnsflow-print version %d\n", DNSFLOW_PRINT_VERSION);
				exit(1);
				break;
			case 'h': //intentional fall through
			case '?':
			case '-':
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

	process_globals();
	if(arguments_g.files)
	{
		DBG("%s\n", "checking for pcap files");
		//check if std in
		char * ptr = strtok(argv[0], WHITESPACE_DELIMS);
		if(*ptr == '-')
		{
			return read_from_stdin();
		}
		int32_t ret = process_from_pcapfiles(argv, argc);
		return ret;
	}
	else if(arguments_g.dcap)
	{
		//read from dcap file given by -R flag
		//check if stdin
		DBG("%s\n", "checking for dcap files");
		if(*arguments_g.dcap_file == '-')
		{
			DBG("%s\n", "hi");
			return read_dcap_filestream(stdin);
		}
		DBG("%s\n", "h");
		print_dcap_file(arguments_g.dcap_file);
		return 0;
	}
	
	//process dnsflow data from networks -- default action
	int socketfd = get_dnsflow_socketfd(DNSFLOW_PORT, 0, arguments_g.verbosity);
	listen_for_dnsflow_pkt(socketfd, parse_dnsflow_packet);

	return 0;
}

