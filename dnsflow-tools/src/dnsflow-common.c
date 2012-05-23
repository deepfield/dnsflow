/*
 * dnsflow-common.c
 *
 * contact: jkrez@merit.edu
 *  
 *  This program listens to dnsflow messages and prints out the packet 
 *  information
 *
 */
 
 /* kroell changes - added write_dnsflow_pkt_to_nmsg_file
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
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <time.h>
#include <sys/types.h>
#include "dnsflow-common.h"

//for nmsg output
#include "nmsg.h"
#include <nmsg/isc/defs.h>
#include <assert.h>
#define nmsf(a,b,c,d,e) do { \
	nmsg_res _res; \
	_res = nmsg_message_set_field(a,b,c,(uint8_t *) d,e); \
	assert(_res == nmsg_res_success); \
} while (0)



#define MAX_FILENAME_LEN 255
#define DCAP_HEADER_SIZE 25
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
#define DNSFLOW_FILE_EXT "dcap"


//#define DO_DEBUG

#ifdef DO_DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#define DBG(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			__LINE__, __func__, __VA_ARGS__); } while (0)

void print_pcap_stats(uint32_t pkt_counter, uint32_t byte_counter, 
		uint32_t file_counter, clock_t start)
{
	if(file_counter == 1)
		DBG("\nProcessed %d packets and %u bytes from %u files in %.2f"
				" seconds\n", pkt_counter, byte_counter, file_counter,
				((double)clock() - start) / CLOCKS_PER_SEC);
	else 
		DBG("\nProcessed %d packets and %u bytes from %u file in %.2f"
				" seconds\n", pkt_counter, byte_counter, file_counter,
				((double)clock() - start) / CLOCKS_PER_SEC);
}

pcap_t * get_pcapfile_handle(char * pcapfile, char * filter)
{
	//open file
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	handle = pcap_open_offline(pcapfile, errbuf);

	if(!handle) {
		err(1, "Couldn't open pcap file %s: %s\n", pcapfile, errbuf);
		return 0;
	}

	//compile filter
	if(pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN))
	{
		err(1, "Filter did not compile");
		return 0;
	}

	//add filter to pcap handle
	if(pcap_setfilter(handle, &fp))
	{
		err(1, "Error setting filter");
		return 0;
	}
	return handle;
}

//used by listen_for_dnsflow_pkt --- when listening on socket for packets
//used by read_next_dnsflow_packet --- when reading from file
static char data_g[DNSFLOW_PKT_MAX_SIZE + DCAP_HEADER_SIZE];

//A simple function to loop and continue to accepting requests to then pass 
//on the messages to handleRequest to be parsed
void listen_for_dnsflow_pkt(int socketfd, int32_t (*func)(char*, uint32_t))
{
	uint32_t total_data;
	int32_t ret = 0;

	//loop while we can read from socket
	while(1)
	{
		//Receive request data
		total_data = recvfrom(socketfd, data_g, DNSFLOW_PKT_MAX_SIZE, 0, (struct sockaddr *) 0, (socklen_t *) 0);

		DBG("Total data received: %u\n", total_data);
		//Check size of received packet
		if(total_data < DNSFLOW_HEADER_SIZE || total_data > DNSFLOW_PKT_MAX_SIZE)
		{
			warnx("Bad dnsflow packet!");
			continue;	
		}
		ret = func(data_g, total_data);
		if(ret)
		{
			err(1, "Error, callback function returned code %d",ret);
			exit(ret);
		}
	}
}

static char filename_g[MAX_FILENAME_LEN + 1];
static int32_t file_byte_counter_g = 0;
static FILE * file_read_handle_g;
static uint32_t file_size_g;

//read dcap from a file
void read_dcap_packets(FILE file, int32_t (*func)(char*, uint32_t))
{
	/*
	uint32_t total_data;
	int32_t ret = 0;

	//loop while we can read from socket
	while(1)
	{
		//Receive request data
		total_data = recvfrom(socketfd, data_g, DNSFLOW_PKT_MAX_SIZE, 0, (struct sockaddr *) 0, (socklen_t *) 0);

		printf("Total data received: %u\n", total_data);
		//Check size of received packet
		if(total_data < DNSFLOW_HEADER_SIZE || total_data > DNSFLOW_PKT_MAX_SIZE)
		{
			warnx("Bad dnsflow packet!");
			continue;	
		}
		ret = func(data_g, total_data);
		if(ret)
		{
			err(1, "Error, callback function returned code %d",ret);
			exit(ret);
		}
	}
	*/
}


//set up to read from a file handle
//returns 0 on failure, 1 on success
int32_t prepare_to_open_dcap_fileh(FILE * file, int32_t file_type)
{
	file_byte_counter_g = 0;
	file_read_handle_g = file;

	if(file_type == STDIN_FILE)
	{
		//get file size
		fseek(file_read_handle_g, 0, SEEK_END);
		file_size_g = ftell(file_read_handle_g);
		rewind(file_read_handle_g);
	}
	else
		file_size_g = 0;
	return 1;
}

//set up to read from a file
//returns 0 on failure, 1 on success
int32_t prepare_to_open_dcap_files(char * filename, int32_t write_flag)
{
	DBG("opening file %s with flag %d\n", filename, write_flag);
	//check length
	if(strlen(filename) > MAX_FILENAME_LEN)
		return 0;

	if(write_flag) //open files append
	{
		if (!(file_read_handle_g = fopen(filename, "a+")))
			return 0;
	}
	else
	{  //open for reading
		if (!(file_read_handle_g = fopen(filename, "r")))
			return 0;
	}

	strncpy(filename_g, filename, MAX_FILENAME_LEN);
	file_byte_counter_g = 0;

	//get file size
	fseek(file_read_handle_g, 0, SEEK_END);
	file_size_g = ftell(file_read_handle_g);
	DBG("file %s size %u\n", filename, file_size_g);
	rewind(file_read_handle_g);
	return 1;
}

//reads in header from file into hdr pointer
void read_dcap_header(struct dcap_header *hdr, FILE * file)
{
	if(!fread(hdr, sizeof(struct dcap_header), 1, file))
	{
		//set data len 0
		hdr->data_len = 0;
	}

}

//read in dcap file and print32_t out data
int32_t read_dcap_filestream_cb(FILE * handle, int (*callback)(char *, struct dcap_header *))
{
	DBG("%s\n", "reading in from file handle");

	struct dcap_header header;
	char * data;

	//read in file while we can
	uint32_t byte_counter = 0;
	
	//read header
	read_dcap_header(&header, handle);
//	DBG("dnsflow header len %u\n", (unsigned int)sizeof(struct dnsflow_hdr));
//	DBG("dcap header len %u\n", (unsigned int)sizeof(struct dcap_header));
//	DBG("first dcap header len %u\n", header.data_len);

	printf("dnsflow header len %u\n", (unsigned int)sizeof(struct dnsflow_hdr));
	printf("dcap header len %u\n", (unsigned int)sizeof(struct dcap_header));
	printf("first dcap header len %u\n", header.data_len);

	//read file while datalen
	while(header.data_len)
	{
		//add to counter
		byte_counter += sizeof(struct dcap_header);
        printf("byte_counter = %d\n",byte_counter);

		//get data packet
		data = get_next_dnsflow_packet_from_file(&header, handle);
        printf("got data");

		//call callback function
		callback(data, &header);

		//read next header
		read_dcap_header(&header, handle);

		byte_counter += header.data_len;
	}

	DBG("%s\n","done reading in file");

	//close file
	return byte_counter;
}
//returns 1 if a is greater than or equal to b
//otherwise returns -1 if a = b or if a is less than b
int32_t compare_tm(struct tm32 * a, struct tm32 *b)
{

	struct tm buf1, buf2;
	memcpy(&buf1, a, sizeof(struct tm32));
	memcpy(&buf2, b, sizeof(struct tm32));

	time_t t1 = mktime((struct tm*) &buf1);
	time_t t2 = mktime((struct tm*) &buf2);

	return (difftime(t1, t2) >= 0) ? 1 : -1;

}

//swaps two pointers pointing to a container pointer type
inline void swap_ptrs(void ** a, void ** b)
{
	void *c = *a;
	*a = *b;
	*b = c;
}

//returns the data ptr of next dnsflow packet's data
// SHOULD NOT BE CALLED WITH THE OTHER get_next_dnsflow_packet function!!!
// THEY SHARE BUFFERS
char * get_next_dnsflow_packet_from_file(struct dcap_header * header, FILE * file)
{
	//get data
    printf("i'm in get_next_dnsflow_packet_from_file!");
	size_t amt2 = fread(data_g, 1, header->data_len, file);
	if(amt2 == 0)
	{
		return 0; // error
	}

	return data_g;
}


//returns the type of a dnsflow packet 0 == stats, 1 == data
//on error returns -1
int32_t parse_packet_type(char * data, uint32_t len)
{
	uint32_t offset = 0;
	struct dnsflow_hdr hdr;
	offset = get_header(&hdr, data);

	//error check
	if(offset < sizeof(struct dnsflow_hdr))
		return DNSFLOW_TYPE_ERR;

	//stats
	if(hdr.flags)
		return DNSFLOW_TYPE_STATS;

	//data
	return DNSFLOW_TYPE_DATA;
}

//returns the data ptr of next dnsflow packet and the dcap header which has 
//the timestamp and length of data
char * get_next_dnsflow_packet(struct dcap_header * header)
{
	DBG("%s\n", "getting next packet");
	if(file_byte_counter_g >= file_size_g || (file_size_g == 0 && file_read_handle_g == STDIN_FILE))
	{
		//done
		return 0;
	}

	//get files handle
	//read from filehandle + offset
	size_t amt1 = fread(data_g, 1, sizeof(struct dcap_header), file_read_handle_g);
	DBG("reading header size %u\n", (uint32_t)amt1);
	if(amt1 == 0)
		return 0; // done reading

	//get timestamp, data len from header
	struct dcap_header * cast_header = (struct dcap_header *)data_g;
	*header = *cast_header;

	//get rest of data
	DBG("reading data size %u\n", header->data_len);
	size_t amt2 = fread(data_g, 1, header->data_len, file_read_handle_g);
	if(amt2 == 0)
		return 0; // error

	file_byte_counter_g += sizeof(struct dcap_header) + header->data_len;

	return data_g;
}

//returns total amount of bytes read
uint32_t close_dcap_file(void)
{
	if(file_read_handle_g)
	{
		fclose(file_read_handle_g);
	}
	return file_byte_counter_g;
}

void print_dcap_headers(struct dcap_header ** hdrs, int32_t num)
{
	//printf("printing all dcap headers\n");
	int32_t i;
	for(i=0; i<num;i++)
	{
	DBG("printing dcap_hdr %d\n", i);
	}
}

void print_hex_data(unsigned char * data, uint32_t len)
{
	DBG("PRINTING HEX DATA, len: %d\n", (int)len);
	int32_t i;
	for(i = 0; i < (int)len; i++)
	{
		fprintf(stderr, "%hhx ", data[i]);
	}
	fprintf(stderr, "\n");
}

//This is duplicated code from write_dnsflow_pkt_to_dcap_file
//
//file should be open for appending!!
//
//write raw stream to file
//file format: (uint32_t size) (data)
int32_t write_dnsflow_pkt_to_dcap_fileh(char * data, uint32_t total_size, FILE * file)
{

	//want to add an additional header
	struct dcap_header header;
	header.data_len = total_size;
	header.timestamp = get_timestamp(NULL);

	//write data to file
	//printf("writing data to file header size %d, data %d\n", sizeof(header), total_size);
	write_dcap_data(file, data, &header);

	return 0;
}

/* takes in a set and a dcap header (for time stamp purposes) and creates a new
   dnsflow packet to write to the file handle passed in
   dcap_packet (for data dnsflow packet) contents:
      header: struct tm timestamp, unisnged int len
      dnsflow:
		header:
		    version(uint8), sets_count(uint8), flags(uint16), sequence_number(uint32)
		[header->sets_count of these]
		set header:
			client_ip(in_addr_t), names_count(uint8), ips_count(uint8), names_len(uint16)
		data set:	
			char *names[], int32 name_lens[], num_names(int32), in_addr_t ips[], num_ipsint32)

struct dnsflow_buf {
	uint32_t		db_type;	 What's in the union
	uint32_t		db_len;		Size of what's in the pkt,
								   db_pkt_hdr and below.
	uint32_t		db_loop_hdr;	 Holds PF_ type when dumping
									   straight to pcap file. 
	struct dnsflow_hdr	db_pkt_hdr;
	union {
		struct dnsflow_data_pkt		data_pkt;
		struct dnsflow_stats_pkt	stats_pkt;
	} DB_dat;
};


*/
//Note: don't really need the data packet size, but it makes things easier
//also need to check if this function returns -1 (error) or 0 (ok)
int32_t write_dcap_set_to_file(struct dcap_header * dc_hdr, char * data, unsigned int data_size, FILE * file)
{
	DBG("data size: %u, Hex:\n", data_size);

	struct dnsflow_hdr hdr;
	init_dnsflow_data_header(&hdr);
	host_to_net_dnsflow_hdr(&hdr);

	//add one set to dnsflow data packet
	hdr.sets_count = 1;
	
	//update dcap length
	dc_hdr->data_len = data_size + sizeof(struct dnsflow_hdr);
	//keeping old timestamp

	//write data:
	//dcap header
	if(!fwrite(((char*) dc_hdr), 1, sizeof(struct dcap_header), file))
		return -1;

	//write data set header and data set to file
	return write_dnsflow_set_to_file(&hdr, data, data_size, file);
}

//write a data set to a file
int32_t write_dnsflow_set_to_file(struct dnsflow_hdr * hdr, char * data, unsigned int data_size, FILE * file)
{
	//change the packets back to netowrk order
	if(!fwrite(((char*) hdr), 1, sizeof(struct dnsflow_hdr), file))
		return -1;

	//write data for dnsflow packet
	if(!fwrite(data, 1, data_size, file))
		return -1;

	return 0;
}
//converts a dnsflow header to network order
void host_to_net_dnsflow_hdr(struct dnsflow_hdr * hdr)
{
	hdr->flags = htons(hdr->flags);
	hdr->sequence_number = htonl(hdr->sequence_number);
}

//inits a dnsflow header
void init_dnsflow_data_header(struct dnsflow_hdr * hdr)
{
	hdr->version = 0;
	hdr->sets_count = 0;
	hdr->flags = 0; //0 for data packet, 1 for stats packet
	hdr->sequence_number = 0;
}


int32_t write_dcap_pkt_to_dcap_file(char * data, struct dcap_header * header, char * filename)
{
	FILE * file = fopen(filename, "a+");
	if(!file)
	{
		err(1, "Unable to open file: %s", filename);
		return 1;
	}
	write_dcap_data(file, data, header);
	return 0;
}


//write raw stream to file
//file format: (uint32_t size) (data)
int32_t write_dnsflow_pkt_to_dcap_file(char * data, uint32_t total_size, char * filename)
{
	//printf("writing to file %s\n", filename);
	FILE * file;

	//append to file
	file = fopen(filename, "a+");
	if(!file)
	{
		err(1, "Unable to open file: %s", filename);
		return 1;
	}

	//want to add an additional header
	struct dcap_header header;
	header.data_len = total_size;
	header.timestamp = get_timestamp(NULL);

	//write data to file
	//printf("writing data to file header size %d, data %d\n", sizeof(header), total_size);
	write_dcap_data(file, data, &header);

	fclose(file);

	return 0;
}

//Currently writes format: <size of data in bytes><data>
int32_t write_dcap_data(FILE * file, char * data, struct dcap_header * header)
{
	DBG("writing %u data\n", header->data_len);

	if(!fwrite(((char *)header), 1, sizeof(struct dcap_header), file))
		return -1;


	if(!fwrite(data, 1, header->data_len, file))
		return -1;


	return 0;
}

//nmsg globals
static nmsg_message_t msg_g;
static nmsg_msgmod_t mod_g;
static nmsg_output_t output_g;
static nmsg_res res_g;
static void *clos_g;

//write raw stream to nmsg format
int32_t write_dnsflow_pkt_to_nmsg_file(char * data, uint32_t total_size) 
{       
        //get the dnsflow header
        struct dnsflow_hdr hdr; 
        int offset = get_header(&hdr, data);

        //move past dnsflow header
        data += offset;
        
        //call write function
        write_nmsg_dcap_data(data, &hdr, total_size);
	
	return 0;
}

//Write preformated data to nmsg formatted file
int32_t write_nmsg_dcap_data(char * data, struct dnsflow_hdr * hdr, uint32_t size)
{       
	int version = hdr->version;
	int sets_count = hdr->sets_count;
	int flags = hdr->flags;
	int seq_num = hdr->sequence_number;
	
        //fprintf(stderr, "%d, %d, %d, %d\n", version, sets_count, flags, seq_num);

        //set dcap mod fields with data
        nmsf(msg_g, "version", 0, &version, sizeof(version));
        nmsf(msg_g, "sets_count", 0, &sets_count, sizeof(sets_count));
        nmsf(msg_g, "flags", 0, &flags, sizeof(flags));
        nmsf(msg_g, "sequence_number", 0, &seq_num, sizeof(seq_num));
        nmsf(msg_g, "data", 0, data, size);
     	
     	//write output to file
     	nmsg_output_write(output_g, msg_g);
     	
	return 0;       
}

//init the nmsg lib set up file for writing
int init_nmsg(char * filename) {

        /* initialize libnmsg */
	res_g = nmsg_init();
	if (res_g != nmsg_res_success)
		err(1, "Unable to initialize libnmsg\n");

        /*open file for appending*/
        FILE * file;
        file = fopen(filename, "a+");
        int fd = fileno(file);
        if (!file) 
        {
                err(1, "Unable to open file: %s", filename);
        }


	/* create nmsg output */
	output_g = nmsg_output_open_file(fd, 5000);
	if (output_g == NULL)
		err(1, "Unable to nmsg_output_open_file()");

	/* open handle to the dcap module */
	mod_g = nmsg_msgmod_lookup(NMSG_VENDOR_ISC_ID, NMSG_VENDOR_ISC_DCAP_ID);
	if (mod_g == NULL)
		err(1, "Unable to acquire module handle");

	/* initialize module */
	res_g = nmsg_msgmod_init(mod_g, &clos_g);
	if (res_g != nmsg_res_success)
		exit(res_g);
		
        msg_g = nmsg_message_init(mod_g);
	assert(msg_g != NULL);

        return 0;
}

//clean up nmsg and close output file
int cleanup_nmsg() {

        nmsg_message_destroy(&msg_g);
        
        /* finalize module */
	nmsg_msgmod_fini(mod_g, &clos_g);

	/* close nmsg output */
	nmsg_output_close(&output_g);
        
        return 0;
}

int get_dnsflow_socketfd(int port, char * interface, int32_t verbosity)
{
	int socketfd;
	int32_t length;
	struct sockaddr_in server;
	struct ifreq ifr;


	//Socket we'll use to listen to dnsflow messages
	if(verbosity)
		printf("Creating socket\n");
	if((socketfd = socket(AF_INET, SOCK_DGRAM, 0)) < 1)
	{
		err(1, "socket failed");
		exit(1);
	}

	//bind socket to device
	if(interface)
	{
		memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
		DBG("binding to interface: %s, ifr size: %u\n", ifr.ifr_name, sizeof(ifr));
		if(setsockopt(socketfd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
		{
            //try to get any device
            //printf("binding to os given device\n");
            DBG("%s: %i\n", "perror", errno);
			err(1, "binding to device %s failed", interface);
			exit(1);
		}
	}


	//Set up socket to listen for dnsflow messages
	length = sizeof(server);
	bzero((char *) &server, length);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("198.108.63.60");
	server.sin_port = htons(port);
	DBG("binding to port %u\n", port);

	//bind to socket 
	if(verbosity)
		printf("Binding to socket\n");
	if(bind(socketfd, (struct sockaddr *) &server, length) < 0)
//bind(3, {sa_family=AF_INET, sin_port=htons(5300), sin_addr=inet_addr("0.0.0.0")}, 16) = 0

        
	{
		err(1, "error on binding");
		exit(1);
	}

	return socketfd;
}

//parse the data in a data packet from dnsflow
//data packet contents:
//		set header:
//			client_ip(in_addr_t), names_count(uint8), ips_count(uint8), names_len(uint16)
//		data set:	
//			char *names[], int32 name_lens[], num_names(int32), in_addr_t ips[], num_ipsint32)
void parse_data_packet(struct dnsflow_hdr * header, char * data_ptr,
		struct dns_data_set *data, struct dnsflow_set_hdr * set_header,
	   	uint32_t size)
{
	//Whats in a data packet?
	//Data sets containing: set header, and data
	uint32_t offset = 0;
	uint32_t i = 0;
	for(i = 0; i < header->sets_count; i++)
	{
		//parse the data set header
		offset = parse_set_hdr(data_ptr, &set_header[i]);
		data_ptr += offset;

		//Parse actual data set
		offset = parse_dns_data_set_pkt(data_ptr, &data[i], &set_header[i]);
		if(!offset)
		{
			warnx("no valid offset when parsing data set");
			return;
		}
		data_ptr += offset;
	}
}

//parses a dnsflow data set
//		data set:
//			char *names[], int32 name_lens[], num_names(int32), in_addr_t ips[], num_ipsint32)
//
uint32_t parse_dns_data_set_pkt(char * data_ptr, struct dns_data_set * data, struct dnsflow_set_hdr * header)
{
	uint32_t offset = 0;
	unsigned names_offset = 0;
	//*names[]
	uint32_t i =0;
	for(i = 0; i < header->names_count; i++)
	{
		//parse name
		int32_t len = strlen(data_ptr + names_offset);
		if(len > header-> names_len) //Shouldn't happen
		{
			warnx("error parsing names");
			return 0;
		}
		//ONLY COPY POINTER TO DATA -- DATA PACKET ON STACK NOT HEAP
		data->names[i] = (data_ptr + names_offset);
		data->name_lens[i] = len;
		data->num_names++;
		names_offset += len + 1; // Add 1 for null
	}
	offset += header->names_len;

	//num_names
	data->num_names = header->names_count;

	//ips
	for(i = 0; i < header->ips_count; i++)
	{
		data->ips[i] = *((in_addr_t*) (data_ptr + offset));
		offset += sizeof(in_addr_t);
		data->num_ips++;
	}

	//ips_count
	data->num_ips = header->ips_count;

	return offset;
}

//parses a data set header:
//		set hdr:
//			client_ip(in_addr_t), names_count(uint8), ips_count(uint8), names_len(uint16)
uint32_t parse_set_hdr(char * data_ptr, struct dnsflow_set_hdr *set_header)
{

	uint32_t offset = 0;

	set_header->client_ip = *((in_addr_t*) (data_ptr + offset));
	offset += sizeof(in_addr_t);

	set_header->names_count = *(uint8_t*) (data_ptr + offset);
	offset += sizeof(uint8_t);

	set_header->ips_count = *(uint8_t*) (data_ptr + offset);
	offset += sizeof(uint8_t);

	set_header->names_len = ntohs(*(uint16_t*)(data_ptr + offset));
	offset += sizeof(uint16_t);

	return offset;
}

//Parses a dns flow stats packet
void parse_stats_packet(char * data_ptr, struct dnsflow_stats_pkt *stats)
{
	uint32_t offset = 0;
	stats->pkts_captured = ntohl(*(uint32_t*) (data_ptr + offset));
	offset += sizeof(uint32_t);

	stats->pkts_received = ntohl(*(uint32_t*) (data_ptr + offset));
	offset += sizeof(uint32_t);
	
	stats->pkts_dropped = ntohl(*(uint32_t*) (data_ptr + offset));
	offset += sizeof(uint32_t);

	stats->pkts_ifdropped = ntohl(*(uint32_t*) (data_ptr + offset));
	offset += sizeof(uint32_t);
	
}

//Parse the dnsflow header and sets up the header struct
// header: version(uint8), sets_count(uint8), flags(uint16), sequence_number(uint32)
uint32_t get_header(struct dnsflow_hdr *header, char * data)
{
	DBG("%s\n", "packet dnsflow header:");

	uint32_t offset = 0;

	//put raw_header into dnsflow struct
	header->version = *((uint8_t *) (data + offset));
	offset += sizeof(uint8_t);

	header->sets_count = *((uint8_t*)(data + offset));
	offset += sizeof(uint8_t);

	header->flags = ntohs(*((uint16_t*)(data + offset)));
	offset += sizeof(uint16_t);

	header->sequence_number = ntohl(*((uint32_t*)(data + offset)));
	offset += sizeof(uint32_t);

        DBG("%s\n", "packet dnsflow header complete");

	return offset;
}

//pass in buffer or null, returns struct tm, or printed time in timestamp

struct tm32 get_timestamp(char * timestamp)
{
	static time_t raw_time_g;
	static struct tm32 * timeparts_g;
	time(&raw_time_g);
	timeparts_g = (struct tm32 *) localtime(&raw_time_g);

	//print into buffer if not null
	if(timestamp)
		strftime (timestamp, 20, "%X", (struct tm *)timeparts_g);
	return *timeparts_g;
}

//give a struct tm and buf prints a timestamp into buf
// timestamp could change in the future
int32_t get_tm_timestamp_string(struct tm32 * ts, char * buf, uint32_t buf_size)
{
	return strftime(buf, buf_size, "%X", (struct tm *)ts);
}
