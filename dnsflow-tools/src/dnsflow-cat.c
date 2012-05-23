/* 
 * dnsflow-cat.c
 *
 * the main purpose of this module is to read in dcap files and
 * cat them to stdout. 
 *
 * For now that's it
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <string.h>

#include "dnsflow-common.h"
#include "dnsflow-cat.h"

#include  "nmsg.h"

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
	int verbosity;
	int filename;
	int combine;
	char * combine_name;
	char * nmsg_file;
} arguments_g;

static char * program_name;

int main(int argc, char * argv[])
{     
	program_name = argv[0];

	//initalize vars
	arguments_g.verbosity = 0;
	arguments_g.filename = 0;
	arguments_g.combine = 0;
	arguments_g.nmsg_file = 0;

	//options string
	char * opt_string = "hcn:v";
	char c;
	
	DBG("size of dcap %u\n", sizeof(struct dcap_header));

	//Get options
	while ((c = getopt(argc, argv, opt_string)) != -1) {
		switch (c) {
			case 'c': //combine files
				arguments_g.combine = 1;
				break;
			case 'n': //write to nmsg file
			        arguments_g.nmsg_file = optarg;
			        break;
			case 'v': //verbosity
				//printf("setting verbosity to 1\n");
				arguments_g.verbosity = 1;
				break;
			case 'h': //intentional fall through
			case '?':
			default:
			  usage();
			  /* NOTREACHED */
		}
	}
	//no options passed
	if(optind == 1 && argc == 1)
		usage();
	//update where argv and argc point
	//NOTE: Get opt moves files names, or invalid arguments to the end of the
	//argv array. After these lines, argv and argc will point to the filesnames
	//or invalide arguments
	argc -= optind;
	argv += optind;
	
	if(arguments_g.combine)
	{
		combine_files(argc, argv);
		return 0;
	}
	
	if(arguments_g.nmsg_file) {
	        init_nmsg(arguments_g.nmsg_file);
	}

	cat_out_multiple_files(argc, argv);
	return 0;
}

//combines an arbitrary number of files and print to stdout
void combine_files(int argc, char ** argv)
{
	//printf("combining files\n");
	int num_files = argc;
	//some checks
	if(num_files >= 100)
	{
		warnx("passed in more than 100 files");
	}
	if(num_files >= 500)
	{
		errx(1,"too many files passed in: %d", num_files);
	}


	//printf("allocating memory\n");
	//allocate for each FILE pointer
	FILE ** files = NULL; 
	//allocate enough to keep each timestamp in memory
	//struct dcap_header ** dcap_hdrs = malloc(num_files * sizeof(struct dcap_header *));
	struct dcap_header ** dcap_hdrs = NULL;
	int i;
	
	//initalize
	dcap_hdrs = (struct dcap_header **) malloc(num_files * sizeof(struct dcap_header*));
	files = (FILE **) malloc(num_files * sizeof(FILE *));
	
	//allocate for each header 
	for(i = 0; i < num_files; i++)
	{
		files[i] = (FILE *) malloc(sizeof(FILE *));
		dcap_hdrs[i] = (struct dcap_header *) malloc(sizeof(struct dcap_header));
		bzero(dcap_hdrs[i], sizeof(struct dcap_header));
	}
	
	DBG("opening all %d files\n", argc);
	//open each file
	for(i = 0; i < num_files; i++)
	{
		//try to open file for reading
		if(!(files[i] = fopen(argv[i], "r")))
		{
			errx(1,"could not open file %s", argv[i]);
		}

		//get first chunk
		read_dcap_header(dcap_hdrs[i], files[i]);
		DBG("Read dcap len: %u, struct tm: %s", dcap_hdrs[i]->data_len, asctime((struct tm *)&dcap_hdrs[i]->timestamp));
	}

	//assume that if dcap_hdrs[i] == 0 that we are at the end of a file	
	int done = 0; // flag for finishing
	int next_smallest_idx = 0;
	char * data;

	DBG("dcap len: %u, struct tm: %s", dcap_hdrs[0]->data_len, asctime((struct tm *)&dcap_hdrs[0]->timestamp));

	//printf("looping over all files\n");
	while(!done)
	{
		next_smallest_idx = 0;
		//compare all of the file chunks
		for( i = 0; i < num_files; i++)
		{
			DBG("|dcap len: %u, struct tm: %s", dcap_hdrs[0]->data_len, asctime((struct tm *)&dcap_hdrs[0]->timestamp));

			DBG("printing dcap_hdr i:%d\n", i);
			//print_hex_data((unsigned char *)dcap_hdrs[i], sizeof(struct dcap_header));
			if(!dcap_hdrs[i]->data_len) //swap to end decreace num active files
			{
				DBG("\tfile %d done\n", i);
				swap_ptrs((void *)&dcap_hdrs[i], (void *)&dcap_hdrs[num_files-1]);
				swap_ptrs((void *)&files[i], (void *)&files[(num_files--)-1]);
				DBG("printing dcap_hdr %d\n", i);
				DBG("dcap len: %u, struct tm: %s", dcap_hdrs[i]->data_len, asctime((struct tm *)&dcap_hdrs[i]->timestamp));
				#ifdef DO_DEBUG
				print_hex_data((unsigned char *)dcap_hdrs[i], sizeof(struct dcap_header));
				#endif
				if(!num_files) // exit
				{
					done = 1;
					close_files(argc, files);
					free_dcaps(dcap_hdrs, argc);
					//free memory
					return;
				}
				if(i == num_files) // this is the last file
					break;
			}

			//printf("\tcomparing indexs\n");
			DBG("compare_tm returning %d\n", compare_tm(&dcap_hdrs[i]->timestamp, &dcap_hdrs[next_smallest_idx]->timestamp));
			DBG("comparing index %d and next_smallest_index %d\n", i, next_smallest_idx);
			//int32_t ret = difftime(mktime((struct tm*)&dcap_hdrs[i]->timestamp),mktime((struct tm*)&dcap_hdrs[next_smallest_idx]->timestamp));
			if(compare_tm(&dcap_hdrs[i]->timestamp, &dcap_hdrs[next_smallest_idx]->timestamp) < 0) // entry at i is less than index
			//if(ret < 0)
			{
				DBG("found a new smaller time at index %d\n", i);
				next_smallest_idx = i;
			}
			//print_hex_data((unsigned char *)dcap_hdrs[i], sizeof(struct dcap_header));
			DBG("|dcap len: %u, struct tm: %s", dcap_hdrs[0]->data_len, asctime((struct tm *)&dcap_hdrs[0]->timestamp));
		}
		DBG("Iteration end%s\n\n", "");

		//get data part of packet to write to output
		DBG("dcap len: %u, struct tm: %s", dcap_hdrs[next_smallest_idx]->data_len, asctime((struct tm *)&dcap_hdrs[next_smallest_idx]->timestamp));
		data = get_next_dnsflow_packet_from_file(dcap_hdrs[next_smallest_idx],
				files[next_smallest_idx]);

		//memcpy(&buf, dcap_hdrs[next_smallest_idx], sizeof(struct dcap_header));
		DBG("index %d writing data\n", next_smallest_idx);
		DBG("dcap len: %u, struct tm: %s", dcap_hdrs[next_smallest_idx]->data_len, asctime((struct tm *)&dcap_hdrs[next_smallest_idx]->timestamp));

		//write_dcap_data(stdout, data, &buf);
		write_dcap_data(stdout, data, (struct dcap_header *)dcap_hdrs[next_smallest_idx]);

		//get next header file
		read_dcap_header(dcap_hdrs[next_smallest_idx], files[next_smallest_idx]);
	}
}

//free dcap struct
void free_dcaps(struct dcap_header ** hdrs, int num)
{
	int i;
	for(i = 0; i < num; i++)
		free(hdrs[i]);
	free(hdrs);
}

//closes and frees files
void close_files(int num, FILE ** files)
{
	int i;
	for(i = 0; i < num; i++)
	{
		fclose(files[i]);
	}
	free(files);
}



//reads in multiple files and prints thier output using glob expansion
void cat_out_multiple_files(int num_files, char * files[])
{
	unsigned int byte_counter = 0; //total bytes seen in entire trace 
	unsigned int file_counter = 0;
	int index = 0;

	//for each file try to process
	for(index = 0; index < num_files; index++, file_counter++)
	{
		//printf("processing file %s\n", files[index]);
		if(files[index][0] == '-') // check first char in filename
		{
			warnx("invalid filename or option around \"-\"");
			break;
		}
		//gets(temp); //used to pause input between files for debugging
		byte_counter += cat_out_file(files[index]);
		file_counter++;
	}

	//print stats
	/*
	printf("\nProcessed %u bytes from %u files in %.2f seconds\n", byte_counter,
		   	file_counter, ((double)clock() - start) / CLOCKS_PER_SEC);
	*/
}

//prints out binary data from file to terminal
int cat_out_file(char * filename)
{
	
	if(!prepare_to_open_dcap_files(filename, 0)) //open for reading
	{
		perror("couldn't open file\n");
		return 0;
	}


	struct dcap_header dcap_hdr;
	char * data;

	//read in file while we can
	unsigned int counter = 0;
	
	//get data while there's some in the file
	while((data = get_next_dnsflow_packet(&dcap_hdr)))
	{
	        //write to nmsg file if specified
		if (arguments_g.nmsg_file) 
		        write_dnsflow_pkt_to_nmsg_file(data, dcap_hdr.data_len);
		else
		        write_dcap_data(stdout, data, &dcap_hdr);
		
		counter += dcap_hdr.data_len + sizeof(struct dcap_header);
	}

	//close file
        cleanup_nmsg();
	return (int) close_dcap_file();
}

//TODO NOT USED ANYMORE -- YET
//parses a dcap data packet and then calls to write it to file
int parse_dcap_data_packet(struct dcap_header * dcap_hdr, char * data)
{
	unsigned int data_size, header_size, total_data = dcap_hdr->data_len;
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
		//do stuff
		process_stats_packet(dcap_hdr, &header, &dnsflow_stats);
	}
	else //DNSFLOW DATA PACKET
   	{
		parse_data_packet(&header, data_ptr, dnsflow_data, dnsflow_data_set_hdr, data_size);
		//do stuff
		process_data_packet(dcap_hdr, &header, dnsflow_data, dnsflow_data_set_hdr);
	}

	return 0;
}

int process_stats_packet(struct dcap_header * dcap_hdr, struct dnsflow_hdr * dnsf_hdr,
		struct dnsflow_stats_pkt * stats)
{

	return 0;
}

int process_data_packet(struct dcap_header * dcap_hdr, struct dnsflow_hdr * dnsf_hdr,
		struct dns_data_set * dnsflow_data, struct dnsflow_set_hdr * dnsflow_data_set_hdr)
{
	return 0;
}

void usage()
{
	fprintf(stderr, "\nUsage: %s [-h] [-c] [-n filename] [-v] <filename>", program_name);
	fprintf(stderr, "\t[-h]: this help message\n");
	fprintf(stderr, "\t[-c]: combine 1 or more dcap files\n");
	fprintf(stderr, "\t[-n]: print to nmsg file\n");
	fprintf(stderr, "\t[-v]: use verbosity level\n");
	exit(1);
}
