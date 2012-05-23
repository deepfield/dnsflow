/* kroell change - added nsmg flag to globalargs 
/*               - added call to nmsg output function if arg set
*/

#include <getopt.h>
#include <sys/stat.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <time.h>
#include "dnsflow-capture.h"
#include "dnsflow-common.h"


#define WHITESPACE_DELIMS " \n\t\v\f\r"
#define DNSFLOW_PORT 5300
#define DNSFLOW_FILE_EXT "dcap"
#define DNSFLOW_CAP_FILENAME "dnsflow"
#define DNSFLOW_MAX_FILENAME 50
#define DNSFLOW_MAX_DIRNAME 50
#define DNSFLOW_MAX_FILESIZE 1024000 //1 MB
#define DEFAULT_PERMISSIONS 0777
#define DNSFLOW_MAX_FILEPATH 255
#define EST (-5)

//#define DO_DEBUG

#ifdef DO_DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#define DBG(fmt, ...) \
	do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
			__LINE__, __func__, __VA_ARGS__); } while (0)

//globals ----------------
struct GlobalArgs_t {
	int verbosity;
	char * interface;
	char * outfile;
	char * directory;
	char * filename;
	FILE * file;
	char file_and_path[DNSFLOW_MAX_FILEPATH];
	char cap_filename[DNSFLOW_MAX_FILENAME];
	char cap_directory[DNSFLOW_MAX_FILEPATH];
	unsigned int file_counter;
	unsigned int bytes_to_file;
	unsigned int bytes_written_total;
	unsigned int nmsg;
	char * nmsg_filename;
	struct tm32 time;
} arguments_g;
//-------------------------


static char * program_name;

int main(int argc, char *argv[])
{
	DBG("%s\n", "starting capture");
	int c, port = DNSFLOW_PORT;

	program_name = argv[0];
	char opt_string[] = "d:i:p:n:w:v:";
	char * interface = 0;
	char buf[DNSFLOW_MAX_FILENAME + DNSFLOW_MAX_DIRNAME + 1];

	//init global args
	arguments_g.verbosity = 0;
	arguments_g.outfile = 0;
	arguments_g.directory = 0;
	arguments_g.filename = 0;
	arguments_g.bytes_to_file = 0;
	arguments_g.bytes_written_total = 0;
	arguments_g.file_counter = 0;
	arguments_g.file = 0;
	arguments_g.nmsg = 0;
	arguments_g.nmsg_filename = 0;
	strcpy(arguments_g.cap_filename, DNSFLOW_CAP_FILENAME);


	//Get options
	while ((c = getopt(argc, argv, opt_string)) != -1) {
		switch (c) {
			case 'd': //directory to write files to
				DBG("%s\n", "checking directory");
				//check for slash "/" at the end
				if(*(optarg + strlen(optarg) - 1) == '/')
					optarg[strlen(optarg) - 1] = '\0';
				arguments_g.directory = optarg;
				struct stat st;
				if(stat(arguments_g.directory,&st) != 0)
				{
					DBG("%s is not present, creating %s.\n", optarg, optarg);
					mkdir(arguments_g.directory, DEFAULT_PERMISSIONS);
				}
				DBG("directory present, status %s %d\n", optarg, stat(optarg, &st));
				arguments_g.filename = buf;
				break;
			case 'i': //interface to listen on default to read from std in
				interface = optarg;
				break;
			case 'p': //port to capture on
				port = atoi(optarg); 
				break;
			case 'v':
				arguments_g.verbosity = atoi(optarg);
				break;
			case 'w':
				arguments_g.filename = optarg;
				break;
		        case 'n': 
		                //write to nmsg format
		                arguments_g.nmsg = 1;
		                arguments_g.nmsg_filename = optarg;
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

	//check if ouput destination for flow
	if(!arguments_g.filename && !arguments_g.directory)
	{
		printf("No output file or directory, writing to std out!\n");
		//usage();
	}
	
	//check for nmsg 
	if (arguments_g.nmsg) 
	{
	        if (arguments_g.nmsg_filename)
	        {
	                init_nmsg(arguments_g.nmsg_filename);
	        }
	        else 
	        { 
	                fprintf(stderr, "No nmsg filename specified for write");
	                return 1;
	        }
	}
	
	//check for conflicting options
	if(arguments_g.filename && arguments_g.directory)
	{
		printf("Ignoring filename argument, using directory\n");
	}
	else if (arguments_g.filename) // open file for writing
	{
		arguments_g.file = fopen(arguments_g.filename, "a+");
		if(!arguments_g.file)
		{
            perror(NULL);
			err(1, "Unable to open file: %s", arguments_g.filename);
			return 1;
		}
	}

	//if no interface read from stdin
	if(!interface)
		return read_from_stdin();

	//process dnsflow data from networks -- default action
    DBG("binding to interface %s\n", interface);
	int socketfd = get_dnsflow_socketfd(port, interface, arguments_g.verbosity);
	listen_for_dnsflow_pkt(socketfd, parse_dnsflow_packets);

        //close nmsg 
        if (arguments_g.nmsg) 
        {
                cleanup_nmsg();
        }
        
	//close file  XXX NEEDS TESTING
	if(arguments_g.filename && !arguments_g.directory)
		fclose(arguments_g.file);
	
	return 0;
}


//call back funciton for dnsflow data capture
int parse_dnsflow_packets(char * data, unsigned int total_size)
{
	DBG("in parse_dnsflow_packets %u data\n", total_size);
	int ret;
	//check if writing to directory
	if(arguments_g.directory)
	{
		//printf("writing to dir\n");
		ret = write_dnsflow_pkt_to_directory(data, total_size);
	}
	else if(arguments_g.filename || arguments_g.nmsg_filename)
	{
		printf("writing to file %s\n", arguments_g.filename);
		//check if writing to nmsg file or regular file
		if (arguments_g.nmsg) 
		{
		        printf("writing in nmsg format\n");
		        ret = write_dnsflow_pkt_to_nmsg_file(data, total_size); 
		}
		
		if (arguments_g.filename)
		        ret = write_dnsflow_pkt_to_dcap_file(data, total_size, arguments_g.filename);
	}
	else
	{
		//printf("writing to stdout", data);
		ret = write_dnsflow_pkt_to_dcap_fileh(data, total_size, stdout);
	}
	return ret;
}

//parses dcap packets and records them
int parse_dcap_packets(char * data, struct dcap_header * header)
{
	int ret;
	//check if writing to directory
	if(arguments_g.directory)
	{
		ret = write_dcap_to_directory(data, header);
	}
	else if(arguments_g.filename)
	{
		ret = write_dcap_pkt_to_dcap_file(data, header, arguments_g.filename);
	}
	else
	{
		ret = write_dcap_data(stdout, data, header);
	}
	return ret;
}

//returns 1 if the we're in the next hour time slot or 0 if not
int is_next_hour()
{
	static int last_hour = -1;
	time_t timenow;

	timenow = time(NULL);
	struct tm * new_time = gmtime( &timenow );
	if(last_hour < 0 || last_hour != new_time->tm_hour)
	{
		last_hour = new_time->tm_hour;
		DBG("new filename, last hour: %i\n", last_hour);
		return 1;
	}
	return 0;
}


int write_dcap_to_directory(char * data, struct dcap_header * header)
{
	DBG("writing dcap pkts to directory %s\n", arguments_g.directory);
	if(is_next_hour() || arguments_g.bytes_to_file == 0)
	{
		//create new file
		char filenum[20];

		get_tm_time(&arguments_g.time);
		get_directory(arguments_g.cap_directory);
		get_filename(arguments_g.filename, filenum);


		DBG("so far %s\n", arguments_g.filename);
		DBG("so1 far %s\n", arguments_g.cap_directory);

		arguments_g.file_and_path[0] = '\0';
		strcat(arguments_g.file_and_path, arguments_g.cap_directory);
		strcat(arguments_g.file_and_path, "/");
		strcat(arguments_g.file_and_path, arguments_g.filename);

		DBG("so2 far %s\n", arguments_g.file_and_path);

		arguments_g.bytes_to_file = 0;
		arguments_g.file_counter++;
	}

	return write_dcap_pkt_to_dcap_file(data, header, arguments_g.filename);
}

//this function creates files in a directory of max size
int write_dnsflow_pkt_to_directory(char *data, unsigned int total_size)
{
	DBG("writing to directory %s\n", arguments_g.directory);
	if(is_next_hour())
	{
		//create new file
		char filenum[20];
		DBG("filenum %u\n", arguments_g.file_counter);

		get_tm_time(&arguments_g.time);
		get_directory(arguments_g.cap_directory);
		get_filename(arguments_g.filename, filenum);


		DBG("so far %s\n", arguments_g.filename);
		DBG("so1 far %s\n", arguments_g.cap_directory);

		arguments_g.file_and_path[0] = '\0';
		strcat(arguments_g.file_and_path, arguments_g.cap_directory);
		strcat(arguments_g.file_and_path, "/");
		strcat(arguments_g.file_and_path, arguments_g.filename);

		DBG("so2 far %s\n", arguments_g.file_and_path);

		arguments_g.bytes_to_file = 0;
		arguments_g.file_counter++;
	}
	return write_dnsflow_pkt_to_dcap_file(data, total_size, arguments_g.file_and_path);
}

void get_tm_time(struct tm32 * tm)
{
	//get time
	time_t rawtime;
	time(&rawtime);
	*tm = *((struct tm32*)gmtime(&rawtime));
}

//get filename and make directories for rolling log files
void get_filename(char * file, char * num)
{
	struct tm32 * timeinfo = (struct tm32*)&arguments_g.time;

	//get year
	int year = 1900 + timeinfo->tm_year;
	char year_str[10];
	sprintf(year_str, "%04d", year);

	//get month 
	int month = timeinfo->tm_mon;
	char month_str[10];
	sprintf(month_str, "%02d", (month + 1));

	//get day
	int day = timeinfo->tm_mday;
	char day_str[10];
	sprintf(day_str, "%02d", day);

	//get hour
	int hour = timeinfo->tm_hour;
	char hour_str[10];
	sprintf(hour_str, "%02d", (hour+EST)%24);

	//get second
	int minute = timeinfo->tm_min;
	char minute_str[10];
	sprintf(minute_str, "%02d", minute);

	//get seconds
	int second = timeinfo->tm_sec;
	char second_str[10];
	sprintf(second_str, "%02d", second);

	//base directory is arguments_g.directory
	file[0] = '\0';

	//make all directories
	//make year
	strcat(file, year_str);
	//make month
	strcat(file, "-");
	strcat(file, month_str);
	//make day of month
	strcat(file, "-");
	strcat(file, day_str);
	strcat(file, ".");
	strcat(file, hour_str);
	strcat(file, "");
	strcat(file, minute_str);
	strcat(file, "");
	//strcat(file, DNSFLOW_CAP_FILENAME);
	strcat(file, ".");
	strcat(file, second_str);
	strcat(file, ".");
	strcat(file, DNSFLOW_FILE_EXT);
}

void get_directory(char * dir)
{
	struct tm32 * timeinfo = (struct tm32 *) &arguments_g.time;

	//get year
	int year = 1900 + timeinfo->tm_year;
	char year_str[10];
	sprintf(year_str, "%04d", year);

	//get month 
	int month = timeinfo->tm_mon;
	char month_str[10];
	sprintf(month_str, "%02d", (month + 1));

	//get day
	int day = timeinfo->tm_mday;
	char day_str[10];
	sprintf(day_str, "%02d", day);

	//get hour
	int hour = timeinfo->tm_hour;
	char hour_str[10];
	sprintf(hour_str, "%02d", hour);

	//base directory is arguments_g.directory
	dir[0] = '\0';
	strcat(dir, arguments_g.directory);

	//make all directories
	//make year
	strcat(dir, "/");
	strcat(dir, year_str);
	mkdir(dir, DEFAULT_PERMISSIONS);
	//make month
	strcat(dir, "/");
	strcat(dir, month_str);
	mkdir(dir, DEFAULT_PERMISSIONS);
	//make day of month
	strcat(dir, "/");
	strcat(dir, day_str);
	mkdir(dir, DEFAULT_PERMISSIONS);

}

/*
//write raw stream to file
//file format: (unsigned int size) (data)
int write_dcap_to_file(char * data, unsigned int total_size, char * filename)
{
	printf("writing to file %s\n", filename);
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
	printf("writing data to file header size %d, data %d\n", sizeof(header), total_size);
	write_dcap_data(file, data, &header);

	fclose(file);

	arguments_g.bytes_to_file += total_size;
	arguments_g.bytes_written_total += total_size;
	return 0;
}
*/


//Read in a dcap file from stdin
int read_from_stdin(void)
{
	DBG("%s\n","reading from stdin");
	DBG("%s\n", "not tested yet");

	read_dcap_filestream_cb(stdin, parse_dcap_packets);

	return 0;
}

void usage(void)
{
	fprintf(stderr, "\nUsage: %s [-i interface] [-p port] [-h]"
		   " [-v<number [0:1]>] [-n outfilename] [-w outfilename]\n", program_name);
	fprintf(stderr, "default's to reading in from stdin and writing to stdout\n");
	fprintf(stderr, "\t[-d]: directory to write rolling pcap files to\n");
	fprintf(stderr, "\t[-i]: interface to read packets\n");
	fprintf(stderr, "\t[-h]: print this help message\n");
	fprintf(stderr, "\t[-n]: write to file in nmsg format\n");
	fprintf(stderr, "\t[-p]: listen port number\n");
	fprintf(stderr, "\t[-w]: write to file in dcap format\n");
	fprintf(stderr, "\t[-v]: version\n\n");
	exit(1);
}
