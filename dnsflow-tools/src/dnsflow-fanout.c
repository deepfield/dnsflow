
/*
 * dnsflow-fanout takes in a single dnsflow stream and sends it out to
 * multiple clients specified on the command line
 *
 * command line options include:
 *
 * 10.10.1.1
 * 10.10.1.1:8000
 *
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>

#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "dnsflow-common.h"
#include "dnsflow-fanout.h"

#define DNSFLOW_PORT 5300
#define DNSFLOW_MAX_FANOUT 100
#define MAX_IP_LEN 16
#define MAX_PORT_LEN 6


static struct GlobalArgs_t {
	struct sockaddr_in clients[DNSFLOW_MAX_FANOUT];
	int num_clients;
	int udp_socket;
	int verbosity;
} arguments_g;

char * program_name;

int main(int argc, char *argv[])
{
	printf("starting fanout\n");
	int c;
	unsigned short portno = DNSFLOW_PORT;
	int clients = 0;

	program_name = argv[0];
	char * interface = 0;

	arguments_g.num_clients = 0;
	arguments_g.udp_socket = 0;
	arguments_g.verbosity = 0;

	char * opt_string = "cei:p:v";

	//Get options
	while ((c = getopt(argc, argv, opt_string)) != -1) {
		switch (c) {
			case 'c': //clients listed on command line
				clients = 1;
				break;
			case 'e': //extra 
				arguments_g.verbosity = 1;
				printf("verbosity on level 1\n");
				break;
			case 'i':
				interface = optarg;
				printf("interface %s\n", interface);
				break;
			case 'p':
				portno = (unsigned short) atoi(optarg);
				printf("port option given %d\n", portno);
				break;
			case 'v':
				printf("dnsflow-fanout version 1.0\n");
				exit(1);
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
	printf("argc %d\n", argc);

	if(!clients)
	{
		printf("no dest clients\n");
		usage();
	}
	//parse clients string
	
	parse_client_string(argc, argv);

	if(!interface)
	{
		printf("listening on default interface for dnsflow\n");
	}

	//create udp socket to send on
	if((arguments_g.udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 1)
	{
		perror(NULL);
		err(1, "socket failed");
	}
	printf("socket %d\n", arguments_g.udp_socket);

	int verbosity = 1;

	//process dnsflow data from networks -- default action
	int socketfd = get_dnsflow_socketfd(portno, interface, verbosity);
	listen_for_dnsflow_pkt(socketfd, fanout_dnsflow_packets);
	return 0;

}

// convert each string to struct in_addr
// format is <ip>:<port>
int parse_client_string(int argc, char ** argv)
{
	printf("parsing client ips\n");
	char ip_str[MAX_IP_LEN] = {0}, port_str[MAX_PORT_LEN];
	char * pch = NULL;
	char * check = NULL;
	int i;
	char str[INET_ADDRSTRLEN];

	for(i = 0; i < argc; i++)
	{
		//zero mem
		memset((char *) &arguments_g.clients[i], 0, sizeof(struct sockaddr_in));
		arguments_g.clients[i].sin_family = AF_INET;

		//get ip part and port part
		check = strchr(argv[i], ':'); //check should be first
		pch = strtok(argv[i], ":");
		if(!check) // no port
		{
			printf("parsing ip %s\n", argv[i]);
			strcpy(ip_str, argv[i]);
			arguments_g.clients[i].sin_port = htons(DNSFLOW_PORT);
			printf("wtf %hu %hu %hu\n", arguments_g.clients[i].sin_port, DNSFLOW_PORT, ntohs(DNSFLOW_PORT));
		}
		else  // there is a port
		{
			printf("parsing port and ip\n");
			strcpy(ip_str, pch);
			pch = strtok(NULL, ":");
			strcpy(port_str, pch);
			printf("parsed port %s %d\n", port_str, atoi(port_str));
			arguments_g.clients[i].sin_port = htons(atoi(port_str));
			//strtok should return null now
			printf("parsed ip %s\n", ip_str);
		}
		
		//put ip string into sin_addr
		//returns 1 on success, 0 on error
		if (!inet_pton(AF_INET, ip_str, &(arguments_g.clients[i].sin_addr)))
		{
			perror(NULL);
			warnx("parsing ip failed");
		}

		printf("checking parse with client %d \n", i);
		//returns null on error
		if(!inet_ntop(AF_INET, &arguments_g.clients[i], str, INET_ADDRSTRLEN))
		{
			perror("Bad stuff\n");
		}
		printf("sending to %s on port %hu %hu\n", str, htons(arguments_g.clients[i].sin_port), arguments_g.clients[i].sin_port);

		arguments_g.num_clients++;
	}

	printf("clients parsed %d\n\n", arguments_g.num_clients);
	return arguments_g.num_clients;
}

//call back for sending out data packets
int fanout_dnsflow_packets(char * data, unsigned int data_len)
{
	if(arguments_g.verbosity)
		printf("faning out %u bytes of dnsflow\n", data_len);
	//send data to each client
	int i;
	char str[INET_ADDRSTRLEN];

	for(i = 0; i < arguments_g.num_clients; i++)
	{
		if(arguments_g.verbosity)
		{
			inet_ntop(AF_INET, (struct in_addr *)&arguments_g.clients[i], str, INET_ADDRSTRLEN);
			printf("%d sending to %s on port %hu\n", i, str, htons(arguments_g.clients[i].sin_port));
		}
		if(sendto(arguments_g.udp_socket, data, data_len, 0, 
					(struct sockaddr *) &arguments_g.clients[i], 
					sizeof(struct sockaddr_in)) < 0)
		{
			perror(NULL);
			warnx("sending failed");
		}
	}
	return 0;
}


void usage()
{
	fprintf(stderr, "\nUsage: %s [-i interface] [-p port] [-c client dest list]"
			, program_name);
	fprintf(stderr, "\t[-c]: client ip list\n");
	fprintf(stderr, "\t[-i]: interface to listen to dnsflow messages on\n");
	fprintf(stderr, "\t[-p]: port to listen for dnsflow message\n");
	fprintf(stderr, "\t[-v]: version\n\n");

	exit(1);

}
