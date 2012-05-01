#include <glib.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>

#define CACHE_SIZE 4000000 //4 MB
#define TRIALS 1000000

void usage();
timespec diff(timespec start, timespec end);
gboolean g_str_comp(gconstpointer a, gconstpointer b);

//this function tests the time it takes to call strcmp vs hashing the same string
int main(int argc, char * argv[])
{
	if(argc != 2)
		usage();

	int size = atoi(argv[1]);
	char * buf = (char *) malloc(size+1);
	char * buf1 = (char *) malloc(size+1);
	memset(buf, 'j', size);
	memset(buf1, 'j', size);
	buf[size] = '\0';

	//flush cache
	
	//insert string into hash table
	GHashTable * test = g_hash_table_new(g_str_hash, g_str_equal);
	int * i = new int;
	*i = 1;

	g_hash_table_insert(test, buf, i);

	//get a timestamp
	timespec ts_start;
	timespec ts_end;
	timespec strcmp_time;
	timespec hash_time;

	//flush cache
	char * a = (char *)malloc(CACHE_SIZE + 1);
	memset(a, 'j', CACHE_SIZE);

	//time has look up
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts_start);
	for(int j = 0 ; j < TRIALS; j++)
	assert(g_hash_table_lookup(test, buf1) != NULL);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts_end);

	hash_time = diff(ts_start, ts_end);
	float th = hash_time.tv_sec; 

	//flush cache
	a = (char*)malloc(CACHE_SIZE + 1);
	memset(a, 'j', CACHE_SIZE);


	//time strcmp call:
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts_start);
	for(int j = 0 ; j < TRIALS; j++)
	assert(strcmp(buf, buf1) == 0);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts_end);

	strcmp_time = diff(ts_start, ts_end);
	float ts = strcmp_time.tv_sec; 

	timespec diff_time = diff(strcmp_time, hash_time);
	float td = diff_time.tv_sec;

	printf("%i:\t\t %fsec %luns,\t\t %fsec %luns\n diff: %fsec %luns\n", size, ts, strcmp_time.tv_nsec, th, hash_time.tv_nsec, td, diff_time.tv_nsec);

	return 0;

}

timespec diff(timespec start, timespec end)
{
	timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}

gboolean g_str_comp(gconstpointer a, gconstpointer b)
{
	const char * d1 = (const char *) a;
	const char * d2 = (const char *) b;
	//int len;
	//if(strlen(d1) < strlen(d2))len = strlen(d1); else len = strlen(d2);
	//DBG("strcmp, a: %s, and b: %s\n", d1, d2);

	return strcmp(d1,d2) == 0 ? 0 : 1;
}

void usage()
{
	fprintf(stderr, "enter test string\n");
	exit(1);
}

