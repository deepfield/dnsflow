#include <stdio.h>
#include <stdlib.h>
#define BUF_SIZE 200

char filename[] = "dcaps/capture1.dcap";

int main()
{
	FILE * file = fopen(filename, "r");
	int size;
	fseek(file, 0, SEEK_END);
	size = ftell(file);
	printf("file size %d\n", size);
	rewind(file);
	printf("file after rewind %d\n", ftell(file));

	int position = 0;
	int readcnt = 0;
	char buf[BUF_SIZE];

	while(position < size)
	{
		readcnt = fread(buf,1, BUF_SIZE, file);
		printf("read cnt %d\n", readcnt);
		printf("file after read %d\n", ftell(file));
		position += readcnt;
		if(!readcnt)
			break;
	}
	printf("position %d\n", position);
}

