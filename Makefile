OS = $(shell uname)

CC = gcc -g -L/usr/lib -Wall -O3 -D_BSD_SOURCE

LIBS_DEFAULT = -lldns -lpcap -levent

ifeq ($(OS), Linux)
	LIBS_LINUX += -lrt -lcrypto 
	#LIBS = -Wl,-Bstatic $(LIBS_DEFAULT) $(LIBS_LINUX) -Wl,-Bdynamic
	LIBS = $(LIBS_DEFAULT) $(LIBS_LINUX)
else
	LIBS = $(LIBS_DEFAULT)
endif

dnsflow: dnsflow.c dcap.c dcap.h
	@echo "Building on OS [${OS}]"
	$(CC) dnsflow.c dcap.c -o dnsflow $(LIBS)
clean:
	@rm -f *.o dnsflow
	@rm -rf *.dSYM
