OS = $(shell uname)

CC_OPTS =
CC = gcc $(CC_OPTS) -g -L/usr/lib -Wall -D_BSD_SOURCE

LIBS_DEFAULT = -lldns -lpcap -levent

ifeq ($(OS), Linux)
	LIBS_LINUX += -lrt -lcrypto -lbsd
	LIBS = -Wl,-Bstatic $(LIBS_DEFAULT) $(LIBS_LINUX) -Wl,-Bdynamic
else
	LIBS = $(LIBS_DEFAULT)
endif

dnsflow: dnsflow.c dcap.c dcap.h
	@echo "Building on OS [${OS}]"
	$(CC) dnsflow.c dcap.c -o dnsflow $(LIBS)
clean:
	@rm -f *.o dnsflow
	@rm -rf *.dSYM
