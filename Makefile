OS = $(shell uname)

CC = gcc -g -L/usr/lib -Wall -O3 -D_BSD_SOURCE

LIBS_DEFAULT = -lldns -lpcap -levent

ifeq ($(OS), Linux)
	LIBS_LINUX += -lrt 
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

uninstall: clean
	@rm -v /usr/local/sbin/dnsflow

ubuntu-uninstall: uninstall
	@update-rc.d -f dnsflow remove
	@rm -v /etc/init.d/dnsflow
	@rm -v /etc/default/dnsflow

install: dnsflow
	@install -cv dnsflow /usr/local/sbin/

ubuntu-install: install
	@install -cv init/dnsflow /etc/init.d/
	@install -cv default/dnsflow /etc/default/
	@update-rc.d dnsflow start 20 2 3 4 5 . stop 99 0 1 6 .
