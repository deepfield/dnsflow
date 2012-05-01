AM_CFLAGS =		-g3 -O0 -Wall

INCLUDES =		-I$(top_srcdir)/include $(GLIB_CFLAGS) $(PQ_CFLAGS)

bin_PROGRAMS =		dnsflow-print dnsflow-capture dnsflow-filter dnsflow-fanout dnsflow-cat dnsflow-todb

dnsflow_print_SOURCES =		dnsflow-common.c dnsflow-print.c 

dnsflow_print_LDADD =		$(GLIB_LIBS) -lm -lpcap

dnsflow_capture_SOURCES =	dnsflow-common.c dnsflow-capture.c

dnsflow_capture_LDADD=		$(GLIB_LIBS)-lglib-2.0 -lm -lpcap

dnsflow_filter_SOURCES =	dnsflow-common.c dnsflow-filter.c 

dnsflow_filter_LDADD =		$(GLIB_LIBS) -lglib-2.0 -lm -lpcap

dnsflow_fanout_SOURCES =	dnsflow-common.c dnsflow-fanout.c

dnsflow_fanout_LDADD =		$(GLIB_LIBS) -lglib-2.0 -lm -lpcap

dnsflow_cat_SOURCES =		dnsflow-common.c dnsflow-cat.c

dnsflow_cat_LDADD =		$(GLIB_LIBS) -lglib-2.0 -lm -lpcap

dnsflow_todb_SOURCES =		dnsflow-common.c dnsflow-todb.c

dnsflow_todb_LDADD =             $(GLIB_LIBS) -lm -lpcap -lpq
