AC_INIT(dnsflow-tools, 0.1, mkarir@merit.edu jkrez@merit.edu)
AC_CONFIG_SRCDIR(./src)
AC_PREREQ(2.57)
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS(config.h)

AC_PROG_CC
AC_STDC_HEADERS
AC_PROG_INSTALL
#AM_PROG_LIBTOOL

AC_C_CONST
AC_CHECK_HEADERS(limits.h unistd.h)

# check for glib (needed by both client and server)
PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.6, AC_MSG_RESULT([found]), AC_MSG_ERROR([glib-2.0 >= 2.6 not found]))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

# check for libpcap (needed by both client and server)
AC_CHECK_LIB(pcap, bpf_validate, PCAP_LIBS="-lpcap", AC_MSG_ERROR([libpcap not found]))
AC_SUBST(PCAP_LIBS)

# check fo libpq
AC_CHECK_HEADER(postgresql/libpq-fe.h, AC_CHECK_LIB(pq, PQconnectdb, PQ_LIBS="-lpq", AC_MSG_ERROR([libpq not found])),  AC_MSG_ERROR([libpq not found]))
AC_SUBST(PQ_LIBS)

AC_OUTPUT([Makefile src/Makefile])
