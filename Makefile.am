
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = @deps_CFLAGS@
LDADD = @deps_LIBS@

libslip_sources = libslip.c libslip.h libslip_types.h

lib_LTLIBRARIES = libslip.la
libslip_la_SOURCES = $(libslip_sources)

noinst_PROGRAMS = slipcat libslip-test

check_PROGRAMS = libslip-test

libslip_test_SOURCES = libslip-test.c $(libslip_sources)
libslip_test_CFLAGS = $(AM_CFLAGS)

slipcat_SOURCES = slipcat.c slipcat.h $(libslip_sources)
slipcat_CFLAGS = $(AM_CFLAGS)

TESTS = \
	tests/slip-01.txt \
	tests/slip-02.txt \
	tests/slip-03.txt

LOG_COMPILER = tests/test-wrapper.sh

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 compile configure config.guess config.sub depcomp missing \
	install-sh ltmain.sh test-driver cscope.out *~ .*~ core

maintainer-clean-local:
	-rm -rf m4
