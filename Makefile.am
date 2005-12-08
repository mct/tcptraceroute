bin_PROGRAMS = tcptraceroute
tcptraceroute_SOURCES = main.c datalink.c util.c probe.c capture.c
man_MANS = tcptraceroute.1

docdir = $(datadir)/doc/tcptraceroute
doc_DATA = AUTHORS COPYING ChangeLog NEWS README \
	examples.txt tcptraceroute.1.html tcptraceroute.lsm

EXTRA_DIST = $(doc_DATA) $(man_MANS) VERSION debian

# AM_CFLAGS = @AM_CFLAGS@

