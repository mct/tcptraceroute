# vim:set ts=4 sw=4 ai:

# tcptraceroute -- A traceroute implementation using TCP packets
# Copyright (c) 2001, 2002 Michael C. Toren <mct@toren.net>

CC = gcc
CFLAGS = -O2 -Wall
DESTDIR=/usr/local/bin

tcptraceroute: tcptraceroute.c
	$(CC) $(CFLAGS) `libnet-config --defines` \
		-o tcptraceroute tcptraceroute.c \
		`libnet-config --libs` -lpcap

6:
	$(MAKE) CFLAGS="$(CFLAGS) -L/usr/local/pkg/libpcap-0.6.2/lib -I/usr/local/pkg/libpcap-0.6.2/include"

7:
	$(MAKE) CFLAGS="$(CFLAGS) -L/usr/local/pkg/libpcap-0.7.1/lib -I/usr/local/pkg/libpcap-0.7.1/include"

static:
	$(MAKE) tcptraceroute CFLAGS="$(CFLAGS) -static"

install: tcptraceroute
	install -D tcptraceroute $(DESTDIR)/tcptraceroute

distrib: clean changelog man

changelog: tcptraceroute.c Makefile
	perl -000 -ne 'next unless (/\*\s+Revision\s+history:/); \
		print "Extracted from tcptraceroute.c:\n\n$$_"; exit;' \
		< tcptraceroute.c | expand -t 4 > changelog

man: tcptraceroute.8.html Makefile
tcptraceroute.8.html: tcptraceroute.8
	rman -fHTML -r- tcptraceroute.8 > tcptraceroute.8.html

clean:
	rm -f core a.out tcptraceroute *~
