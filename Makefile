# tcptraceroute -- A traceroute implementation using TCP packets
# Copyright (c) 2001, Michael C. Toren <mct@toren.net>

CC = gcc
CFLAGS = -O2 -Wall
DESTDIR=/usr/local/bin

tcptraceroute: tcptraceroute.c
	$(CC) $(CFLAGS) `libnet-config --defines` \
		-o tcptraceroute tcptraceroute.c \
		`libnet-config --libs` -lpcap

static:
	$(MAKE) tcptraceroute CFLAGS="$(CFLAGS) -static"

install: tcptraceroute
	install -D tcptraceroute $(DESTDIR)/tcptraceroute

distrib: clean changelog man

clean:
	rm -f core a.out tcptraceroute *~

changelog: tcptraceroute.c Makefile
	perl -000 -ne 'next unless (/\*\s+Revision\s+history:/); \
		print "Extracted from tcptraceroute.c:\n\n$$_"; exit;' \
		< tcptraceroute.c | expand -t 4 > changelog

man: tcptraceroute.8.html Makefile
tcptraceroute.8.html: tcptraceroute.8
	rman -fHTML -r- tcptraceroute.8 > tcptraceroute.8.html