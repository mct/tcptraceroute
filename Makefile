# tcptraceroute -- A traceroute implementation using TCP packets
# Copyright (c) 2001, Michael C. Toren <michael@toren.net>

CC = gcc
CFLAGS = -O2 -Wall

tcptraceroute: tcptraceroute.c
	$(CC) $(CFLAGS) `libnet-config --defines` \
		-o tcptraceroute tcptraceroute.c \
		`libnet-config --libs` -lpcap

static:
	$(MAKE) tcptraceroute CFLAGS="$(CFLAGS) -static"

clean:
	rm -f core a.out tcptraceroute
