/* -*- Mode: c; tab-width: 4; indent-tabs-mode: 1; c-basic-offset: 4; -*- */
/* vim:set ts=4 sw=4 ai nobackup nocindent sm: */

/*
 * tcptraceroute -- A traceroute implementation using TCP packets
 * Copyright (c) 2001-2006  Michael C. Toren <mct@toren.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2, as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * A copy of the GNU GPL is available as /usr/doc/copyright/GPL on Debian
 * systems, or on the World Wide Web at http://www.gnu.org/copyleft/gpl.html
 * You can also obtain it by writing to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "tcptraceroute.h"

#if (LIBNET_API_VERSION < 110)
	int sockfd;
#else
	libnet_t *libnet_context;
#endif

/*
 * Initialize the libnet library context.
 */

void initlibnet(void)
{
#if (LIBNET_API_VERSION >= 110)
	libnet_context = libnet_init(LIBNET_RAW4, NULL, errbuf);
	if (libnet_context == NULL)
		fatal("libnet_init() failed: %s\n", errbuf);
#else
	/* Nothing to do for libnet-1.0 */
#endif
	return;
}

/*
 * Allocates memory for a new proberecord structure.
 */

proberecord *newproberecord(void)
{
	proberecord *record;

	record = xrealloc(NULL, sizeof(proberecord));
	record->state = xrealloc(NULL, TEXTSIZE);
	record->string = xrealloc(NULL, TEXTSIZE);
	return record;
}

/*
 * Destroys a proberecord structure, carefully, as not to leak memory.
 */

void freeproberecord(proberecord *record)
{
	if (record->string)
		free(record->string);

	if (record->state)
		free(record->state);

	free(record);
}

/*
 * Request a local unused TCP port from the kernel using bind(2)
 */

u_short allocateport(u_short requested)
{
	struct sockaddr_in in;
	int	s, insize;

	if ((s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		pfatal("socket error");

	insize = sizeof(in);
	memset(&in, 0, insize);

	in.sin_family = AF_INET;
	in.sin_port = htons(requested);

	if ((bind(s, (struct sockaddr *)&in, insize)) < 0)
		return 0;

	if ((getsockname(s, (struct sockaddr *)&in, &insize)) < 0)
		pfatal("getsockname");

	close(s);
	return ntohs(in.sin_port);
}

/*
 * Allocate an IP ID from our pool of unallocated ID's.  A cache is kept of
 * the last ALLOCATEID_CACHE_SIZE allocations, so we can check for duplicates.
 */

u_short allocateid(void)
{
	static u_short ids[ALLOCATEID_CACHE_SIZE];
	static int n;
	int i, j;

	if ((n = n % ALLOCATEID_CACHE_SIZE) == 0)
	{
		debug("Generating a new batch of %d IP ID's\n", ALLOCATEID_CACHE_SIZE);

		for(i = 0; i < ALLOCATEID_CACHE_SIZE; i++)
		{
			for(ids[i] = libnet_get_prand(LIBNET_PRu16), j = i + 1; j < ALLOCATEID_CACHE_SIZE + i; j++)
				if (ids[i] == ids[j % ALLOCATEID_CACHE_SIZE])
					ids[i] = libnet_get_prand(LIBNET_PRu16), j = i + 1;
		}
	}

	return ids[n++];
}

/*
 * Sends out a TCP SYN packet with the specified TTL, and returns a
 * proberecord structure describing the packet sent, so we know what
 * to listen for later.  A new IP ID is generated for each probe, and
 * a new source port if o_trackport is specified.
 */

void probe(proberecord *record, int ttl, int q)
{
	static u_char *payload;
	int i, size, ret;

#if (LIBNET_API_VERSION < 110)
	static u_char *buf;
#else
	static libnet_ptag_t ip_tag, tcp_tag, data_tag;
#endif

	size = LIBNET_IPV4_H + LIBNET_TCP_H + o_pktlen;

#if (LIBNET_API_VERSION < 110)
	if (!buf)
	{
		debug("Initializing packet buffer of %d bytes\n", size);
		buf = xrealloc(buf, size);
	}

	else
		memset(buf, 0, size);
#endif

	/* Initialize the packet payload */
	if (o_pktlen && !payload)
	{
		debug("Initializing payload of %d bytes\n", o_pktlen);
		payload = xrealloc(payload, o_pktlen);

		for(i = 0; i < o_pktlen; i++)
			payload[i] = i % ('~' - '!') + '!';

		debug("Payload: %s\n", sprintable((char *)payload));
	}

	/* Set some values of the probe record */
	record->q = q;
	record->ttl = ttl;
	record->addr = INADDR_ANY;
	record->dnat_ip = INADDR_ANY;
	record->src_prt = src_prt;
	record->id = allocateid();
	record->delta = 0;

	if (o_trackport)
	{
		record->src_prt = allocateport(0);
		if (record->src_prt == 0)
			pfatal("Could not allocate local port: bind");
	}

	if (gettimeofday(&(record->timestamp), NULL) < 0)
		pfatal("gettimeofday");

	/* Build the packet, and send it off into the cold, cruel world */

#if (LIBNET_API_VERSION < 110)
	libnet_build_ip(
		LIBNET_TCP_H+o_pktlen,	/* len			*/
		o_tos,					/* tos			*/
		record->id,				/* id			*/
		o_dontfrag ? IP_DF : 0,	/* frag			*/
		ttl,					/* ttl			*/
		IPPROTO_TCP,			/* proto		*/
		src_ip,					/* saddr		*/
		dst_ip,					/* daddr		*/
		NULL,					/* data			*/
		0,						/* datasize?	*/
		buf);					/* buffer		*/

	libnet_build_tcp(
		record->src_prt,		/* source port	*/
		dst_prt,				/* dest port	*/
		isn,					/* seq number	*/
		0,						/* ack number	*/

		(o_syn ? TH_SYN : 0) |
		(o_ack ? TH_ACK : 0) |
		(o_ecn ? TH_CWR|TH_ECN : 0), /* control	*/

		0,						/* window		*/
		0,						/* urgent?		*/
		payload,				/* data			*/
		o_pktlen,				/* datasize		*/
		buf + LIBNET_IPV4_H);	/* buffer		*/

	libnet_do_checksum(buf, IPPROTO_TCP, LIBNET_TCP_H + o_pktlen);

	/* Write */
	if ((ret = libnet_write_ip(sockfd, buf, size)) < size)
		fatal("libnet_write_ip failed?  Attempted to write %d bytes, only wrote %d\n",
			  size, ret);
#else

	/* Add the payload */
	data_tag = libnet_build_data(payload, o_pktlen, libnet_context, data_tag);

	if (data_tag < 0)
		fatal("Can't add payload: %s\n", libnet_geterror(libnet_context));

	/* Add the TCP header */
	tcp_tag = libnet_build_tcp(
		record->src_prt,		     /* source port	        */
		dst_prt,				     /* dest port	        */
		isn,					     /* seq number	        */
		0,						     /* ack number	        */
		
		(o_syn ? TH_SYN : 0) |
		(o_ack ? TH_ACK : 0) |
		(o_ecn ? TH_CWR|TH_ECN : 0), /* control	            */

		0,						     /* window		        */
		0,                           /* checksum TBD        */
		0,						     /* urgent?	            */
		LIBNET_TCP_H + o_pktlen,     /* TCP PDU size        */
		NULL,				         /* data		        */
		0,	          			     /* datasize	        */
		libnet_context,              /* libnet context      */
		tcp_tag);                    /* libnet protocol tag */

	if (tcp_tag < 0)
		fatal("Can't build TCP header: %s\n", libnet_geterror(libnet_context));

	/* Add the IP header */
	ip_tag = libnet_build_ipv4(
		size,	                /* total packet len	   */
		o_tos,					/* tos			       */
		record->id,				/* id			       */
		o_dontfrag ? IP_DF : 0,	/* frag			       */
		ttl,					/* ttl			       */
		IPPROTO_TCP,			/* proto		       */
		0,                      /* checksum TBD        */
		src_ip,					/* saddr		       */
		dst_ip,					/* daddr		       */
		NULL,    				/* data			       */
		0,      				/* datasize?	       */
		libnet_context,         /* libnet context      */
		ip_tag);                /* libnet protocol tag */

	if (ip_tag < 0)
		fatal("Can't build IP header: %s\n", libnet_geterror(libnet_context));
	
	/* Write */
	if ((ret = libnet_write(libnet_context)) < size)
		fatal("libnet_write failed?  Attempted to write %d bytes, only wrote %d\n",
			  size, ret);
#endif
}

/* 
 * A mess of a function, but it works.  The aim is to be as compatible as
 * possible with traceroute(8), with the one exception that if for the same hop
 * we receive a response from two different hosts, display the second host on a
 * new line, as Cisco does.  This drastically improves readability when tracing
 * through links which have per-packet, round-robin load balancing.
 */

void showprobe(proberecord *record)
{
	/* Variables to keep state between calls */
	static char laststate[TEXTSIZE];
	static int lastttl;
	static u_long lastaddr, lastdnat_ip;
	static u_short lastdnat_dport;

	static int everprinthost;	// have we ever printed the hostname?
	int printhost = 0;			// should we print the hostname this time?

	/* kludge to make debug mode usable */
	if (o_debug)
	{
		fflush(stdout);
		fprintf(stderr, "debug: displayed hop\n");
		fflush(stderr);
	}

	/* print the DNAT line */
	if ((lastdnat_ip != record->dnat_ip && record->dnat_ip != INADDR_ANY)
		|| (lastdnat_dport != record->dnat_dport && record->dnat_dport != 0))
	{
		/* If lastttl != record->ttl, we're already on a newline */
		if (lastttl == record->ttl)
			printf("\n");

		printf("      Detected DNAT to %s", iptos(record->dnat_ip));
		if (record->dnat_dport)
			printf(":%d", ntohs(record->dnat_dport));
		printf("\n");

		/* Only print the leading four spaces if this is not the start of a new hop */
		if (lastttl == record->ttl)
			printf("    ");

		lastdnat_ip = record->dnat_ip;
		lastdnat_dport = record->dnat_dport;
		printhost = 1;
	}

	/* ttl */
	if (lastttl != record->ttl)
	{
		printf("%2d  ", record->ttl);
		printhost = 1;
		everprinthost = 0;
		safe_strncpy(laststate, "", TEXTSIZE);
	}
	else if (lastaddr != record->addr && record->addr != INADDR_ANY && lastaddr != INADDR_ANY)
	{
		printf("\n    ");
		printhost = 1;
	}

	/* host */
	if ((printhost || !everprinthost) && record->addr != INADDR_ANY)
	{
		char buf[TEXTSIZE];

		if (record->q > 1 && lastaddr == INADDR_ANY)
			printf(" ");

		printf("%s", iptohost(record->addr));

		safe_strncpy(buf, iptohost(record->addr), TEXTSIZE);
		if (strncmp(buf, iptos(record->addr), IPTOSBUFSIZ) != 0)
			printf(" (%s)", iptos(record->addr));

		everprinthost = 1;
	}

	/* tcp state */
	if ( ((record->ttl != lastttl) && *(record->state)) ||
		((record->ttl == lastttl) && *(record->state) && (strncmp(laststate, record->state, TEXTSIZE) != 0)))
	{
		printf(" [%s]", record->state);
	}

	/* space before ms */
	if (! (record->addr == INADDR_ANY && record->q == 1))
	{
		/* if timeout, only print one space. otherwise, two */
		if ((record->addr == INADDR_ANY) || (lastaddr == INADDR_ANY && record->q > 1))
			printf(" ");
		else
			printf("  ");
	}

	if (record->addr == INADDR_ANY)
		safe_strncpy(record->string, "*", TEXTSIZE);
	
	if (! record->string)
		fatal("something bad happened\n");

	printf(record->string, record->delta);

	/* If this will be the last probe, print the newline */
	if (record->q == o_nqueries)
		printf("\n");

	lastttl = record->ttl;
	lastaddr = record->addr;
	if (*(record->state))
		safe_strncpy(laststate, record->state, TEXTSIZE);

	/* kludge to make debug mode usable */
	if (o_debug)
		fprintf(stdout, "\n");
	if (o_debug && record->q != o_nqueries)
		fprintf(stdout, "\n");

	fflush(stdout);
}
