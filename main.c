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

/* globals */
u_long dst_ip, src_ip, isn;
u_short src_prt, dst_prt;
char *device, *name, *dst, *src;
char dst_name[TEXTSIZE], dst_prt_name[TEXTSIZE], filter[TEXTSIZE];
int datalink, offset;
int o_minttl, o_maxttl, o_timeout, o_debug, o_numeric, o_pktlen,
	o_nqueries, o_dontfrag, o_tos, o_forceport, o_syn, o_ack, o_ecn,
	o_nofilter, o_nogetinterfaces, o_noselect, o_trackport, o_dnat,
	o_isn;

char errbuf [PCAP_ERRBUF_SIZE > LIBNET_ERRBUF_SIZE ?
			 PCAP_ERRBUF_SIZE : LIBNET_ERRBUF_SIZE];

/*
 * Check command line arguments for sanity, and fill in the blanks.
 */

void defaults(void)
{
	struct servent *serv;
	u_long recommended_src;

	getinterfaces();

	if ((dst_ip = hosttoip(dst, LIBNET_RESOLVE)) == 0xFFFFFFFF)
		fatal("Bad destination address: %s\n", dst);

	recommended_src = findsrc(dst_ip);

	if (src)
	{
		if ((src_ip = hosttoip(src, LIBNET_RESOLVE)) == 0xFFFFFFFF)
			fatal("Bad source address: %s\n", src);
	}
	else
	{
		src_ip = recommended_src;
	}

	if (device == NULL)
		/* not specified on command line */
		device = finddev(recommended_src);

	if (device == NULL)
	{
		/* couldn't find an appropriate interface */
		warn("Could not determine appropriate device; resorting to pcap_lookupdev()\n");
		device = pcap_lookupdev(errbuf);
	}

	if (device == NULL)
		fatal("Could not determine device via pcap_lookupdev(): %\n", errbuf);

	if ((pcap = pcap_open_live(device, 0, 0, 0, errbuf)) == NULL)
		fatal("error opening device %s: %s\n", device, errbuf);

	datalink = pcap_datalink(pcap);
	offset = datalinkoffset(datalink);

	if (offset < 0)
		fatal("Sorry, media type of device %s (%s) is not supported\n",
			device, datalinkname(datalink));

	pcap_close(pcap);

	if (src_prt && o_trackport)
	{
		warn("--track-id implied by specifying the local source port\n");
		o_trackport = 0;
	}

	if (! o_trackport)
	{
#ifdef HAVE_SOLARIS
		warn("--track-id is unlikely to work on Solaris\n");
#endif

		if (! o_forceport)
			src_prt = allocateport(src_prt);

		if (src_prt == 0)
			fatal("Sorry, requested local port is already in use.  Use -P, instead of -p, to override.\n");
	}

	if (o_minttl <= 0 || o_maxttl <= 0)
		fatal("TTL must be greater than 0\n");

	if (o_minttl >= 256 || o_maxttl >= 256)
		fatal("TTL must be less than 256\n");

	if (o_minttl > o_maxttl)
		fatal("Minimum TTL (%d) must be less than maximum TTL (%d)\n",
			o_minttl, o_maxttl);

	if (o_nqueries <= 0)
		fatal("Number of queries must be at least 1\n");

	if (o_timeout <= 0)
		fatal("Timeout must be at least 1\n");

	if (o_pktlen < LIBNET_TCP_H + LIBNET_IPV4_H)
	{
		if (o_pktlen != 0)
			warn("Increasing packet length to %d bytes\n", LIBNET_TCP_H + LIBNET_IPV4_H);
		o_pktlen = 0;
	}
	else
		o_pktlen -= (LIBNET_TCP_H + LIBNET_IPV4_H);

#if (LIBNET_API_VERSION < 110)
	if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) < 0)
		pfatal("socket allocation");
#endif

#if (LIBNET_API_VERSION < 110)
	libnet_seed_prand();
#else
	libnet_seed_prand(libnet_context);
#endif

	if (strcmp(dst, iptos(dst_ip)) == 0)
		safe_snprintf(dst_name, TEXTSIZE, "%s", dst);
	else
		safe_snprintf(dst_name, TEXTSIZE, "%s (%s)", dst, iptos(dst_ip));

	if ((serv = getservbyport(htons(dst_prt), "tcp")) == NULL)
		safe_snprintf(dst_prt_name, TEXTSIZE, "%d", dst_prt);
	else
		safe_snprintf(dst_prt_name, TEXTSIZE, "%d (%s)", dst_prt, serv->s_name);

	if (! (o_syn|o_ack))
	{
		debug("Setting o_syn, in absence of either o_syn or o_ack\n");
		o_syn = 1;
	}

	if (! o_isn)
		isn = libnet_get_prand(LIBNET_PRu32);

	debugoptions();

	fprintf(stderr, "Selected device %s, address %s", device, iptos(src_ip));
	if (! o_trackport) fprintf(stderr, ", port %d", src_prt);
	fprintf(stderr, " for outgoing packets\n");
}

int trace(void)
{
	int ttl, q, done;
	proberecord *record;

	fprintf(stderr, "Tracing the path to %s on TCP port %s, %d hops max",
		dst_name, dst_prt_name, o_maxttl);
	if (o_pktlen)
		fprintf(stderr, ", %d byte packets", o_pktlen + LIBNET_TCP_H + LIBNET_IPV4_H);
	fprintf(stderr, "\n");

	for (ttl = o_minttl, done = 0; !done && ttl <= o_maxttl; ttl++)
	{
		for (q = 1; q <= o_nqueries; q++)
		{
			record = newproberecord();
			probe(record, ttl, q);

			debug("Sent probe %d of %d for hop %d, IP ID %d, source port %d, %s%s%s\n",
				q, o_nqueries, ttl, record->id, record->src_prt,
				o_syn ? "SYN " : "",
				o_ack ? "ACK " : "",
				o_ecn ? "CWR ECN " : "");

			if (capture(record))
				done = 1;

			showprobe(record);
			freeproberecord(record);
		}
	}

	if (!done)
		fprintf(stderr, "Destination not reached\n");

	return !done;
}

/*
 * Verify a command line argument is numeric; only to be called from main().
 */

int checknumericarg(void)
{
	if (! isnumeric(optarg))
		fatal("Numeric argument required for -%c\n", optopt);

	return atoi(optarg);
}

/*
 * A kludge to help us process long command line arguments, only to be called
 * using the CHECKLONG() macro, and only from main().  If the given word
 * matches the current word being processed, it's removed from the argument
 * list, and returns 1.
 */

#define CHECKLONG(word) ( checklong_real(word, &i, &argc, &argv) )
int checklong_real(char *word, int *i, int *argc, char ***argv)
{
	int j;

	if (strcmp((*argv)[*i], word) != 0)
		return 0;

	/* shift */
	for (j = *i; (*argv)[j]; j++)
		(*argv)[j] = (*argv)[j+1];

	(*argc)--;
	(*i)--;

	return 1;
}

int main(int argc, char **argv)
{
	char *optstring, *s;
	int op, i, exitcode;

	src_ip	= 0;
	src_prt = 0;
	dst_prt	= DEFAULT_PORT;
	src		= NULL;
	device	= NULL;
	interfaces = NULL;

	o_minttl = 1;
	o_maxttl = 30;
	o_debug	= 0;
	o_numeric = 0;
	o_nqueries = 3;
	o_forceport = 0;
	o_pktlen = 0;
	o_tos	= 0;
	o_ecn	= 0;
	o_syn	= 0;
	o_ack	= 0;
	o_dontfrag = 0;
	o_timeout = 3;
	o_nofilter = 0;
	o_nogetinterfaces = 0;
	o_dnat = 0;
	o_isn = 0;

#ifdef NOSELECT_DEFAULT
	o_noselect = 1;
#else
	o_noselect = 0;
#endif

#ifdef TRACK_PORT_DEFAULT
	o_trackport = 1;
#else
	o_trackport = 0;
#endif

	/* strip out path from argv[0] */
	for (name = s = argv[0]; s[0]; s++)
		if (s[0] == '/' && s[1])
			name = &s[1];
	
	/* First loop through and extract long command line arguments ... */

	for(i = 1; argv[i]; i++)
	{
		if (CHECKLONG("--help"))
			usage();

		if (CHECKLONG("--version"))
			about();

		/* undocumented, for debugging only */
		if (CHECKLONG("--no-filter"))
		{
			o_nofilter = 1;
			debug("o_nofilter set\n");
			continue;
		}

		/* undocumented, for debugging only */
		if (CHECKLONG("--no-getinterfaces"))
		{
			o_nogetinterfaces = 1;
			debug("o_nogetinterfaces set\n");
			continue;
		}

		/* undocumented, for debugging only */
		if (CHECKLONG("--no-select"))
		{
			o_noselect = 1;
			debug("o_noselect set\n");
			continue;
		}

		/* undocumented, for debugging only */
		if (CHECKLONG("--select"))
		{
			o_noselect = 0;
			debug("o_noselect disabled\n");
			continue;
		}

		if (CHECKLONG("--track-id") ||
			CHECKLONG("--track-ipid"))
		{
			o_trackport = 0;
			debug("o_trackport disabled\n");
			continue;
		}

		if (CHECKLONG("--track-port"))
		{
			o_trackport = 1;
			debug("o_trackport set\n");
			continue;
		}

		if (CHECKLONG("--dnat"))
		{
			o_dnat = 1;
			debug("o_dnat set\n");
			continue;
		}

		if (CHECKLONG("--no-dnat"))
		{
			o_dnat = 0;
			debug("o_dnat unset\n");
			continue;
		}

		if (CHECKLONG("--no-dnat-strict"))
		{
			o_dnat = -1;
			debug("o_dnat set to -1\n");
			continue;
		}

		/* One day, when our command line argument processing is improved,
		 * and we CHECKLONG() can take optional or required arguments... */
		/*
		if (CHECKLONG("--isn"))
		{
			o_isn = 1;
			isn = // XXX
			debug("o_dnat set to -1\n");
			continue;
		}
		*/

		if (strcmp(argv[i], "--") == 0)
			break;

		if (argv[i][0] == '-' && argv[i][1] == '-')
		{
			fprintf(stderr, "Unknown command line argument: %s\n", argv[i]);
			usage();
		}
	}

	/* ... then handoff to getopt() */

	opterr = 0;
	optstring = "hvdnNi:l:f:Fm:P:p:q:w:s:t:SAE";

	while ((op = getopt(argc, argv, optstring)) != -1)
		switch(op)
		{
			case 'h':
				usage();

			case 'v':
				about();

			case 'd':
				o_debug++;
				debug("%s %s, %s\n", PACKAGE, VERSION, TARGET);
				debug("Compiled with libpcap %s, libnet %s (API %d)\n",
					pcap_version, LIBNET_VERSION, LIBNET_API_VERSION);
				break;

			case 'n':
				o_numeric = 1;
				debug("o_numeric set to 1\n");
				break;

			case 'N':
				o_numeric = -1;
				debug("o_numeric set to -1\n");
				break;

			case 'i': /* ARG */
				device = optarg;
				debug("device set to %s\n", device);
				break;

			case 'l': /* ARG */
				o_pktlen = checknumericarg();
				debug("o_pktlen set to %d\n", o_pktlen);
				break;

			case 'f': /* ARG */
				o_minttl = checknumericarg();
				debug("o_minttl set to %d\n", o_minttl);
				break;

			case 'F':
				o_dontfrag = 1;
				debug("o_dontfrag set\n");
				break;

			case 'm': /* ARG */
				o_maxttl = checknumericarg();
				debug("o_maxttl set to %d\n", o_maxttl);
				break;

			case 'P': /* ARG */
				o_forceport = 1;
			case 'p': /* ARG */
				if (getuid()) fatal("Sorry, must be root to use -p\n");
				src_prt = checknumericarg();
				debug("src_prt set to %d\n", src_prt);
				break;

			case 'q': /* ARG */
				o_nqueries = checknumericarg();
				debug("o_nqueries set to %d\n", o_nqueries);
				break;

			case 'w': /* ARG */
				o_timeout = checknumericarg();
				debug("o_timeout set to %d\n", o_timeout);
				break;

			case 's': /* ARG */
				if (getuid()) fatal("Sorry, must be root to use -s\n");
				src = optarg;
				break;

			case 't': /* ARG */
				o_tos = checknumericarg();
				debug("o_tos set to %d\n", o_tos);
				break;

			case 'S':
				o_syn = 1;
				debug("o_syn set\n");
				break;

			case 'A':
				o_ack = 1;
				debug("o_ack set\n");
				break;

			case 'E':
				o_ecn = 1;
				debug("o_ecn set\n");
				break;

			case '?':
			default:
				if (optopt != ':' && strchr(optstring, optopt))
					fatal("Argument required for -%c\n", optopt);
				fprintf(stderr, "Unknown command line argument: -%c\n", optopt);
				usage();
		}

	argc -= optind;
	argv += optind;

	switch(argc - 1)
	{
		case 2:
			o_pktlen = atoi(argv[2]);

		case 1:
			if (isnumeric(argv[1]))
			{
				dst_prt = atoi(argv[1]);
			}
			else
			{
				struct servent *serv;

				if ((serv = getservbyname(argv[1], "tcp")) == NULL)
					fatal("Unknown port: %s\n", argv[1]);

				dst_prt = ntohs(serv->s_port);
			}

		case 0:
			dst = argv[0];
			break;

		default:
			usage();
	}

	if (getuid() & geteuid())
		fatal("Got root?\n");

	initlibnet();
	defaults();
	initcapture();
	setuid(getuid());
	exitcode = trace();
#if (LIBNET_API_VERSION >= 110)
	libnet_destroy(libnet_context);
#endif
	return exitcode;
}
