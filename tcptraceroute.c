/* vim:set ts=4 sw=4 ai nobackup nocindent: */

/*
 * tcptraceroute -- A traceroute implementation using TCP
 * Copyright (c) 2001, Michael C. Toren <michael@toren.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
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

/*
 * Revision history:
 *
 *		Version 1.0 (2001-04-10)		Initial Release
 *
 * Updates are available from http://michael.toren.net/code/tcptraceroute/
 */

/*
 * Requires libnet (http://www.packetfactory.net/libnet) and libpcap
 * (http://www.tcpdump.org/).  To compile, try something like:
 *
 *	gcc -O2 -Wall `libnet-config --defines` \
 *		-o tcptraceroute tcptraceroute.c `libnet-config --libs` -lpcap
 */

/*
 * TODO:
 *
 * - There needs to be a better way to detect a timeout from pcap_next()
 * - Add support for sending more than one probe
 * - The size of the packets returned by libpcap should be checked before
 *   assuming that the entire header structure is there.
 */

#define VERSION "tcptraceroute 1.0 (2001-04-10)"
#define BANNER  "\
Copyright (c) 2001, Michael C. Toren <michael@toren.net>
Updates are available from http://michael.toren.net/code/tcptraceroute/
"

#include <libnet.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>

/* Buffer size used for a few strings, including the pcap filter */
#define TEXTSIZE	1024

/*
 * How many bytes should we examine on every packet that comes off the
 * wire?  This doesn't include the link layer, which is accounted for
 * later.  We're looking only for ICMP and TCP packets, so this should
 * work.  For ICMP, we also examine the quoted IP header, which is why
 * there's a *2 there.  The +32 is just to be safe.
 */

#define SNAPLEN	 (LIBNET_IP_H * 2 + \
	(LIBNET_TCP_H > LIBNET_ICMP_H ? LIBNET_TCP_H : LIBNET_ICMP_H) + 32)

/* pcap error buffer */
char errbuf[PCAP_ERRBUF_SIZE];

/* various globals */
u_long dst_ip, src_ip;
u_short src_prt, dst_prt;
int	sockfd, datalink, offset, minttl, maxttl, timeout;
int o_debug, o_numeric;
char *device, *name, *dst, *src;
char dst_name[TEXTSIZE+1], dst_prt_name[TEXTSIZE+1], filter[TEXTSIZE+1];
pcap_t *pcap;
u_char *buf;
struct timeval t1, t2;

/*
 * fatal() and pfatal() are useful stdarg functions from namp.  debug() is
 * based on them.
 */

void fatal(char *fmt, ...)
{
	va_list ap;
	fflush(stdout);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	exit(1);
}

void pfatal(char *err)
{
	fflush(stdout);
	perror(err);
	exit(1);
}

void debug(char *fmt, ...)
{
	va_list ap;
	if (! o_debug) return;
	fflush(stdout);
	fprintf(stderr, "debug: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
}

void usage(void)
{
	printf("\n%s\n%s\n", VERSION, BANNER);
	fatal("Usage: %s [-n] [-i <interface>] [-f <first ttl>]
	[-m <max ttl>] [-p <source port>] [-s <source address>]
	[-w <wait time>] <host> [destination port]\n\n", name);
}

void about(void)
{
	printf("\n%s\n%s\n", VERSION, BANNER);
	exit(0);
}

/*
 * Inspired by libnet_host_lookup(), but I needed more than 2 buffers while
 * I was debugging.  I really could get by with only 2 now, but *shrug*.
 */

#define IPTOSBUFFERS	12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

/*
 * A wrapper for libnet_host_lookup() which doesn't attempt to resolve
 * RFC1918 space.  If you don't want this feature, compile with RESOLVE_1918
 * defined.
 */

char *iptohost(u_long in)
{
	u_char *p = (u_char *)&in;

#ifndef RESOLVE_1918
	/* Don't attempt to resolve RFC1918 space */
	if ((p[0] == 10) ||
		(p[0] == 192 && p[1] == 168) ||
		(p[0] == 172 && p[1] >= 16 && p[1] <= 31))
	{
		debug("Not attempting to resolve RFC1918 address %s\n", iptos(in));
		return iptos(in);
	}
#endif

	return libnet_host_lookup(in, ~o_numeric & 1);
}

/*
 * To add support for additional link layers, add entries to datalinkoffset()
 * and datalinkname().  The numbers I have in here now I believe are correct,
 * and were obtained by looking through other pcap programs, however I've
 * only tested tcptraceroute on ethernet interfaces.
 */

int datalinkoffset(int type)
{
	switch (type)
	{
		case DLT_EN10MB:		return 14;
		case DLT_PPP:			return 4;
		case DLT_PPP_BSDOS:		return 24;
		case DLT_SLIP:			return 16;
		case DLT_SLIP_BSDOS:	return 24;
		case DLT_FDDI:			return 21;
		case DLT_IEEE802:		return 22;
		case DLT_RAW:			return 0;
		default:				return -1;
	}
}

char *datalinkname(int type)
{
	switch (type)
	{
		case DLT_EN10MB:		return "ETHERNET";
		case DLT_SLIP:			return "SLIP";
		case DLT_SLIP_BSDOS:	return "SLIP_BSDOS";
		case DLT_PPP:			return "PPP";
		case DLT_PPP_BSDOS:		return "PPP_BSDOS";
		case DLT_FDDI:			return "FDDI";
		case DLT_IEEE802:		return "IEEE802";
		case DLT_ATM_RFC1483:	return "ATM";
		case DLT_RAW:			return "RAW";
		default:				return "UNKNOWN";
	}
}

/*
 * Check command line arguments for sanity, and fill in the blanks.
 */

void defaults(void)
{
	struct libnet_link_int l;
	struct protoent *proto;
	struct sockaddr_in in;
	struct servent *serv;
	int insize;

	if (device == NULL)
		if ((device = pcap_lookupdev(errbuf)) == NULL)
			fatal("Could not determine device: %\n", errbuf);

	if ((pcap = pcap_open_live(device, 0, 0, 0, errbuf)) == NULL)
		fatal("error opening device %s: %s\n", device, errbuf);

	datalink = pcap_datalink(pcap);
	offset = datalinkoffset(datalink);

	if (offset < 0)
		fatal("Sorry, media type of device %s (%s) is not supported\n",
			device, datalinkname(datalink));

	pcap_close(pcap);

	if ((dst_ip = libnet_name_resolve(dst, 1)) == 0xFFFFFFFF)
		fatal("Bad destination address: %s\n", dst);

	if (src)
	{
		if ((src_ip = libnet_name_resolve(src, 1)) == 0xFFFFFFFF)
			fatal("Bad source address: %s\n", src);
	}
	else
	{
		if (! (src_ip = libnet_get_ipaddr(&l, device, errbuf)))
			fatal("Could not determine IP address of device %s: %s\n",
				device, errbuf);

		/* hmm, do I need to use htonl() here because of a bug in libnet? */
		src_ip = htonl(src_ip);
	}

	if ((proto = getprotobyname("tcp")) == NULL)
		fatal("Could not determine protcol number for TCP?\n");

	if (src_prt == 0)
	{
		if ((sockfd = socket(PF_INET, SOCK_STREAM, proto->p_proto)) < 0)
			pfatal("Could not allocate socket\n");

		insize = sizeof(in);
		bzero(&in, insize);

		if ((bind(sockfd, &in, insize)) < 0)
			pfatal("bind");

		if ((getsockname(sockfd, &in, &insize)) < 0)
			pfatal("getsockname");

		src_prt = in.sin_port;
	}

	if (minttl <= 0 || maxttl <= 0)
		fatal("TTL must be greater than 0\n");

	if (minttl >= 256 || maxttl >= 256)
		fatal("TTL must be less than 256\n");
	
	if (minttl >= maxttl)
		fatal("Minimum TTL (%d) must be less than maximum TTL (%d)\n",
			minttl, maxttl);
	
	if (timeout <= 0)
		fatal("Timeout must be greater than zero\n");

	libnet_seed_prand();

	if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) == -1)
		pfatal("socket allocation");

	if ((buf = malloc(LIBNET_TCP_H + LIBNET_IP_H)) == NULL)
		pfatal("malloc");
	
	if (strcmp(dst, iptos(dst_ip)) == 0)
		snprintf(dst_name, TEXTSIZE, "%s", dst);
	else
		snprintf(dst_name, TEXTSIZE, "%s (%s)", dst, iptos(dst_ip));

	if ((serv = getservbyport(dst_prt, "tcp")) == NULL)
		snprintf(dst_prt_name, TEXTSIZE, "%d", dst_prt);
	else
		snprintf(dst_prt_name, TEXTSIZE, "%d (%s)", dst_prt, serv->s_name);

	printf("Selected device %s, address %s, port %d for outgoing packets\n",
		device, iptos(src_ip), src_prt);
}

/*
 * Open the pcap listening device, and apply our filter.
 */

void initcapture(void)
{
	struct bpf_program fcode;
	bpf_u_int32 localnet, netmask;

	if (! (pcap = pcap_open_live(device, offset + SNAPLEN, 0, 1, errbuf)))
		fatal("pcap_open_live failed: %s", errbuf);

	snprintf(filter, TEXTSIZE,
		"(tcp and src host %s and src port %d and dst host %s and dst port %d)
		or ((icmp[0] == 11 or icmp[0] == 3) and dst host %s)",
			iptos(dst_ip), dst_prt, iptos(src_ip), src_prt, iptos(src_ip));

	localnet = 0;
	netmask = 0;

	if (pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0)
		fatal("pcap_lookupnet failed: %s\n", errbuf);

	if (pcap_compile(pcap, &fcode, filter, 1, netmask) < 0)
		fatal("filter compile failed: %s", pcap_geterr(pcap));

	if (pcap_setfilter(pcap, &fcode) < 0)
		fatal("pcap_setfilter failed\n");
}

/*
 * Sends out a TCP SYN packet with the specified TTL, and returns the IP
 * ID that was sent so we know which one to listen for later.
 */

u_short probe(int ttl)
{
	u_short id;

	id = libnet_get_prand(PRu32);
	bzero(buf, LIBNET_TCP_H + LIBNET_IP_H);

	libnet_build_ip(
		LIBNET_TCP_H,			/* len			*/
		0,						/* tos			*/
		id,						/* id			*/
		0,						/* frag			*/
		ttl,					/* ttl			*/
		IPPROTO_TCP,			/* proto		*/
		src_ip,					/* saddr		*/
		dst_ip,					/* daddr		*/
		NULL,					/* data			*/
		0,						/* datasize?	*/
		buf);					/* buffer		*/

	libnet_build_tcp(
		src_prt,				/* source port	*/
		dst_prt,				/* dest port	*/
		0,						/* seq number	*/
		0,						/* ack number	*/
		TH_SYN,					/* control		*/
		0,						/* window		*/
		0,						/* urgent?		*/
		NULL,					/* data			*/
   		0,						/* datasize		*/
		buf + LIBNET_IP_H);		/* buffer		*/

	libnet_do_checksum(buf, IPPROTO_TCP, LIBNET_TCP_H);

	if (gettimeofday(&t1, NULL) != 0)
		pfatal("gettimeofday");

	if (libnet_write_ip(sockfd, buf, LIBNET_TCP_H + LIBNET_IP_H)
			< LIBNET_TCP_H + LIBNET_IP_H)
		fatal("libnet_write_ip failed?\n");
	
	return id;
}

/*
 * Listens for responses to our probe matching the specified IP ID and print
 * the results.  Returns 1 if the destination was reached, or 0 if we need to
 * increment the TTL some more.
 */

int capture(int ttl, u_short id)
{
    u_char *packet;
	struct pcap_pkthdr packet_hdr;
	struct libnet_ip_hdr *ip_hdr, *old_ip_hdr;
	struct libnet_tcp_hdr *tcp_hdr, *old_tcp_hdr;
	struct libnet_icmp_hdr *icmp_hdr;
	time_t start;
	double delta;

	start = time(NULL);

	for(;;)
	{
		/*
		 * This doesn't always work -- pcap_next() doesn't always return
		 * quickly, which means that the timeout check doesn't always happen.
		 * There needs to be a better way to go about this, perhaps with
		 * alarm().
		 */

		if (time(NULL) - start >= timeout)
		{
			printf("%2d  *\n", ttl);
			return 0;
		}

		if ((packet = (u_char *)pcap_next(pcap, &packet_hdr)) == NULL)
		{
			debug("null pointer from pcap_next()\n");
			continue;
		}

		debug("packet recieved from pcap_next()\n");

		packet += offset;
		ip_hdr = (struct libnet_ip_hdr *)packet;

		if (gettimeofday(&t2, NULL) != 0)
			pfatal("gettimeofday");

		delta = (double)(t2.tv_sec - t1.tv_sec) * 1000 +
				(double)(t2.tv_usec - t1.tv_usec) / 1000;

		if (ip_hdr->ip_p == IPPROTO_ICMP)
		{
			icmp_hdr = (struct libnet_icmp_hdr *)(packet + LIBNET_IP_H);
			debug("received icmp packet\n");

			if (icmp_hdr->icmp_type != ICMP_TIMXCEED &&
				icmp_hdr->icmp_type != ICMP_UNREACH)
			{
				printf("%2d  %s (%s)  %.3f ms -- Unexpected ICMP\n",
					ttl, iptohost(ip_hdr->ip_src.s_addr),
					iptos(ip_hdr->ip_src.s_addr), delta);
				return 0;
			}

			/*
			 * The IP header that generated the ICMP packet is quoted
			 * here.  I don't know what the +4 is, but it works.
			 */
			old_ip_hdr = (struct libnet_ip_hdr *)(packet +
				LIBNET_IP_H + LIBNET_ICMP_H + 4);

			/* The entire TCP header isn't here, but the port numbers are */
			old_tcp_hdr = (struct libnet_tcp_hdr *)(packet +
					LIBNET_IP_H + LIBNET_ICMP_H + 4 + LIBNET_IP_H);

			/* These are not the droids you are looking for */
			if (old_ip_hdr->ip_p != IPPROTO_TCP)
			{
				debug("icmp packet doesn't quote a tcp ip header\n");
				continue;
			}

			/* We are free to go about our business */
			if (ntohs(old_ip_hdr->ip_id) != id)
			{
				debug("icmp packet doesn't contain the id we sent\n");
				continue;
			}

			/* Move along, move along */
			if (ntohs(old_tcp_hdr->th_sport) != src_prt)
			{
				debug("icmp packet doesn't contain the correct tcp port numbers\n");
				continue;
			}

			if (icmp_hdr->icmp_type == ICMP_UNREACH)
			{
				char *s;

				switch(icmp_hdr->icmp_code)
				{
					case ICMP_UNREACH_NET:
						s = "!N"; break;

					case ICMP_UNREACH_HOST:
						s = "!H"; break;

					case ICMP_UNREACH_PROTOCOL:
						s = "!P"; break;

					case ICMP_UNREACH_NEEDFRAG:
						s = "!F"; break;

					case ICMP_UNREACH_SRCFAIL:
						s = "!S"; break;

					case ICMP_UNREACH_NET_PROHIB:
					case ICMP_UNREACH_FILTER_PROHIB:
						s = "!A"; break;

					case ICMP_UNREACH_HOST_PROHIB:
						s = "!C"; break;

					case ICMP_UNREACH_NET_UNKNOWN:
					case ICMP_UNREACH_HOST_UNKNOWN:
						s = "!U"; break;

					case ICMP_UNREACH_ISOLATED:
						s = "!I"; break;

					case ICMP_UNREACH_TOSNET:
					case ICMP_UNREACH_TOSHOST:
						s = "!T"; break;

					case ICMP_UNREACH_PORT:
					case ICMP_UNREACH_HOST_PRECEDENCE:
					case ICMP_UNREACH_PRECEDENCE_CUTOFF:
					default:
						s = "!?"; break;
				}

				printf("%2d  %s (%s)  %.3f ms %s\n", ttl,
					iptohost(ip_hdr->ip_src.s_addr),
					iptos(ip_hdr->ip_src.s_addr), delta, s);
				return 1;
			}

			if (icmp_hdr->icmp_type == ICMP_TIMXCEED)
			{
				printf("%2d  %s (%s)  %.3f ms\n", ttl,
					iptohost(ip_hdr->ip_src.s_addr),
					iptos(ip_hdr->ip_src.s_addr), delta);
				return 0;
			}

			fatal("something bad happened\n");
		}

		if (ip_hdr->ip_p == IPPROTO_TCP)
		{
			char *s;

			tcp_hdr = (struct libnet_tcp_hdr *)(packet + LIBNET_IP_H);
			debug("received tcp packet\n");

			if (tcp_hdr->th_flags & TH_RST)
				s = "closed";
			else if (tcp_hdr->th_flags & TH_SYN && tcp_hdr->th_flags & TH_ACK)
				s = "open";
			else
				s = "unknown";

			printf("%2d  %s (%s) [%s]  %.3f ms\n",
				ttl, iptohost(ip_hdr->ip_src.s_addr),
				iptos(ip_hdr->ip_src.s_addr), s, delta);

			return 1;
		}

		fatal("something bad happened\n");
	}
}

void trace(void)
{
	int ttl, done;
	u_short id;

	printf("Tracing the path to %s on TCP port %s, %d hops max\n",
		dst_name, dst_prt_name, maxttl);
	initcapture();
	
	for (ttl = minttl, done = 0; !done && ttl <= maxttl; ttl++)
	{
		id = probe(ttl);
		done = capture(ttl, id);
	}

	if (!done)
		printf("Destination not reached\n");
}

int main(int argc, char *argv[])
{
	struct servent *serv;
	char *s;

	if (getuid() & geteuid())
		fatal("Got root?\n");

	src_ip	= 0;
	src_prt	= 0;
	src		= NULL;
	minttl	= 1;
	maxttl	= 30;
	o_debug	= 0;
	o_numeric = 0;
	device	= NULL;
	dst_prt	= 0;
	timeout	= 3;

	/* strip out path from argv[0] */
	for (name = s = argv[0]; s[0]; s++)
		if (s[0] == '/' && s[1])
			name = &s[1];

	for (argc--, argv++; argc > 0; argc--, argv++)
	{
		s = argv[0];

		if (strcmp("--", s) == 0)
		{
			argc--, argv++;
			break;
		}

		if (s[0] != '-')
			break;

		if (strcmp("--help", s) == 0)
			s = "-h";

		if (strcmp("--version", s) == 0)
			s = "-v";

		for (s++; s[0]; s++)
			switch(s[0])
			{
				case 'h':
					usage();

				case 'v':
					about();

				case 'd':
					o_debug++;
					debug("Debugging enabled, for what it's worth\n");
					break;

				case 'n':
					o_numeric = 1;
					break;

				case 'i':
					if (argc < 2) fatal("Argument required for -i\n");
					device = argv[1];
					argc--, argv++;
					break;

				case 'f':
					if (argc < 2) fatal("Argument required for -f\n");
					minttl = atoi(argv[1]);
					argc--, argv++;
					break;

				case 'm':
					if (argc < 2) fatal("Argument required for -m\n");
					maxttl = atoi(argv[1]);
					argc--, argv++;
					break;

				case 'p':
					if (argc < 2) fatal("Argument required for -p\n");
					src_prt = atoi(argv[1]);
					argc--, argv++;
					break;

				case 'w':
					if (argc < 2) fatal("Argument required for -w\n");
					timeout = atoi(argv[1]);
					argc--, argv++;
					break;

				case 's':
					if (argc < 2) fatal("Argument required for -s\n");
					src = argv[1];
					argc--, argv++;
					break;

				default:
					printf("Unknown command line argument: -%c\n", s[0]);
					usage();
			}
	}

	if (argc < 1 || argc > 2)
		usage();

	dst = argv[0];

	if (argc == 2)
	{
		dst_prt = atoi(argv[1]);

		if (dst_prt == 0)
		{
			if ((serv = getservbyname(argv[1], "tcp")) == NULL)
				fatal("Unknown port: %s\n", argv[1]);
			else
				dst_prt = serv->s_port;
		}
	}

	if (dst_prt == 0)
		dst_prt = 80;

	defaults();
	trace();

	free(buf);
	return 0;
}
