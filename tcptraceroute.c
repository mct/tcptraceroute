/* -*- Mode: c; tab-width: 4; indent-tabs-mode: 1; c-basic-offset: 4; -*- */
/* vim:set ts=4 sw=4 ai nobackup nocindent: */

/*
 * tcptraceroute -- A traceroute implementation using TCP packets
 * Copyright (c) 2001, Michael C. Toren <mct@toren.net>
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
 * Requires libnet (http://www.packetfactory.net/libnet) and libpcap
 * (http://www.tcpdump.org/).  To compile, try something like:
 *
 *	gcc -O2 -Wall `libnet-config --defines` \
 *		-o tcptraceroute tcptraceroute.c `libnet-config --libs` -lpcap
 *
 * Updates are available from http://michael.toren.net/code/tcptraceroute/
 */

/*
 * Revision history:
 *
 *	Version 1.2 (2001-07-31)
 *
 *		Contains large portions of code and ideas contributed by
 *		Scott Gifford <sgifford@tir.com>
 *		
 *		Attempt to determine what outgoing interface to use based on the
 *		destination address and the local system's interface list.  Could
 *		still use a good deal of work on BSD systems, though, especially
 *		when it comes to virtual addresses which reside on subnets
 *		different than the primary address.
 *		
 *		The timeout code has been reworked significantly, and should now
 *		be much more reliable.
 *		
 *		Added -E command line argument to send ECN (RFC2481) packets.
 *		Requested by Christophe Barb <christophe.barbe@lineo.fr> and
 *		Jim Penny <jpenny@debian.org>
 *		
 *		Added -l command line argument to set the total packet length,
 *		including IP header.
 *		
 *		Added support for sending more than one probe to each hop, and
 *		the -q command line option to specify the number of probes.
 *		
 *		Added -F command line argument to set the IP_DF bit.
 *		
 *		Added -t command line argument to set the IP TOS.
 *		
 *		Now properly checks the length of the packets returned by libpcap
 *		before blindly assuming that the entire header structure we happen
 *		to be looking for is there.  This could have been very ugly had the
 *		snaplen not been set so conservatively.
 *		
 *		Print banner information to stderr, not stdout, to be compatible
 *		with traceroute(8).  Reported by Scott Fenton <scott@matts-books.com>
 *
 *		Fixed an endian bug reported by Zoran Dzelajlija <jelly@srk.fer.hr>,
 *		which prevented users from specifying the destination port number by
 *		name.
 *
 *	Version 1.1 (2001-06-30)
 *
 *		Now drops root privileges after sockets have been opened.
 *
 *		Must now be root to use -s or -p, making it now safe to to
 *		install tcptraceroute suid root, without fear that users can
 *		generate arbitrary SYN packets.
 *
 *	Version 1.0 (2001-04-10)
 *
 *		Initial Release
 */

/*
 * TODO:
 *
 * - RESOLVE_1918 should be a runtime, command line option.
 * - Command line arguments could be handled better.
 * - Display if the remote host is ECN capable when using o_ecn?
 * - Currently it is not possible to traceroute to yourself.
 * - finddev() doesn't detect virtual addresses on BSD systems.
 * - We really should be using GNU autoconf.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <pcap.h>

#ifndef SIOCGIFCONF
#include <sys/sockio.h> /* Solaris, maybe others? */
#endif

#ifndef AF_LINK
#define AF_LINK AF_INET /* BSD defines some AF_INET network interfaces as AF_LINK */
#endif

/* ECN (RFC2481) */
#ifndef TH_ECN
#define TH_ECN  0x40
#endif
#ifndef TH_CWR
#define TH_CWR  0x80
#endif

#define VERSION "tcptraceroute 1.2 (2001-07-31)"
#define BANNER  "Copyright (c) 2001, Michael C. Toren <mct@toren.net>\n\
Updates are available from http://michael.toren.net/code/tcptraceroute/\n"

/* Buffer size used for a few strings, including the pcap filter */
#define TEXTSIZE	1024

/* Should we attempt to resolve RFC1918 address space? */
#undef RESOLVE_1918

/*
 * How many bytes should we examine on every packet that comes off the
 * wire?  This doesn't include the link layer which is accounted for
 * later.  We're looking only for ICMP and TCP packets, so this should
 * work.  For ICMP, we also examine the quoted IP header, which is why
 * there's a *2 there.  The +32 is just to be safe.
 */

#define SNAPLEN	 (LIBNET_IP_H * 2 + \
	(LIBNET_TCP_H > LIBNET_ICMP_H ? LIBNET_TCP_H : LIBNET_ICMP_H) + 32)

/* Various globals */
u_long dst_ip, src_ip;
u_short src_prt, dst_prt;
char *device, *name, *dst, *src;
char dst_name[TEXTSIZE], dst_prt_name[TEXTSIZE], filter[TEXTSIZE];
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *pcap;
struct timeval t1, t2;
int	sockfd, datalink, offset;
int o_minttl, o_maxttl, o_timeout, o_debug, o_numeric, o_pktlen,
	o_nqueries, o_dontfrag, o_tos, o_forceport, o_ecn;

extern char pcap_version[];
extern int errno;

/*
 * fatal() and pfatal() are useful stdarg functions from
 * namp.  debug() and warn() are based on them.
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

void warn(char *fmt, ...)
{
	va_list ap;
	fflush(stdout);
	fprintf(stderr, "Warning: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
}

void pfatal(char *err)
{
	debug("errno == %d\n", errno);
	fflush(stdout);
	perror(err);
	exit(1);
}

void usage(void)
{
	printf("\n%s\n%s\n", VERSION, BANNER);
    fatal("Usage: %s [-nFE] [-i <interface>] [-f <first ttl>]
       [-l <packet length>] [-q <number of queries>] [-t <tos>]
       [-m <max ttl>] [-[pP] <source port>] [-s <source address>]
       [-w <wait time>] <host> [destination port] [packet length]\n\n", name);
}

void about(void)
{
	printf("\n%s\n%s\n", VERSION, BANNER);
	debug("Compiled with libpcap version %s\n\n",pcap_version);
	exit(0);
}

/*
 * realloc(3) or bust!
 */

void *xrealloc(void *oldp, int size)
{
	void *p;

	if (!oldp)
	{
		/* Kludge for SunOS, which doesn't allow realloc on a NULL pointer */
		oldp = malloc(1);
		if (!oldp)
			fatal("Out of memory!  Could not allocate 1 byte!\n");
	}

	if (! (p = realloc(oldp, size)))
		fatal("Out of memory!  Could not reallocate %d bytes!X\n", size);

	return p;
}

/*
 * Same as strncpy, but always be sure the result is terminated.
 */

char *safe_strncpy(char *dst, const char *src, int size)
{
	dst[size-1] = '\0';
	return strncpy(dst, src, size-1);
}

/*
 * return a pointer to a string containing only the
 * printable characters of the string passed to it.
 */

char *sprintable(char *s)
{
	static char buf[TEXTSIZE];
	int i;

	for (i = 0; s[i]; i++)
	{
		if (i == TEXTSIZE)
			break;

		buf[i] = isprint(s[i]) ? s[i] : '?';
	}

	buf[i] = '\0';

	if (i == 0)
		safe_strncpy(buf, "(empty)", TEXTSIZE);

	return buf;
}

/*
 * Compute the difference between two timeval structures.
 */

struct timeval tvdiff(struct timeval *tv1, struct timeval *tv2)
{
	struct timeval tvdiff;

	tvdiff.tv_sec = tv1->tv_sec - tv2->tv_sec;
	tvdiff.tv_usec = tv1->tv_usec - tv2->tv_usec;

	if ((tvdiff.tv_sec > 0) && (tvdiff.tv_usec < 0))
	{
		tvdiff.tv_usec += 1000000L;
		tvdiff.tv_sec--;
	}

	else if ((tvdiff.tv_sec < 0) && (tvdiff.tv_usec > 0))
	{
		tvdiff.tv_usec -= 1000000L;
		tvdiff.tv_sec++;
	}

	return tvdiff;
}


/*
 * Is the timeval less than, equal to, or greater than zero?
 */

int tvsign(struct timeval *tv)
{
	if (tv->tv_sec < 0) return -1;

	if (tv->tv_sec == 0)
	{
		if (tv->tv_usec < 0) return -1;
		if (tv->tv_usec == 0) return 0;
		if (tv->tv_usec > 0) return 1;
	}

	if (tv->tv_sec > 0) return 1;

	return -1;
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
 * A wrapper for libnet_host_lookup() with the option not to resolve
 * 1918 space.  This #define should be moved to a command line argument
 * at some point.
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
 * Determines the source address that should be used to reach the
 * given destination address.
 */

u_long findsrc(u_long dest)
{
	struct sockaddr_in sinsrc, sindest;
	int s, size;

	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		pfatal("socket error");

	memset(&sinsrc, 0, sizeof(struct sockaddr_in));
	memset(&sindest, 0, sizeof(struct sockaddr_in));

	sindest.sin_family = AF_INET;
	sindest.sin_addr.s_addr = dest;
	sindest.sin_port = htons(53); /* can be anything */

	if (connect(s, (struct sockaddr *)&sindest, sizeof(sindest)) < 0)
		pfatal("connect");

	size = sizeof(sinsrc);
	if (getsockname(s, (struct sockaddr *)&sinsrc, &size) < 0)
		pfatal("getsockname");

	close(s);
	debug("Determined source address of %s to reach %s\n",
		iptos(sinsrc.sin_addr.s_addr), iptos(dest));
	return sinsrc.sin_addr.s_addr;
}

/*
 * Locates the device name matching the given source address.  For
 * virtual hosts under Linux and Solaris, returns the portions of the
 * name before the first ":" character.  Unfortunately, this won't
 * match virtual hosts under OpenBSD.
 */

char *finddev(u_long src)
{
	struct ifconf ifc;
	struct ifreq *ifrp, ifr;
	int numreqs, n, i, s;
	char *device;

	device = NULL;
	ifc.ifc_buf = NULL;

	/*
	 * The initial request length needs to be somewhat large, because
	 * the incrementing technique doesn't work on BSD(?)  But, it can't
	 * be too large, or ioct() will complain (on Linux at least) about
	 * not being able to allocate enough memory for the request.
	 */

	numreqs = 1024;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		fatal("socket error");

	debug("ifreq buffer set to %d\n", numreqs);

	for (;;)
	{
		ifc.ifc_len = sizeof(struct ifreq) * numreqs;
		ifc.ifc_buf = xrealloc(ifc.ifc_buf, ifc.ifc_len);

		if (ioctl(s, SIOCGIFCONF, &ifc) < 0)
			pfatal("ioctl");

        if (ifc.ifc_len >= sizeof(struct ifreq) * numreqs)
		{
			/* Assume it overflowed and try again */
			numreqs += 1024;
			debug("ifreq buffer grown to %d\n", numreqs);
			continue;
		}

		break;
	}

	debug("successfully retrieved interface list\n");

	for (n = 0, ifrp = ifc.ifc_req;
		n < ifc.ifc_len;
		n += sizeof(struct ifreq), ifrp++)
	{
		u_long addr;

		memset(&ifr, 0, sizeof(struct ifreq));
		strcpy(ifr.ifr_name, ifrp->ifr_name);

		if (ifrp->ifr_addr.sa_family != AF_INET &&
			ifrp->ifr_addr.sa_family != AF_LINK)
		{
			debug("ignoring non-AF_INET interface %s\n", sprintable(ifr.ifr_name));
			continue;
		}

		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
			pfatal("ioctl(SIOCGIFFLAGS)");

		if ((ifr.ifr_flags & IFF_UP) == 0)
		{
			debug("Ignoring down interface %s\n", sprintable(ifr.ifr_name));
			continue;
		}

		if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
			pfatal("ioctl(SIOCGIFADDR)");

		addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

		debug("Discovered interface %s with address %s\n",
			sprintable(ifr.ifr_name), iptos(addr));

		if (addr == src)
		{
			debug("Interface %s matches source address %s\n",
				sprintable(ifr.ifr_name), iptos(src));
			device = xrealloc(NULL, sizeof(ifr.ifr_name+1));
			strcpy(device, ifr.ifr_name);

			/* Deal with virtual hosts */
			for (i = 0; device[i]; i++)
				if (device[i] == ':')
					device[i] = '\0';
		}
	}

	free(ifc.ifc_buf);
	return device;
}

/*
 * To add support for additional link layers, add entries to datalinkoffset()
 * and datalinkname().  The numbers I have in here now I believe are correct,
 * and were obtained by looking through other pcap programs, however I have
 * only tested tcptraceroute on ethernet and Linux PPP interfaces.
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
	static char name[TEXTSIZE];

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

		default:
			snprintf(name, TEXTSIZE, "#%d", type);
			return name;
	}
}

/* 
 * What a kludge, but it works.  The aim is to be as compatible as possible
 * with traceroute(8), with the one exception that if for the same hop we
 * receive a response from two different hosts, display the second host on
 * a new line, as Cisco does.  This drastically improves readability when
 * tracing through links which have per-packet, round-robin load balancing.
 */

void showprobe(int ttl, int q, u_long addr, char *state, char *fmt, ...)
{
	/* Variables to keep state between calls */
	static char laststate[TEXTSIZE];
	static int lastttl;
	static u_long lastaddr;
	static int everprint;

	int printflag = 0;
	va_list ap;

	/* ttl */
	if (lastttl != ttl)
	{
		printf("%2d  ", ttl);
		printflag = 1;
		everprint = 0;
		safe_strncpy(laststate, "", TEXTSIZE);
	}
	else if (lastaddr != addr && addr != INADDR_ANY && lastaddr != INADDR_ANY)
	{
		printf("\n    ");
		printflag = 1;
	}

	/* host */
	if ((printflag || !everprint) && addr != INADDR_ANY)
	{
		if (q > 1 && lastaddr == INADDR_ANY)
			printf(" ");

		printf("%s (%s)", iptohost(addr), iptos(addr));
		everprint = 1;
	}

	/* tcp state */
	if ( ((ttl != lastttl) && state) ||
		((ttl == lastttl) && state && (strncmp(laststate, state, TEXTSIZE) != 0)))
	{
		printf(" [%s]", state);
	}

	/* space before ms */
	if (! (addr == INADDR_ANY && q == 1))
	{
		/* if timeout, only print one space. otherwise, two */
		if ((addr == INADDR_ANY) || (lastaddr == INADDR_ANY))
			printf(" ");
		else
			printf("  ");
	}

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	if (q == o_nqueries)
		printf("\n");

	lastttl = ttl;
	lastaddr = addr;
	if (state)
		safe_strncpy(laststate, state, TEXTSIZE);

	fflush(stdout);
}


/*
 * Check command line arguments for sanity, and fill in the blanks.
 */

void defaults(void)
{
	struct sockaddr_in in;
	struct servent *serv;
	int insize;
	u_long recommended_src;

	if ((dst_ip = libnet_name_resolve(dst, 1)) == 0xFFFFFFFF)
		fatal("Bad destination address: %s\n", dst);

	recommended_src = findsrc(dst_ip);

	if (src)
	{
		if ((src_ip = libnet_name_resolve(src, 1)) == 0xFFFFFFFF)
			fatal("Bad source address: %s\n", src);
	}
	else
		src_ip = recommended_src;

	if (device == NULL)
		/* not specified on command line */
		device = finddev(recommended_src);

	if (device == NULL)
	{
		/* couldn't find an interface matching recommended_src */
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

	if (! o_forceport)
	{
		if ((sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
			pfatal("socket error");

		insize = sizeof(in);
		memset(&in, 0, insize);

		in.sin_family = AF_INET;
		in.sin_port = htons(src_prt);

		if ((bind(sockfd, (struct sockaddr *)&in, insize)) < 0)
			fatal("Sorry, could not bind to port %d.  Use -P instead of -p to override.\n", src_prt);

		if ((getsockname(sockfd, (struct sockaddr *)&in, &insize)) < 0)
			pfatal("getsockname");

		src_prt = ntohs(in.sin_port);
		close(sockfd);
	}

	if (o_minttl <= 0 || o_maxttl <= 0)
		fatal("TTL must be greater than 0\n");

	if (o_minttl >= 256 || o_maxttl >= 256)
		fatal("TTL must be less than 256\n");

	if (o_minttl > o_maxttl)
		fatal("Minimum TTL (%d) must be less than maximum TTL (%d)\n",
			o_minttl, o_maxttl);

	if (o_timeout <= 0)
		fatal("Timeout must be at least 1\n");

	if (o_pktlen < LIBNET_TCP_H + LIBNET_IP_H)
	{
		if (o_pktlen != 0)
			warn("Increasing packet length to %d bytes\n", LIBNET_TCP_H + LIBNET_IP_H);
		o_pktlen = 0;
	}
	else
		o_pktlen -= (LIBNET_TCP_H + LIBNET_IP_H);

	libnet_seed_prand();

	if ((sockfd = libnet_open_raw_sock(IPPROTO_RAW)) < 0)
		pfatal("socket allocation");

	if (strcmp(dst, iptos(dst_ip)) == 0)
		snprintf(dst_name, TEXTSIZE, "%s", dst);
	else
		snprintf(dst_name, TEXTSIZE, "%s (%s)", dst, iptos(dst_ip));

	if ((serv = getservbyport(dst_prt, "tcp")) == NULL)
		snprintf(dst_prt_name, TEXTSIZE, "%d", dst_prt);
	else
		snprintf(dst_prt_name, TEXTSIZE, "%d (%s)", dst_prt, serv->s_name);

	fprintf(stderr, "Selected device %s, address %s, port %d for outgoing packets\n",
		device, iptos(src_ip), src_prt);
}

/*
 * Open the pcap listening device, and apply our filter.
 */

void initcapture(void)
{
	struct bpf_program fcode;
	bpf_u_int32 localnet, netmask;

	if (! (pcap = pcap_open_live(device, offset + SNAPLEN, 0, 10, errbuf)))
		fatal("pcap_open_live failed: %s", errbuf);

	snprintf(filter, TEXTSIZE,
		"(tcp and src host %s and src port %d and dst host %s and dst port %d)
		or ((icmp[0] == 11 or icmp[0] == 3) and dst host %s)",
			iptos(dst_ip), dst_prt, iptos(src_ip), src_prt, iptos(src_ip));
	debug("pcap filter is:\n'%s'\n",filter);

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
 * Sends out a TCP SYN packet with the specified TTL, and returns
 * the IP ID that was sent so we know which one to listen for later.
 */

u_short probe(int ttl)
{
	static u_char *payload, *buf;
	u_short id;
	int i, size, ret;

	if (o_pktlen && !payload)
	{
		debug("Initializing payload of %d bytes\n", o_pktlen);
		payload = xrealloc(payload, o_pktlen);

		for(i = 0; i < o_pktlen; i++)
			payload[i] = '!' + (i % ('~' - '!'));
	}

	size = LIBNET_IP_H + LIBNET_TCP_H + o_pktlen;

	if (!buf)
	{
		debug("Initializing probe buffer\n");
		buf = xrealloc(buf, size);
	}

	memset(buf, 0, size);
	id = libnet_get_prand(PRu32);

	libnet_build_ip(
		LIBNET_TCP_H+o_pktlen,	/* len			*/
		o_tos,					/* tos			*/
		id,						/* id			*/
		o_dontfrag ? IP_DF : 0,	/* frag			*/
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
		TH_SYN | (o_ecn ? TH_CWR|TH_ECN : 0), /* control		*/ 
		0,						/* window		*/
		0,						/* urgent?		*/
		payload,				/* data			*/
		o_pktlen,				/* datasize		*/
		buf + LIBNET_IP_H);		/* buffer		*/

	libnet_do_checksum(buf, IPPROTO_TCP, LIBNET_TCP_H + o_pktlen);

	if (gettimeofday(&t1, NULL) < 0)
		pfatal("gettimeofday");

	if ((ret = libnet_write_ip(sockfd, buf, size)) < size)
		fatal("libnet_write_ip failed?  Attempted to write %d bytes, only wrote %d\n",
			  size, ret);

	return id;
}

/*
 * Listens for responses to our probe matching the specified IP ID and print
 * the results.  Returns 1 if the destination was reached, or 0 if we need to
 * increment the TTL some more.
 */

int capture(int ttl, int q, u_short id)
{
	u_char *packet;
	struct pcap_pkthdr packet_hdr;
	struct libnet_ip_hdr *ip_hdr, *old_ip_hdr;
	struct libnet_tcp_hdr *tcp_hdr, *old_tcp_hdr;
	struct libnet_icmp_hdr *icmp_hdr;
	struct timeval start, now, timepassed, timeout_tv, timeleft;
	int pcap_fd, firstpass, ret, len;
	double delta;
	fd_set sfd;

	firstpass = 1;
	timeout_tv.tv_sec = o_timeout;
	timeout_tv.tv_usec = 0;

	if (gettimeofday(&start, NULL) < 0)
		pfatal("gettimeofday");

	for(;;)
	{
		if (firstpass)
		{
			firstpass = 0;
			timeleft = timeout_tv;
		}
		else
		{
			if (gettimeofday(&now, NULL) < 0)
				pfatal("gettimeofday");

			timepassed = tvdiff(&now, &start);

			if (tvsign(&timepassed) < 0)
			{
				/* Deal with weird clock skew */
				timepassed.tv_sec = 0;
				timepassed.tv_usec = 0;
			}

			timeleft = tvdiff(&timeout_tv, &timepassed);

			if (tvsign(&timeleft) <= 0)
			{
				showprobe(ttl, q, INADDR_ANY, NULL, "*");
				return 0;
			}
		}

		/*
		 * The libpcap documentation is wrong; pcap_fileno actually
		 * returns the fd of the live capture device, not the save
		 * file.  References:
		 *
		 *   http://www.tcpdump.org/lists/workers/2001/01/msg00223.html
		 *   http://www.tcpdump.org/lists/workers/2001/03/msg00107.html
		 *   http://www.tcpdump.org/lists/workers/2001/03/msg00109.html
		 *   http://www.tcpdump.org/lists/workers/2001/03/msg00110.html
		 */

		pcap_fd = pcap_fileno(pcap);
		FD_ZERO(&sfd);
		FD_SET(pcap_fd, &sfd);

		if ((ret = select(pcap_fd + 1, &sfd, NULL, NULL, &timeleft)) < 0)
		{
			fatal("select");
		}
		else if (ret == 0)
		{
			debug("select() timeout\n");
			continue;
		}

		if ((packet = (u_char *)pcap_next(pcap, &packet_hdr)) == NULL)
		{
			debug("null pointer from pcap_next()\n");
			continue;
		}

		packet += offset;
		len = packet_hdr.caplen - offset;
		debug("received %d byte packet from pcap_next()\n", len);

		if (len < LIBNET_IP_H)
		{
			debug("ignoring partial ip packet\n");
			continue;
		}

		ip_hdr = (struct libnet_ip_hdr *)packet;

		if (gettimeofday(&t2, NULL) < 0)
			pfatal("gettimeofday");

		delta = (double)(t2.tv_sec - t1.tv_sec) * 1000 +
			(double)(t2.tv_usec - t1.tv_usec) / 1000;

		if (ip_hdr->ip_p == IPPROTO_ICMP)
		{
			if (len < LIBNET_IP_H + LIBNET_ICMP_H + 4)
			{
				debug("Ignoring partial icmp packet\n");
				continue;
			}

			icmp_hdr = (struct libnet_icmp_hdr *)(packet + LIBNET_IP_H);
			debug("received icmp packet\n");

			if (icmp_hdr->icmp_type != ICMP_TIMXCEED &&
				icmp_hdr->icmp_type != ICMP_UNREACH)
			{
				showprobe(ttl, q, ip_hdr->ip_src.s_addr, NULL,
					"%.3f ms -- Unexpected ICMP\n", delta);
				return 0;
			}

			/*
			 * The IP header that generated the ICMP packet is quoted
			 * here.  I don't know what the +4 is, but it works.  */

			if (len < LIBNET_IP_H + LIBNET_ICMP_H + 4 + LIBNET_IP_H + 4)
			{
				debug("Ignoring icmp packet with incomplete payload\n");
				continue;
			}

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

				showprobe(ttl, q, ip_hdr->ip_src.s_addr, NULL,
					"%.3f ms %s", delta, s);
				return 1;
			}

			if (icmp_hdr->icmp_type == ICMP_TIMXCEED)
			{
				showprobe(ttl, q, ip_hdr->ip_src.s_addr, NULL,
					"%.3f ms", delta);
				return 0;
			}

			fatal("something bad happened\n");
		}

		if (ip_hdr->ip_p == IPPROTO_TCP)
		{
			char *s;
			
			if (len < LIBNET_IP_H + LIBNET_TCP_H)
			{
				debug("Ignoring partial tcp packet\n");
				continue;
			}

			tcp_hdr = (struct libnet_tcp_hdr *)(packet + LIBNET_IP_H);
			debug("received tcp packet\n");

			if (tcp_hdr->th_flags & TH_RST)
				s = "closed";
			else if (tcp_hdr->th_flags & TH_SYN && tcp_hdr->th_flags & TH_ACK)
				s = "open";
			else
				s = "unknown";

			showprobe(ttl, q, ip_hdr->ip_src.s_addr, s,
				"%.3f ms", delta);

			return 1;
		}

		fatal("something bad happened\n");
	}
}

void trace(void)
{
	int ttl, q, done;
	u_short id;

	fprintf(stderr, "Tracing the path to %s on TCP port %s, %d hops max",
		dst_name, dst_prt_name, o_maxttl);
	
	if (o_pktlen)
		fprintf(stderr, ", %d byte packets", o_pktlen + LIBNET_TCP_H + LIBNET_IP_H);
	fprintf(stderr, "\n");

	for (ttl = o_minttl, done = 0; !done && ttl <= o_maxttl; ttl++)
	{
		for (q = 0; q < o_nqueries; q++)
		{
			id = probe(ttl);
			done |= capture(ttl, q + 1, id);
		}
	}

	if (!done)
		fprintf(stderr, "Destination not reached\n");
}

int main(int argc, char *argv[])
{
	struct servent *serv;
	char *s;

	src_ip	= 0;
	src_prt	= 0;
	dst_prt	= 0;
	src		= NULL;
	device	= NULL;

	o_minttl = 1;
	o_maxttl = 30;
	o_debug	= 0;
	o_numeric = 0;
	o_nqueries = 3;
	o_forceport = 0;
	o_pktlen = 0;
	o_tos	= 0;
	o_ecn	= 0;
	o_dontfrag = 0;
	o_timeout = 3;

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

				case 'l':
					if (argc < 2) fatal("Argument required for -l\n");
					o_pktlen = atoi(argv[1]);
					argc--, argv++;
					break;

				case 'f':
					if (argc < 2) fatal("Argument required for -f\n");
					o_minttl = atoi(argv[1]);
					argc--, argv++;
					break;

				case 'F':
					o_dontfrag = 1;
					debug("Will set DF bit in outgoing packets\n");
					break;

				case 'm':
					if (argc < 2) fatal("Argument required for -m\n");
					o_maxttl = atoi(argv[1]);
					argc--, argv++;
					break;

				case 'P':
					o_forceport = 1;
				case 'p':
					if (argc < 2) fatal("Argument required for -p\n");
					if (getuid()) fatal("Sorry, must be root to use -p\n");
					src_prt = atoi(argv[1]);
					argc--, argv++;
					break;

				case 'q':
					if (argc < 2) fatal("Argument required for -q\n");
					o_nqueries = atoi(argv[1]);
					argc--,argv++;
					break;

				case 'w':
					if (argc < 2) fatal("Argument required for -w\n");
					o_timeout = atoi(argv[1]);
					argc--, argv++;
					break;

				case 's':
					if (argc < 2) fatal("Argument required for -s\n");
					if (getuid()) fatal("Sorry, must be root to use -s\n");
					src = argv[1];
					argc--, argv++;
					break;

				case 't':
					if (argc < 2) fatal("Argument required for -t\n");
					o_tos = atoi(argv[1]);
					debug("TOS set to %d\n", o_tos);
					argc--, argv++;
					break;

				case 'E':
					o_ecn = 1;
					debug("Enabled ECN support\n");
					break;

				default:
					fprintf(stderr, "Unknown command line argument: -%c\n", s[0]);
					usage();
			}
	}

	if (argc < 1 || argc > 3)
		usage();

	dst = argv[0];

	if (argc > 1)
	{
		dst_prt = atoi(argv[1]);

		if (dst_prt == 0)
		{
			if ((serv = getservbyname(argv[1], "tcp")) == NULL)
				fatal("Unknown port: %s\n", argv[1]);
			else
				dst_prt = ntohs(serv->s_port);
		}
	}

	if (argc > 2)
		o_pktlen = atoi(argv[2]);

	if (dst_prt == 0)
		dst_prt = 80;

	if (getuid() & geteuid())
		fatal("Got root?\n");

	defaults();
	initcapture();
	seteuid(getuid());
	trace();

	return 0;
}
