/* -*- Mode: c; tab-width: 4; indent-tabs-mode: 1; c-basic-offset: 4; -*- */
/* vim:set ts=4 sw=4 ai nobackup nocindent sm: */

/*
 * tcptraceroute -- A traceroute implementation using TCP packets
 * Copyright (c) 2001, 2002, 2003  Michael C. Toren <mct@toren.net>
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

/*
 * Requires libnet (http://www.packetfactory.net/libnet) and libpcap
 * (http://www.tcpdump.org/).
 *
 * Updates are available from http://michael.toren.net/code/tcptraceroute/
 */

#define BANNER  "Copyright (c) 2001, 2002, 2003 Michael C. Toren <mct@toren.net>\n\
Updates are available from http://michael.toren.net/code/tcptraceroute/\n"

/*
 * TODO:
 *
 * - Command line argument handling could be improved.  Currently,
 *   long options are always processed before short options, which
 *   means that debugging will always be disabled when long options
 *   are processed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
#include <fcntl.h>

#ifndef __OpenBSD__
#include <net/if.h> /* Why doesn't OpenBSD deal with this for us? */
#endif

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

/* Buffer size used for a few strings, including the pcap filter */
#define TEXTSIZE	1024

/* For compatability with older versions of libnet */
#if (LIBNET_API_VERSION < 110)
#define LIBNET_IPV4_H		LIBNET_IP_H
#define LIBNET_ICMPV4_H		LIBNET_ICMP_H
#define LIBNET_DONT_RESOLVE	0
#define LIBNET_RESOLVE		1
#define libnet_addr2name4	libnet_host_lookup
#define libnet_ipv4_hdr		libnet_ip_hdr
#define libnet_icmpv4_hdr	libnet_icmp_hdr
#endif

#ifndef LIBNET_VERSION
#define LIBNET_VERSION "UNKNOWN"
#endif

#ifndef LIBNET_ERRBUF_SIZE
#define LIBNET_ERRBUF_SIZE TEXTSIZE
#endif

/*
 * How many bytes should we examine on every packet that comes off the
 * wire?  This doesn't include the link layer which is accounted for
 * later.  We're looking only for ICMP and TCP packets, so this should
 * work.  For ICMP, we also examine the quoted IP header, which is why
 * there's a *2 there.  The +32 is just to be safe.
 */

#define SNAPLEN	 (LIBNET_IPV4_H * 2 + \
	(LIBNET_TCP_H > LIBNET_ICMPV4_H ? LIBNET_TCP_H : LIBNET_ICMPV4_H) + 32)

/*
 * To add support for additional link layers, add entries to the following
 * table.  The numbers I have in here now I believe are correct, and were
 * obtained by looking through other pcap programs, however I have only
 * tested tcptraceroute on ethernet, and PPP, and loopback interfaces.
 */

struct datalinktype {
	int type, offset;
	char *name;
} datalinktypes[] = {

#ifdef DLT_RAW
	{	DLT_RAW,			0,		"RAW"			},
#endif
#ifdef DLT_EN10MB
	{	DLT_EN10MB,			14,		"ETHERNET"		},
#endif
#ifdef DLT_PPP
	{	DLT_PPP,			4,		"PPP"			},
#endif
#ifdef DLT_LINUX_SLL
	{	DLT_LINUX_SLL,		16,		"PPP_HDLC"		},
#endif
#ifdef DLT_SLIP
	{	DLT_SLIP,			16,		"SLIP"			},
#endif
#ifdef DLT_PPP_BSDOS
	{	DLT_PPP_BSDOS,		24,		"PPP_BSDOS"		},
#endif
#ifdef DLT_SLIP_BSDOS
	{	DLT_SLIP_BSDOS,		24,		"SLIP_BSDOS"	},
#endif
#ifdef DLT_FDDI
	{	DLT_FDDI,			21,		"FDDI"			},
#endif
#ifdef DLT_IEEE802
	{	DLT_IEEE802,		22,		"IEEE802"		},
#endif
#ifdef DLT_NULL
	{	DLT_NULL,			4,		"DLT_NULL"		},
#endif
#ifdef DLT_LOOP
	{	DLT_LOOP,			4,		"DLT_LOOP"		},
#endif
#ifdef DLT_PPP_ETHER
	{	DLT_PPP_ETHER,		12,		"PPP_ETHER"		},
#endif

	/* Does anyone know correct values for these? */
#ifdef DLT_ATM_RFC1483
	{	DLT_ATM_RFC1483,	-1,		"ATM_RFC1483"	},
#endif
#ifdef DLT_EN3MB
	{	DLT_EN3MB,			-1,		"EN3MB"			},
#endif
#ifdef DLT_AX25
	{	DLT_AX25,			-1,		"AX25"			},
#endif
#ifdef DLT_PRONET
	{	DLT_PRONET,			-1,		"PRONET"		},
#endif
#ifdef DLT_CHAOS
	{	DLT_CHAOS,			-1,		"CHAOS"			},
#endif
#ifdef DLT_ARCNET
	{	DLT_ARCNET,			-1,		"ARCNET"		},
#endif

	/* End of the road */
	{	-1,					-1,		NULL			}
};

/* Various globals */
u_long dst_ip, src_ip;
u_short src_prt, dst_prt;
char *device, *name, *dst, *src;
char dst_name[TEXTSIZE], dst_prt_name[TEXTSIZE], filter[TEXTSIZE];
pcap_t *pcap;
int pcap_fd;
int datalink, offset;
int o_minttl, o_maxttl, o_timeout, o_debug, o_numeric, o_pktlen,
	o_nqueries, o_dontfrag, o_tos, o_forceport, o_syn, o_ack, o_ecn,
	o_nofilter, o_nogetinterfaces, o_noselect, o_trackport;

char errbuf [PCAP_ERRBUF_SIZE > LIBNET_ERRBUF_SIZE ?
			 PCAP_ERRBUF_SIZE : LIBNET_ERRBUF_SIZE];

#if (LIBNET_API_VERSION < 110)
	int sockfd;
#else
	libnet_t *libnet_context;
#endif


/* interface linked list, built later by getinterfaces() */
struct interface_entry {
	char *name;
	u_long addr;
	struct interface_entry *next;
} *interfaces;

/* probe() returns this structure, which describes the packet sent */
typedef struct {
	int ttl, q;
	u_short id, src_prt;
	struct timeval timestamp;
	double delta;
	u_long addr;
	char *state;
	char *string;
} proberecord;

extern char *optarg;
extern int optind, opterr, optopt;
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
	printf("\ntcptraceroute %s\n%s\n", VERSION, BANNER);
    fatal("Usage: %s [-nNFSAE] [-i <interface>] [-f <first ttl>]\n       [-l <packet length>] [-q <number of queries>] [-t <tos>]\n       [-m <max ttl>] [-pP] <source port>] [-s <source address>]\n       [-w <wait time>] <host> [destination port] [packet length]\n\n", name);
}

void about(void)
{
	printf("\ntcptraceroute %s\n%s\n", VERSION, BANNER);
	exit(0);
}

/*
 * realloc(3) or bust!
 */

void *xrealloc(void *oldp, int size)
{
	void *p;

	if (!oldp)
		/* Kludge for SunOS, which doesn't allow realloc on a NULL pointer */
		p = malloc(size);
	else
		p = realloc(oldp, size);
	
	if (!p)
		fatal("Out of memory!  Could not reallocate %d bytes!\n", size);
	
	memset(p, 0, size);
	return p;
}

/*
 * Same as strncpy and snprintf, but always be sure the result is terminated.
 */

char *safe_strncpy(char *dst, char *src, int size)
{
	dst[size-1] = '\0';
	return strncpy(dst, src, size-1);
}

int safe_snprintf(char *s, int size, char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vsnprintf(s, size, fmt, ap);
	s[size-1] = '\0';
	va_end(ap);

	return ret;
}

/*
 * return a pointer to a string containing only the
 * printable characters of the string passed to it.
 */

char *sprintable(char *s)
{
	static char buf[TEXTSIZE];
	int i;

	if (s && s[0])
		safe_strncpy(buf, s, TEXTSIZE);
	else
		safe_strncpy(buf, "(empty)", TEXTSIZE);

	for (i = 0; buf[i]; i++)
		if (! isprint((u_char) buf[i]))
			buf[i] = '?';

	return buf;
}

/*
 * isdigit() across an entire string.
 */

int isnumeric(char *s)
{
	int i;

	if (!s || !s[0])
		return 0;

	for (i = 0; s[i]; i++)
		if (! isdigit((u_char) s[i]))
			return 0;
	
	return 1;
}

int datalinkoffset(int type)
{
	int i;

	for (i = 0; datalinktypes[i].name; i++)
		if (datalinktypes[i].type == type)
			return datalinktypes[i].offset;

	return -1;
}

char *datalinkname(int type)
{
	static char name[TEXTSIZE];
	int i;

	for (i = 0; datalinktypes[i].name; i++)
		if (datalinktypes[i].type == type)
			return datalinktypes[i].name;

	safe_snprintf(name, TEXTSIZE, "#%d", type);
	return name;
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
	safe_snprintf(output[which], 3*4+3+1, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

/*
 * A wrapper for libnet_addr2name4(), with the option not to resolve
 * RFC1918 space.
 */

char *iptohost(u_long in)
{
	u_char *p = (u_char *)&in;

	if ((o_numeric > -1) &&
		((p[0] == 10) ||
		(p[0] == 192 && p[1] == 168) ||
		(p[0] == 172 && p[1] >= 16 && p[1] <= 31)))
	{
		debug("Not attempting to resolve RFC1918 address %s\n", iptos(in));
		return iptos(in);
	}

	return libnet_addr2name4(in,
		o_numeric > 0 ? LIBNET_DONT_RESOLVE : LIBNET_RESOLVE);
}

/*
 * A generic wrapper for libnet_name_resolve and libnet_name2addr4, because
 * it's annoying to have #ifdef's all over the place to support both versions
 * of libnet.
 */

#if (LIBNET_API_VERSION < 110)
#define hosttoip(hostname, numeric) libnet_name_resolve(hostname, numeric)
#else
#define hosttoip(hostname, numeric) libnet_name2addr4(libnet_context, hostname, numeric)
#endif

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
 * Fetches the interface list, storing it in struct interface_entry interfaces.
 */

void getinterfaces(void)
{
	struct interface_entry *p;
	struct ifconf ifc;
	struct ifreq *ifrp, ifr;
	int numreqs, i, s;
	u_long addr;
	int salen;
	char *x;

	debug("entering getinterfaces()\n");

	if (o_nogetinterfaces)
	{
		debug("Not fetching the interface list\n");
		return;
	}

	if (interfaces)
		fatal("Double call to getinterfaces()\n");

	ifc.ifc_buf = NULL;
	p = NULL;

	numreqs = 32;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		fatal("socket error");

	debug("ifreq buffer set to %d\n", numreqs);

	for (;;)
	{
		ifc.ifc_len = sizeof(struct ifreq) * numreqs;
		ifc.ifc_buf = xrealloc(ifc.ifc_buf, ifc.ifc_len);

		if (ioctl(s, SIOCGIFCONF, &ifc) < 0)
			pfatal("ioctl");

		/* This "+ sizeof(struct ifreq) + 64" crap seems to be an (Open?)BSDism. */
		if ( (ifc.ifc_len + sizeof(struct ifreq) + 64) >= (sizeof(struct ifreq) * numreqs) )
		{
			/* Assume it overflowed and try again */
			numreqs += 32;
			if (numreqs > 20000)
				break; /* Too big! */
			debug("ifreq buffer grown to %d\n", numreqs);
			continue;
		}

		break;
	}

	debug("Successfully retrieved interface list\n");

#ifdef HAVE_SOCKADDR_SA_LEN
	debug("Using HAVE_SOCKADDR_SA_LEN method for finding addresses.\n");
#endif

	for (x = ifc.ifc_buf; x < (ifc.ifc_buf + ifc.ifc_len); x += salen)
	{
		ifrp = (struct ifreq *)x;

		memset(&ifr, 0, sizeof(struct ifreq));
		strcpy(ifr.ifr_name, ifrp->ifr_name);

#ifdef HAVE_SOCKADDR_SA_LEN

		salen = sizeof(ifrp->ifr_name) + ifrp->ifr_addr.sa_len;
		if (salen < sizeof(*ifrp))
			salen = sizeof(*ifrp);

		addr = ((struct sockaddr_in *)&ifrp->ifr_addr)->sin_addr.s_addr;
		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
			pfatal("ioctl(SIOCGIFFLAGS)");

#else  /* HAVE_SOCKADDR_SA_LEN */

		salen = sizeof(*ifrp);

		if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
			pfatal("ioctl(SIOCGIFADDR)");
		addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

#endif /* HAVE_SOCKADDR_SA_LEN else */

#ifdef AF_INET6
		if (ifrp->ifr_addr.sa_family == AF_INET6)
		{
			debug("Ignoring AF_INET6 address on interface %s\n",
				sprintable(ifr.ifr_name));
			continue;
		}
#endif

		if (ifrp->ifr_addr.sa_family != AF_INET &&
			ifrp->ifr_addr.sa_family != AF_LINK)
		{
			debug("Ignoring non-AF_INET address on interface %s\n",
				sprintable(ifr.ifr_name));
			continue;
		}

		if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0)
			pfatal("ioctl(SIOCGIFFLAGS)");
		if ((ifr.ifr_flags & IFF_UP) == 0)
		{
			debug("Ignoring down interface %s\n",
				sprintable(ifr.ifr_name));
			continue;
		}

		/* Deal with virtual hosts */
		for (i = 0; ifr.ifr_name[i]; i++)
			if (ifr.ifr_name[i] == ':')
				ifr.ifr_name[i] = '\0';

		/* Grow another node on the linked list... */
		if (!p)
			p = interfaces = xrealloc(NULL, sizeof(struct interface_entry));
		else
			p = p->next = xrealloc(NULL, sizeof(struct interface_entry));

		p->next = NULL;

		/* ... and fill it in */
		p->addr = addr;
		p->name = xrealloc(NULL, strlen(ifr.ifr_name) + 1);
		strcpy(p->name, ifr.ifr_name);

		debug("Discovered interface %s with address %s\n",
			sprintable(p->name), iptos(p->addr));
	}

	free(ifc.ifc_buf);
	debug("leaving getinterfaces()\n");
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
 * Find an appropriate device to use given the specified source address.
 * However, if we find an interface matching the global dst_ip address, set
 * the source address we're looking for to 127.0.0.1 in an attempt to select
 * the loopback.  Ofcourse, this entirely depends on the fact that a loopback
 * interface exists with an address of 127.0.0.1.
 */

char *finddev(u_long with_src)
{
	struct interface_entry *p;
	char *device = NULL;

	debug("entering finddev()\n");

	/* First, see if we're trying to trace to ourself */
	for (p = interfaces; p; p = p->next)
		if (p->addr == dst_ip)
		{
			debug("Destination matches local address of interface %s;\n\tattempting to find loopback interface, o_nofilter set\n", p->name);
			with_src = hosttoip("127.0.0.1", LIBNET_DONT_RESOLVE);
			o_nofilter = 1;
		}

	for (p = interfaces; p; p = p->next)
		if (p->addr == with_src)
			device = p->name;
	
	debug("finddev() returning %s\n", device);
	return device;
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

#ifndef ALLOCATEID_CACHE_SIZE
#define ALLOCATEID_CACHE_SIZE 512
#endif

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
 * What a kludge, but it works.  The aim is to be as compatible as possible
 * with traceroute(8), with the one exception that if for the same hop we
 * receive a response from two different hosts, display the second host on
 * a new line, as Cisco does.  This drastically improves readability when
 * tracing through links which have per-packet, round-robin load balancing.
 */

void showprobe(proberecord *record)
{
	/* Variables to keep state between calls */
	static char laststate[TEXTSIZE];
	static int lastttl;
	static u_long lastaddr;
	static int everprint;

	int printflag = 0;

	/* kludge to make debug mode usable */
	if (o_debug)
	{
		fflush(stdout);
		fprintf(stderr, "debug: displayed hop\n");
		fflush(stderr);
	}

	/* ttl */
	if (lastttl != record->ttl)
	{
		printf("%2d  ", record->ttl);
		printflag = 1;
		everprint = 0;
		safe_strncpy(laststate, "", TEXTSIZE);
	}
	else if (lastaddr != record->addr && record->addr != INADDR_ANY && lastaddr != INADDR_ANY)
	{
		printf("\n    ");
		printflag = 1;
	}

	/* host */
	if ((printflag || !everprint) && record->addr != INADDR_ANY)
	{
		if (record->q > 1 && lastaddr == INADDR_ANY)
			printf(" ");

		printf("%s (%s)", iptohost(record->addr), iptos(record->addr));
		everprint = 1;
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

/*
 * Useful for debugging; dump #define's and command line options.
 */

void debugoptions(void)
{
	if (! o_debug)
		return;

	debug("debugoptions():\n");

	/*
	 * TEXTSIZE SNAPLEN IPTOSBUFFERS ALLOCATEID_CACHE_SIZE device datalink
	 * datalinkname(datalink) datalinkoffset(datalink) o_minttl o_maxttl
	 * o_timeout o_debug o_numeric o_pktlen o_nqueries o_dontfrag o_tos
	 * o_forceport o_syn o_ack o_ecn o_nofilter o_nogetinterfaces o_trackport
	 */

	debug("%16s: %-2d %14s: %-2d %16s: %-2d\n",
		"TEXTSIZE", TEXTSIZE,
		"SNAPLEN", SNAPLEN,
		"IPTOSBUFFERS", IPTOSBUFFERS);

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"ALLOCATEID_CACHE", ALLOCATEID_CACHE_SIZE,
		"datalink", datalink,
		"datalinkoffset", datalinkoffset(datalink));

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"o_minttl", o_minttl,
		"o_maxttl", o_maxttl,
		"o_timeout", o_timeout);

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"o_debug", o_debug,
		"o_numeric", o_numeric,
		"o_pktlen", o_pktlen);

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"o_nqueries", o_nqueries,
		"o_dontfrag", o_dontfrag,
		"o_tos", o_tos);

	debug("%16s: %-2d %16s: %-2d %16s: %-2d\n",
		"o_forceport", o_forceport,
		"o_syn", o_syn,
		"o_ack", o_ack);

	debug("%16s: %-2d %16s: %d %16s: %-2d\n",
		"o_ecn", o_ecn,
		"o_nofilter", o_nofilter,
		"o_nogetinterfaces", o_nogetinterfaces);

	debug("%16s: %-2d %16s: %-12s %s: %s\n",
		"o_trackport", o_trackport,
		"datalinkname", datalinkname(datalink),
		"device", device);

	debug("%16s: %-2d\n",
		"o_noselect", o_noselect);
}

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

	if ((serv = getservbyport(dst_prt, "tcp")) == NULL)
		safe_snprintf(dst_prt_name, TEXTSIZE, "%d", dst_prt);
	else
		safe_snprintf(dst_prt_name, TEXTSIZE, "%d (%s)", dst_prt, serv->s_name);

	if (! (o_syn|o_ack))
	{
		debug("Setting o_syn, in absence of either o_syn or o_ack\n");
		o_syn = 1;
	}

	debugoptions();

	fprintf(stderr, "Selected device %s, address %s", device, iptos(src_ip));
	if (! o_trackport) fprintf(stderr, ", port %d", src_prt);
	fprintf(stderr, " for outgoing packets\n");
}

/*
 * Initialize the libnet library context.
 */

void initlibnet()
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
 * Open the pcap listening device, and apply our filter.
 */

void initcapture(void)
{
	struct bpf_program fcode;
	bpf_u_int32 localnet, netmask;

	if (! (pcap = pcap_open_live(device, offset + SNAPLEN, 0, 10, errbuf)))
		fatal("pcap_open_live failed: %s", errbuf);

	safe_snprintf(filter, TEXTSIZE, "\n		(tcp and src host %s and src port %d and dst host %s)\n		or ((icmp[0] == 11 or icmp[0] == 3) and dst host %s)",
			iptos(dst_ip), dst_prt, iptos(src_ip), iptos(src_ip));

	if (o_nofilter)
		filter[0] = '\0';

	debug("pcap filter is: %s\n", o_nofilter ? "(nothing)" : filter);

	localnet = 0;
	netmask = 0;

	if (pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0)
		fatal("pcap_lookupnet failed: %s\n", errbuf);

	if (pcap_compile(pcap, &fcode, filter, 1, netmask) < 0)
		fatal("filter compile failed: %s", pcap_geterr(pcap));

	if (pcap_setfilter(pcap, &fcode) < 0)
		fatal("pcap_setfilter failed\n");

	pcap_fd = pcap_fileno(pcap);
	if (fcntl(pcap_fd, F_SETFL, O_NONBLOCK) < 0)
		pfatal("fcntl(F_SETFL, O_NONBLOCK) failed");
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

		debug("Payload: %s\n", sprintable(payload));
	}

	/* Set some values of the probe record */
	record->q = q;
	record->ttl = ttl;
	record->addr = INADDR_ANY;
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
		0,						/* seq number	*/
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
		0,						     /* seq number	        */
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
 * Horrible macro kludge, to be called only from capture(), for architectures
 * such as sparc that don't allow non-aligned memory access.  The idea is to
 * malloc new space (which is guaranteed to be properly aligned), copy the
 * packet we want to parse there, then cast the packet header struct against
 * the new, aligned space.
 */

#define ALIGN_PACKET(dest, cast, offset) do { \
		static u_char *buf; \
		if (buf == NULL) buf = xrealloc(NULL, SNAPLEN - (offset)); \
		memcpy(buf, packet + (offset), len - (offset)); \
		dest = (struct cast *)buf; \
	} while (0) /* no semi-colon */

/*
 * Listens for responses to our probe matching the specified proberecord
 * structure.  Returns 1 if the destination was reached, or 0 if we need to
 * increment the TTL some more.
 */

int capture(proberecord *record)
{
	u_char *packet;
	struct pcap_pkthdr packet_hdr;
	struct libnet_ipv4_hdr *ip_hdr;
	struct timeval start, now, timepassed, timeout_tv, timeleft;
	int firstpass, ret, len;
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
				debug("timeout\n");
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

		FD_ZERO(&sfd);
		FD_SET(pcap_fd, &sfd);

		ret = o_noselect ? 1 : select(pcap_fd + 1, &sfd, NULL, NULL, &timeleft);

		if (ret < 0)
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

		debug("received %d byte IP packet from pcap_next()\n", len);

		if (len < LIBNET_IPV4_H)
		{
			debug("Ignoring partial IP packet\n");
			continue;
		}

		if (len > SNAPLEN)
		{
			debug("Packet received is larger than our snaplen?  Ignoring\n", SNAPLEN);
			continue;
		}

		ALIGN_PACKET(ip_hdr, libnet_ipv4_hdr, 0);

		if (ip_hdr->ip_v != 4)
		{
			debug("Ignoring non-IPv4 packet\n");
			continue;
		}

		if (ip_hdr->ip_hl > 5)
		{
			debug("Ignoring IP packet with IP options\n");
			continue;
		}

		if (ip_hdr->ip_dst.s_addr != src_ip)
		{
			debug("Ignoring IP packet not addressed to us (%s, not %s)\n",
				iptos(ip_hdr->ip_dst.s_addr), iptos(src_ip));
			continue;
		}

		delta = (double)(packet_hdr.ts.tv_sec - record->timestamp.tv_sec) * 1000 +
			(double)(packet_hdr.ts.tv_usec - record->timestamp.tv_usec) / 1000;

		if (ip_hdr->ip_p == IPPROTO_ICMP)
		{
			struct libnet_icmpv4_hdr *icmp_hdr;
			struct libnet_ipv4_hdr *old_ip_hdr;
			struct libnet_tcp_hdr *old_tcp_hdr;

			if (len < LIBNET_IPV4_H + LIBNET_ICMPV4_H + 4)
			{
				debug("Ignoring partial icmp packet\n");
				continue;
			}

			ALIGN_PACKET(icmp_hdr, libnet_icmpv4_hdr, 0 + LIBNET_IPV4_H);
			debug("Received icmp packet\n");

			/*
			 * The IP header, plus eight bytes of it's payload that generated
			 * the ICMP packet is quoted here, prepended with four bytes of
			 * padding.
			 */

			if (len < LIBNET_IPV4_H + LIBNET_ICMPV4_H + 4 + LIBNET_IPV4_H + 8)
			{
				debug("Ignoring icmp packet with incomplete payload\n");
				continue;
			}

			ALIGN_PACKET(old_ip_hdr, libnet_ipv4_hdr,
				0 + LIBNET_IPV4_H + LIBNET_ICMPV4_H + 4);

			/*
			 * The entire TCP header isn't here, but the source port,
			 * destination port, and sequence number fiels are.
			 */

			ALIGN_PACKET(old_tcp_hdr, libnet_tcp_hdr,
				0 + LIBNET_IPV4_H + LIBNET_ICMPV4_H + 4 + LIBNET_IPV4_H);

			if (old_ip_hdr->ip_v != 4)
			{
				debug("Ignoring ICMP packet which quotes a non-IPv4 packet\n");
				continue;
			}

			if (old_ip_hdr->ip_hl > 5)
			{
				debug("Ignoring ICMP packet which quotes an IP packet with IP options\n");
				continue;
			}

			if (old_ip_hdr->ip_dst.s_addr != dst_ip)
			{
				debug("Ignoring ICMP packet with incorrect quoted destination (%s, not %s)\n",
					iptos(old_ip_hdr->ip_dst.s_addr), iptos(dst_ip));
				continue;
			}

			if (old_ip_hdr->ip_src.s_addr != src_ip)
			{
				debug("Ignoring ICMP packet with incorrect quoted source (%s, not %s)\n",
					iptos(old_ip_hdr->ip_src.s_addr), iptos(src_ip));
				continue;
			}

			/* These are not the droids you are looking for */
			if (old_ip_hdr->ip_p != IPPROTO_TCP)
			{
				debug("Ignoring ICMP packet which doesn't quote a TCP header\n");
				continue;
			}

			/* We are free to go about our business */
			if (! o_trackport && (ntohs(old_ip_hdr->ip_id) != record->id))
			{
				debug("icmp packet doesn't contain the id we sent\n");
				continue;
			}

			/* Move along, move along */
			if ((ntohs(old_tcp_hdr->th_sport) != record->src_prt)
				|| (ntohs(old_tcp_hdr->th_dport) != dst_prt))
			{
				debug("icmp packet doesn't contain the correct tcp port numbers\n");
				continue;
			}

			if (icmp_hdr->icmp_type == ICMP_UNREACH)
			{
				char s[TEXTSIZE];

				switch(icmp_hdr->icmp_code)
				{
					case ICMP_UNREACH_NET:
						safe_strncpy(s, "!N", TEXTSIZE); break;

					case ICMP_UNREACH_HOST:
						safe_strncpy(s, "!H", TEXTSIZE); break;

					case ICMP_UNREACH_PROTOCOL:
						safe_strncpy(s, "!P", TEXTSIZE); break;

					case ICMP_UNREACH_PORT:
						safe_strncpy(s, "!p", TEXTSIZE); break;

					case ICMP_UNREACH_NEEDFRAG:
						safe_strncpy(s, "!F", TEXTSIZE); break;

					case ICMP_UNREACH_SRCFAIL:
						safe_strncpy(s, "!S", TEXTSIZE); break;

					case ICMP_UNREACH_NET_PROHIB:
					case ICMP_UNREACH_FILTER_PROHIB:
						safe_strncpy(s, "!A", TEXTSIZE); break;

					case ICMP_UNREACH_HOST_PROHIB:
						safe_strncpy(s, "!C", TEXTSIZE); break;

					case ICMP_UNREACH_NET_UNKNOWN:
					case ICMP_UNREACH_HOST_UNKNOWN:
						safe_strncpy(s, "!U", TEXTSIZE); break;

					case ICMP_UNREACH_ISOLATED:
						safe_strncpy(s, "!I", TEXTSIZE); break;

					case ICMP_UNREACH_TOSNET:
					case ICMP_UNREACH_TOSHOST:
						safe_strncpy(s, "!T", TEXTSIZE); break;

					case ICMP_UNREACH_HOST_PRECEDENCE:
					case ICMP_UNREACH_PRECEDENCE_CUTOFF:
					default:
						safe_snprintf(s, TEXTSIZE, "!<%d>", icmp_hdr->icmp_code);
				}

				record->delta = delta;
				record->addr = ip_hdr->ip_src.s_addr;
				safe_snprintf(record->string, TEXTSIZE, "%%.3f ms %s", s);
				return 1;
			}

			if (icmp_hdr->icmp_type == ICMP_TIMXCEED)
			{
				record->delta = delta;
				record->addr = ip_hdr->ip_src.s_addr;
				safe_strncpy(record->string, "%.3f ms", TEXTSIZE);
				return 0;
			}

			if (icmp_hdr->icmp_type != ICMP_TIMXCEED &&
				icmp_hdr->icmp_type != ICMP_UNREACH)
			{
				record->delta = delta;
				record->addr = ip_hdr->ip_src.s_addr;
				safe_strncpy(record->string, "%.3f ms -- Unexpected ICMP", TEXTSIZE);
				return 0;
			}

			fatal("Something bad happened\n");
		}

		if (ip_hdr->ip_p == IPPROTO_TCP)
		{
			struct libnet_tcp_hdr *tcp_hdr;

			if (ip_hdr->ip_src.s_addr != dst_ip)
			{
				debug("tcp packet's origin does not match our target's address (%s, not %s)\n",
					iptos(ip_hdr->ip_src.s_addr), iptos(dst_ip));
				continue;
			}

			if (len < LIBNET_IPV4_H + LIBNET_TCP_H)
			{
				debug("Ignoring partial tcp packet\n");
				continue;
			}

			ALIGN_PACKET(tcp_hdr, libnet_tcp_hdr, 0 + LIBNET_IPV4_H);

			debug("Received tcp packet %s:%d -> %s:%d, flags %s%s%s%s%s%s%s%s%s\n",
				iptos(ip_hdr->ip_src.s_addr), ntohs(tcp_hdr->th_sport),
				iptos(ip_hdr->ip_dst.s_addr), ntohs(tcp_hdr->th_dport),
					tcp_hdr->th_flags & TH_RST  ? "RST " : "",
					tcp_hdr->th_flags & TH_SYN  ? "SYN " : "",
					tcp_hdr->th_flags & TH_ACK  ? "ACK " : "",
					tcp_hdr->th_flags & TH_PUSH ? "PSH " : "",
					tcp_hdr->th_flags & TH_FIN  ? "FIN " : "",
					tcp_hdr->th_flags & TH_URG  ? "URG " : "",
					tcp_hdr->th_flags & TH_CWR  ? "CWR " : "",
					tcp_hdr->th_flags & TH_ECN  ? "ECN " : "",
					tcp_hdr->th_flags ? "" : "(none)");

			if ((ntohs(tcp_hdr->th_sport) != dst_prt)
				|| (ntohs(tcp_hdr->th_dport) != record->src_prt))
			{
				debug("tcp packet doesn't contain the correct port numbers\n");
				continue;
			}

			if (tcp_hdr->th_flags & TH_RST)
				safe_strncpy(record->state, "closed", TEXTSIZE);

			else if ((tcp_hdr->th_flags & TH_SYN)
					&& (tcp_hdr->th_flags & TH_ACK)
					&& (tcp_hdr->th_flags & TH_ECN))
				safe_strncpy(record->state, "open, ecn", TEXTSIZE);

			else if ((tcp_hdr->th_flags & TH_SYN)
					&& (tcp_hdr->th_flags & TH_ACK))
				safe_strncpy(record->state, "open", TEXTSIZE);

			else
				safe_snprintf(record->state, TEXTSIZE, "unknown,%s%s%s%s%s%s%s%s%s",
					tcp_hdr->th_flags & TH_RST  ? " RST" : "",
					tcp_hdr->th_flags & TH_SYN  ? " SYN" : "",
					tcp_hdr->th_flags & TH_ACK  ? " ACK" : "",
					tcp_hdr->th_flags & TH_PUSH ? " PSH" : "",
					tcp_hdr->th_flags & TH_FIN  ? " FIN" : "",
					tcp_hdr->th_flags & TH_URG  ? " URG" : "",
					tcp_hdr->th_flags & TH_CWR  ? " CWR" : "",
					tcp_hdr->th_flags & TH_ECN  ? " ECN" : "",
					tcp_hdr->th_flags ? "" : " no flags");

			record->delta = delta;
			record->addr = ip_hdr->ip_src.s_addr;
			safe_strncpy(record->string, "%.3f ms", TEXTSIZE);
			return 1;
		}

		debug("Ignoring non-ICMP and non-TCP received packet\n");
		continue;
	}
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

			done += capture(record);

			showprobe(record);
			freeproberecord(record);
		}
	}

	if (!done)
		fprintf(stderr, "Destination not reached\n");

	return done ? 0 : 1;
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
	o_noselect = 0;
	o_nogetinterfaces = 0;

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
				debug("tcptraceroute %s\n", VERSION);
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
	seteuid(getuid());
	exitcode = trace();
#if (LIBNET_API_VERSION >= 110)
	libnet_destroy(libnet_context);
#endif
	return exitcode;
}
