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

#ifndef SIOCGIFCONF
#include <sys/sockio.h> /* Solaris, maybe others? */
#endif

#ifndef AF_LINK
#define AF_LINK AF_INET /* BSD defines some AF_INET interfaces as AF_LINK */
#endif

struct interface_entry *interfaces;

/*
 * To add support for additional link layers add entries to the following
 * table.  The numbers below are believed to be correct and were obtained
 * by looking through other pcap programs, however tcptraceroute has only
 * been well tested on ethernet, PPP, and loopback interfaces.
 */

struct datalinktype datalinktypes[] = {
/*		type				offset	name			*/
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
		{
			debug("ioctl(SIOCGIFADDR) on unconfigured interface %s failed; skipping\n",
				sprintable(ifr.ifr_name));
			continue;
		}
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
	sindest.sin_port = htons(53); /* can be anything but zero */

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
