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
#include <arpa/inet.h>
#include <libnet.h>
#include <pcap.h>

/* Some earlier versions lacked support for double <net/if.h> inclusion */
#ifndef __OpenBSD__
#include <net/if.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define BANNER "Copyright (c) 2001-2006 Michael C. Toren <mct@toren.net>\n\
Updates are available from http://michael.toren.net/code/tcptraceroute/\n"

/* Buffer size used for a number of strings, including the pcap filter */
#define TEXTSIZE	1024

/* For compatibility with older versions of libnet */
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

#include "datalink.h"
#include "util.h"
#include "probe.h"
#include "capture.h"

extern u_long dst_ip, src_ip, isn;
extern u_short src_prt, dst_prt;
extern char *device, *name, *dst, *src;
extern char dst_name[], dst_prt_name[], filter[], errbuf[];
extern int datalink, offset;
extern int o_minttl, o_maxttl, o_timeout, o_debug, o_numeric, o_pktlen,
	o_nqueries, o_dontfrag, o_tos, o_forceport, o_syn, o_ack, o_ecn,
	o_nofilter, o_nogetinterfaces, o_noselect, o_trackport, o_dnat,
	o_isn;

extern char *optarg;
extern int optind, opterr, optopt;
