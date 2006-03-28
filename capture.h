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

extern char pcap_version[];

extern pcap_t *pcap;
extern int pcap_fd;

/*
 * How many bytes should we examine on every packet that comes off the
 * wire?  This doesn't include the link layer which is accounted for
 * later.  We're looking only for ICMP and TCP packets, so this should
 * work.  For ICMP, we also examine the quoted IP header, which is why
 * there's a *2 there.  The +32 is just to be safe.
 */

#define SNAPLEN	 (LIBNET_IPV4_H * 2 + \
	(LIBNET_TCP_H > LIBNET_ICMPV4_H ? LIBNET_TCP_H : LIBNET_ICMPV4_H) + 32)

void initcapture(void);
int capture(proberecord *);
