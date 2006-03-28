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

#if (LIBNET_API_VERSION < 110)
	extern int sockfd;
#else
	extern libnet_t *libnet_context;
#endif

/* ECN (RFC2481) */
#ifndef TH_ECN
#define TH_ECN  0x40
#endif
#ifndef TH_CWR
#define TH_CWR  0x80
#endif

/* How many IP IDs should allocateid() remember? */
#define ALLOCATEID_CACHE_SIZE 512

/* probe() returns this structure, which describes the probe packet sent */
typedef struct {
	int ttl, q;
	u_short id, src_prt, dnat_dport;
	struct timeval timestamp;
	double delta;
	u_long addr, dnat_ip;
	char *state;
	char *string;
} proberecord;

proberecord *newproberecord(void);
void freeproberecord(proberecord *);
u_short allocateport(u_short);
u_short allocateid(void);
void showprobe(proberecord *);
void initlibnet(void);
void probe(proberecord *, int, int);
