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

#define IPTOSBUFFERS	12
#define IPTOSBUFSIZ		(4*3+3+1)  /* Four three-digit numbers, three dots, and NUL */

/*
 * A generic wrapper for libnet_name_resolve and libnet_name2addr4, because
 * it's annoying to have #ifdef's all over the place to support both versions
 * of libnet.
 */

#if (LIBNET_API_VERSION < 110)
#define hosttoip(hostname, numeric) \
	libnet_name_resolve((u_char *)hostname, numeric)
#else
#define hosttoip(hostname, numeric) \
	libnet_name2addr4(libnet_context, (u_char *)hostname, numeric)
#endif

void fatal(char *, ...);
void debug(char *, ...);
void warn(char *, ...);
void pfatal(char *);
void usage(void);
void about(void);
void *xrealloc(void *, int);
char *safe_strncpy(char *, char *, int);
int safe_snprintf(char *, int, char *, ...);
char *sprintable(char *);
int isnumeric(char *);
struct timeval tvdiff(struct timeval *, struct timeval *);
int tvsign(struct timeval *);
char *iptos(u_long);
char *iptohost(u_long);
void debugoptions(void);
