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
#include <stdarg.h>

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
	printf("\n%s %s\n%s\n", PACKAGE, VERSION, BANNER);
    fatal("\
Usage: %s [-nNFSAE] [-i <interface>] [-f <first ttl>]\n\
       [-l <packet length>] [-q <number of queries>] [-t <tos>]\n\
       [-m <max ttl>] [-pP] <source port>] [-s <source address>]\n\
       [-w <wait time>] <host> [destination port] [packet length]\n\n", name);
}

void about(void)
{
	printf("\n%s %s\n%s\n", PACKAGE, VERSION, BANNER);
	exit(0);
}

/*
 * realloc(3) or bust!
 */

void *xrealloc(void *oldp, int size)
{
	void *p;

	if (!oldp)
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

char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][IPTOSBUFSIZ];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	safe_snprintf(output[which], IPTOSBUFSIZ, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
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

	return (char *)libnet_addr2name4(in,
		o_numeric > 0 ? LIBNET_DONT_RESOLVE : LIBNET_RESOLVE);
}

/*
 * Useful for debugging; dump #define's and command line options.
 */

void debugoptions(void)
{
	if (! o_debug)
		return;

	debug("debugoptions():\n");

	debug("%16s: %-2d %14s: %-2d %16s: %-2d\n",
		"TEXTSIZE", TEXTSIZE,
		"SNAPLEN", SNAPLEN,
		"IPTOSBUFFERS", IPTOSBUFFERS);

	debug("%16s: %-3d %15s: %-2d %16s: %-2d\n",
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

	debug("%16s: %-2d %16s: %-2d %16s: %-10ld\n",
		"o_noselect", o_noselect,
		"o_dnat", o_dnat,
		"isn", isn);
}
