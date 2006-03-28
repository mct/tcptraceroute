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

pcap_t *pcap;
int pcap_fd;

/*
 * Open the pcap listening device and apply our filter.
 */

void initcapture(void)
{
	struct bpf_program fcode;
	bpf_u_int32 localnet, netmask;

	if (! (pcap = pcap_open_live(device, offset + SNAPLEN, 0, 10, errbuf)))
		fatal("pcap_open_live failed: %s", errbuf);

	safe_snprintf(filter, TEXTSIZE, "\n\
		(tcp and src host %s and src port %d and dst host %s)\n\
		or ((icmp[0] == 11 or icmp[0] == 3) and dst host %s)",
			iptos(dst_ip), dst_prt, iptos(src_ip), iptos(src_ip));

	if (o_nofilter)
		filter[0] = '\0';

	debug("pcap filter is: %s\n", o_nofilter ? "(nothing)" : filter);

	if (pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0)
	{
		warn("pcap_lookupnet failed: %s\n", errbuf);
		localnet = 0;
		netmask = 0;
	}

	if (pcap_compile(pcap, &fcode, filter, 1, netmask) < 0)
		fatal("filter compile failed: %s", pcap_geterr(pcap));

	if (pcap_setfilter(pcap, &fcode) < 0)
		fatal("pcap_setfilter failed\n");

	pcap_fd = pcap_fileno(pcap);

	if (pcap_fd > 100)
		fatal("Sorry, pcap_fd (%d) is too high.  Why are there so many open file descriptors?\n",
			pcap_fd);

	if (fcntl(pcap_fd, F_SETFL, O_NONBLOCK) < 0)
		pfatal("fcntl(F_SETFL, O_NONBLOCK) failed");

	pcap_freecode(&fcode);
}

/*
 * Horrible macro kludge only to be called from capture(), for architectures
 * such as sparc that don't permit non-aligned memory access.  The idea is to
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
 * structure.  Returns 1 if the destination was reached, or 0 if we need
 * to increment the TTL some more.
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
			debug("Packet received is larger than our snaplen (%d)?  Ignoring\n", SNAPLEN);
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
				debug("Ignoring partial ICMP packet\n");
				continue;
			}

			ALIGN_PACKET(icmp_hdr, libnet_icmpv4_hdr, 0 + LIBNET_IPV4_H);
			debug("Received ICMP packet\n");

			/*
			 * The IP header, plus eight bytes of it's payload that generated
			 * the ICMP packet is quoted here, prepended with four bytes of
			 * padding.
			 */

			if (len < LIBNET_IPV4_H + LIBNET_ICMPV4_H + 4 + LIBNET_IPV4_H + 8)
			{
				debug("Ignoring ICMP with incomplete payload\n");
				continue;
			}

			ALIGN_PACKET(old_ip_hdr, libnet_ipv4_hdr,
				0 + LIBNET_IPV4_H + LIBNET_ICMPV4_H + 4);

			/*
			 * The entire TCP header isn't here, but the source port,
			 * destination port, and sequence number fields are.
			 */

			ALIGN_PACKET(old_tcp_hdr, libnet_tcp_hdr,
				0 + LIBNET_IPV4_H + LIBNET_ICMPV4_H + 4 + LIBNET_IPV4_H);

			if (old_ip_hdr->ip_v != 4)
			{
				debug("Ignoring ICMP which quotes a non-IPv4 packet\n");
				continue;
			}

			if (old_ip_hdr->ip_hl > 5)
			{
				debug("Ignoring ICMP which quotes an IP packet with IP options\n");
				continue;
			}

			if (old_ip_hdr->ip_src.s_addr != src_ip)
			{
				debug("Ignoring ICMP with incorrect quoted source (%s, not %s)\n",
					iptos(old_ip_hdr->ip_src.s_addr), iptos(src_ip));
				continue;
			}

			/* These are not the droids you are looking for */
			if (old_ip_hdr->ip_p != IPPROTO_TCP)
			{
				debug("Ignoring ICMP which doesn't quote a TCP header\n");
				continue;
			}

			/* We are free to go about our business */
			if (! o_trackport && (ntohs(old_ip_hdr->ip_id) != record->id))
			{
				debug("Ignoring ICMP which doesn't contain the IPID we sent\n");
				continue;
			}

			/* Move along, move along */
			if (ntohs(old_tcp_hdr->th_sport) != record->src_prt)
			{
				debug("Ignoring ICMP which doesn't quote the correct TCP source port\n");
				continue;
			}

			if (ntohs(old_tcp_hdr->th_dport) != dst_prt)
			{
				/* Very strict checking, no DNAT detection */
				if (o_dnat < 0)
				{
					debug("Ignoring ICMP which doesn't quote the correct TCP destination port\n");
					continue;
				}

				/* DNAT detection */
				if (o_dnat > 0)
					record->dnat_dport = old_tcp_hdr->th_dport;
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
				/* If all of the fields of the IP, ICMP, quoted IP, and
				 * quoted IP payload are consistent with the probe packet we
				 * sent, yet the quoted destination address is different than
				 * the address we're trying to reach, it's likely the
				 * preceding hop was performing DNAT.
				 */

				if (old_ip_hdr->ip_dst.s_addr != dst_ip)
				{
					/* Very strict checking, no DNAT detection */
					if (o_dnat < 0)
					{
						debug("Ignoring ICMP with incorrect quoted destination (%s, not %s)\n",
							iptos(old_ip_hdr->ip_dst.s_addr), iptos(dst_ip));
						continue;
					}

					/* DNAT detection */
					if (o_dnat > 0)
						record->dnat_ip = old_ip_hdr->ip_dst.s_addr;
				}

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
			debug("Received TCP packet\n");

			if (ip_hdr->ip_src.s_addr != dst_ip)
			{
				debug("Ignoring TCP from source (%s) different than target (%s)\n",
					iptos(ip_hdr->ip_src.s_addr), iptos(dst_ip));
				continue;
			}

			if (len < LIBNET_IPV4_H + LIBNET_TCP_H)
			{
				debug("Ignoring partial TCP packet\n");
				continue;
			}

			ALIGN_PACKET(tcp_hdr, libnet_tcp_hdr, 0 + LIBNET_IPV4_H);

			debug("Received TCP packet %s:%d -> %s:%d, flags %s%s%s%s%s%s%s%s%s\n",
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
				debug("Ignoring TCP which doesn't match the correct port numbers\n");
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

		debug("Ignoring non-ICMP and non-TCP packet\n");
		continue;
	}
}
