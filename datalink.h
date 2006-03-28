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

/* array of supported datalink types */
extern struct datalinktype {
	int type, offset;
	char *name;
} datalinktypes[];

/* interface linked list, built by getinterfaces() */
extern struct interface_entry {
	char *name;
	u_long addr;
	struct interface_entry *next;
} *interfaces;

int datalinkoffset(int);
char *datalinkname(int);
void getinterfaces(void);
u_long findsrc(u_long);
char *finddev(u_long);
