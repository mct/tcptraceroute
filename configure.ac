#                                               -*- Autoconf -*-
#                           vim:set syntax=conf nowrap sw=4 ts=4:
# Process this file with autoconf to produce a configure script.

# Initialization.
AC_PREREQ(2.50)

AC_INIT(tcptraceroute,`cat VERSION`)
AC_CONFIG_SRCDIR(main.c)
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR(main.c)
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AC_PROG_CC
AC_PROG_GCC_TRADITIONAL
if test "$GCC" = yes ; then
	CFLAGS="$CFLAGS -Wall"
fi
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_FUNC(gethostbyname, ,[AC_CHECK_LIB(nsl, gethostbyname)])
AC_CHECK_FUNC(socket, ,[AC_CHECK_LIB(socket, socket)])
AC_CHECK_FUNC(connect, ,[AC_CHECK_LIB(inet, connect)])
AC_CHECK_FUNC(inet_aton, ,[AC_CHECK_LIB(resolv, inet_aton)])

AC_ARG_WITH(pcap, [],
	[
		AC_MSG_ERROR([Please use "--with-libpcap=DIR", not "--with-pcap=DIR"])
	],
	[])

AC_ARG_WITH(libpcap, AC_HELP_STRING([--with-libpcap=DIR], [use libpcap in DIR]),
	[
		LIBPCAPCC=""
		LIBPCAPLD=""

		test -f "$withval/pcap.h"			&&	LIBPCAPCC="$LIBPCAPCC -I$withval"
		test -d "$withval/bpf"				&&	LIBPCAPCC="$LIBPCAPCC -I$withval/bpf"
		test -f "$withval/include/pcap.h"	&&	LIBPCAPCC="$LIBPCAPCC -I$withval/include"

		test -f "$withval/pcap.a"			&&	LIBPCAPLD="$LIBPCAPLD -L$withval"
		test -f "$withval/libpcap.a"		&&	LIBPCAPLD="$LIBPCAPLD -L$withval"
		test -f "$withval/lib/pcap.a"		&&	LIBPCAPLD="$LIBPCAPLD -L$withval/lib"
		test -f "$withval/lib/libpcap.a"	&&	LIBPCAPLD="$LIBPCAPLD -L$withval/lib"

		if test -z "$LIBPCAPCC" -o -z "$LIBPCAPLD"
		then
			AC_MSG_ERROR([No valid libpcap library found in $withval])
		else
			CPPFLAGS="$CPPFLAGS $LIBPCAPCC"
			LDFLAGS="$LDFLAGS $LIBPCAPLD"
			AC_MSG_NOTICE([using libpcap in $withval])
		fi
	], [])

LIBNET_CONFIG="libnet-config"	# relative, using $PATH
AC_ARG_WITH(libnet, AC_HELP_STRING( [--with-libnet=DIR], [use libnet in DIR]),
	[
		LIBNETCC=""
		LIBNETLD=""

		test -x "$withval/bin/libnet-config" &&	LIBNET_CONFIG="$withval/bin/libnet-config"
		test -x "$withval/libnet-config"	 &&	LIBNET_CONFIG="$withval/libnet-config"

		test -f "$withval/libnet.h"			&&	LIBNETCC="$LIBNETCC -I$withval"
		test -f "$withval/include/libnet.h"	&&	LIBNETCC="$LIBNETCC -I$withval/include"

		test -f "$withval/libnet.a"			&&	LIBNETLD="$LIBNETLD -L$withval"
		test -f "$withval/lib/libnet.a"		&&	LIBNETLD="$LIBNETLD -L$withval/lib"

		if test -z "$LIBNETCC" -o -z "$LIBNETLD"
		then
			AC_MSG_ERROR([No valid libnet library found in $withval])
		else
			CPPFLAGS="$CPPFLAGS $LIBNETCC"
			LDFLAGS="$LDFLAGS $LIBNETLD"
			AC_MSG_NOTICE([using libnet in $withval])
		fi
	], [])

AC_CHECK_LIB(pcap, pcap_open_live, [], [AC_MSG_ERROR([cannot find libpcap])])

# Libnet underwent a major API change in between version 1.0.2a and 1.1.0.
# The code below sets the preprocessor symbol LIBNET_API_VERSION to 100 if a
# pre-1.1.0 version of libnet is being used, and to 110 if version 1.1.0 or
# greater is being used.
# 
# It would've been simpler to just have a HAVE_LIBNET_110 symbol or the like,
# but this way, if there are more incompatible API changes in the future, the
# values assigned to LIBNET_API_VERSION can be updated accordingly.

AC_CHECK_LIB(net, main, [], [AC_MSG_ERROR([cannot find libnet])])
AC_CHECK_LIB(net, libnet_init_packet,
	[
		AC_DEFINE(LIBNET_API_VERSION, 100, [libnet API version])
		AC_MSG_NOTICE([libnet version: < 1.1.0])
		CPPFLAGS="$CPPFLAGS `$LIBNET_CONFIG --defines`"
		CPPFLAGS="$CPPFLAGS `$LIBNET_CONFIG --cflags`"
	], [
		AC_CHECK_LIB(net, libnet_init,
			[
				AC_DEFINE(LIBNET_API_VERSION, 110, [libnet API version])
				AC_MSG_NOTICE([libnet version: >= 1.1.0])
			], [
				AC_MSG_ERROR([could not identify the version of libnet])
			])
	])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_TIME

# Check to see if socket.sa_len exists.  Adapted from the configure.in of _Unix
# Network Programming_ second edition example code, by W. Richard Stevens.
AC_MSG_CHECKING(for sockaddr.sa_len)
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([
#include <sys/types.h>
#include <sys/socket.h>
	],
		[ unsigned int i = sizeof(((struct sockaddr *)0)->sa_len) ])],
	[
		AC_MSG_RESULT(yes)
		AC_DEFINE([HAVE_SOCKADDR_SA_LEN], 1, [Has socket.sa_len])
	], [
		AC_MSG_RESULT(no)
	])

AC_CHECK_MEMBER([struct sockaddr.sa_len],
	[AC_DEFINE([HAVE_SOCKADDR_SA_LEN], 1, [Has socket.sa_len])],
	[],
	[#include <sys/types.h>
		#include <sys/socket.h>])

# Checks for library functions.
AC_FUNC_MALLOC
# AC_FUNC_REALLOC	# our util.c:xrealloc() function deals with the
					# realloc(0,0) case, and AC_FUNC_REALLOC doesn't
					# appear to break on HP/UX systems.
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gettimeofday memset select socket strchr])

# Is this Solaris?
AC_MSG_CHECKING(for Solaris)
AC_RUN_IFELSE([AC_LANG_PROGRAM( [], [
#if defined (__SVR4) && defined (__sun)
	exit(0);
#else
	exit(-1);
#endif
		])
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE([HAVE_SOLARIS], 1, [Is this a Solaris system?])
		HAVE_SOLARIS=yes
	],[
		AC_MSG_RESULT(no)
	])

# Is this BSDI?
AC_MSG_CHECKING(for BSDI)
AC_RUN_IFELSE([AC_LANG_PROGRAM( [], [
#if defined (__bsdi__)
	exit(0);
#else
	exit(-1);
#endif
		])
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE([HAVE_BSDI], 1, [Is this a BSDI system?])
		HAVE_BSDI=yes
	],[
		AC_MSG_RESULT(no)
	])

# Is this NetBSD?
AC_MSG_CHECKING(for NetBSD)
AC_RUN_IFELSE([AC_LANG_PROGRAM( [], [
#if defined (__NetBSD__)
	exit(0);
#else
	exit(-1);
#endif
		])
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE([HAVE_NETBSD], 1, [Is this a NetBSD system?])
		HAVE_NETBSD=yes
	],[
		AC_MSG_RESULT(no)
	])

# Is this MacOS X?
AC_MSG_CHECKING(for MacOS X)
AC_RUN_IFELSE([AC_LANG_PROGRAM( [], [
#if defined (__APPLE__) && defined (__MACH__)
	exit(0);
#else
	exit(-1);
#endif
		])
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE([HAVE_MACOSX], 1, [Is this a MacOS X system?])
		HAVE_MACOSX=yes
	],[
		AC_MSG_RESULT(no)
	])

# Handle --enable-noselect-default
AC_ARG_ENABLE(noselect-default,
	AC_HELP_STRING([--enable-noselect-default], [default to not using select(2)]),
	[
		NOSELECT_DEFAULT=$enable_noselect_default
	], [
		if test "$HAVE_MACOSX" = "yes"; then
			NOSELECT_DEFAULT=yes
		elif test "$HAVE_BSDI" = "yes"; then
			NOSELECT_DEFAULT=yes
		elif test "$HAVE_NETBSD" = "yes"; then
			NOSELECT_DEFAULT=yes
		else
			NOSELECT_DEFAULT=no
		fi
	])
if test "$NOSELECT_DEFAULT" = "yes"; then
	AC_DEFINE(NOSELECT_DEFAULT, 1, [Use select(2) by default?])
fi

# Handle --enable-track-default=IP|PORT
AC_ARG_ENABLE(track-default,
	AC_HELP_STRING([--enable-track-default=PORT|ID], [default to tracking probes by PORT or ID]),
	[
		if test "$enable_track_default" = "id" -o "$enable_track_default" = "ID"; then
			TRACK_DEFAULT=id
		elif test "$enable_track_default" = "port" -o "$enable_track_default" = "PORT"; then
			TRACK_DEFAULT=port
		else
			AC_MSG_ERROR([valid arguments for --enable-track-default are PORT or ID])
		fi
	], [
		if test "$HAVE_SOLARIS" = "yes"; then
			TRACK_DEFAULT=port
		else
			TRACK_DEFAULT=id
		fi
	])
if test "$TRACK_DEFAULT" = "port"; then
	AC_DEFINE(TRACK_PORT_DEFAULT, 1, [Track ports by default])
fi

# Handle --enable-default-port=N
AC_ARG_ENABLE(default-port,
	AC_HELP_STRING([--enable-default-port=N], [default destination port]),
	[
		case $enable_default_port in
			[[0-9][0-9][0-9][0-9][0-9]|[0-9][0-9][0-9][0-9]|[0-9][0-9][0-9]|[0-9][0-9]|[0-9]])
				DEFAULT_PORT=$enable_default_port
				;;
			*)
				echo "default port: $enable_default_port"
				AC_MSG_ERROR([numeric argument required for --enable-default-port])
				;;
		esac
	], [
		DEFAULT_PORT=80
	])
AC_DEFINE_UNQUOTED(DEFAULT_PORT, $DEFAULT_PORT, [Default destination port])

# If using gcc, --enable-static will compile staticly
AC_ARG_ENABLE(static,
	AC_HELP_STRING([--enable-static], [compile staticly, if using gcc]),
	[
		if test "$GCC" = yes ; then
			CFLAGS="$CFLAGS -static"
		else
			AC_MSG_ERROR([Sorry, I only know how to compile staticly for gcc])
		fi
	], [])

echo "Target OS is $target_os"

AC_DEFINE_UNQUOTED(TARGET, "$target", [Target platform])
AC_CONFIG_FILES(Makefile)
AC_OUTPUT
