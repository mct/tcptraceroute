#!/usr/bin/perl -w -T
#
# (c) Copyright 2001, Michael C. Toren <mct@toren.net>
#
# mct, Fri Jul 20 15:33:21 EDT 2001
# mct, Wed Aug  1 14:39:36 EDT 2001
# mct, Tue Mar 30 08:45:08 EST 2004
#

use CGI;
use strict;

my ($q, $me, $bin, $host, $type, $validhost, $validtype, @command);

$q = new CGI;
$me = (split /\?/, $q->self_url)[0] || "";
$host = $q->param("h") || ($q->keywords)[0] || "";
$type = $q->param("t") || "u";
$ENV{PATH} = "/usr/sbin";

$validhost = ($host =~ /^[a-z0-9_\.]+$/i) ? $host : "";
$validtype = ($type =~ /^[tiu]$/) ? $type : "u";

$bin = {
    t => { string => "TCP",  command => [ qw(/usr/bin/tcptraceroute  ) ] },
    u => { string => "UDP",  command => [ qw(/usr/sbin/traceroute    ) ] },
    i => { string => "ICMP", command => [ qw(/usr/sbin/traceroute -I ) ] }
};

print $q->header("text/html"), <<"	!";
	<html>
	<head>
	<title>Traceroute CGI Gateway</title>
	</head>
	<body bgcolor="#FFFFFF" text="#000000" link="#0000FF"
		vlink="#551A8B" alink="#0000FF">
	<center>
	<br>

	<center>
	<font size="7"><tt><b>traceroute CGI gateway</b></tt></font>
	</center>

	<br>

	<form method=get action=$me>
	Host: &nbsp; &nbsp; <input type=text name=h
		value=${\( $validhost ? $validhost : $ENV{REMOTE_ADDR} )}>
        &nbsp; &nbsp;

	&nbsp; &nbsp; UDP  <input type=radio name=t
	    value=u ${\( $validtype eq "u" ? "checked" : "" )}>
	&nbsp; &nbsp; ICMP <input type=radio name=t
	    value=i ${\( $validtype eq "i" ? "checked" : "" )}>
	&nbsp; &nbsp; <a href=http://michael.toren.net/code/tcptraceroute>TCP</a>
	    <input type=radio name=t
	    value=t ${\( $validtype eq "t" ? "checked" : "" )}>

	&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; <input type=submit value=Go>
	</form>

	</center>
	!

exit unless ($host);

unless ($validhost)
{
    print <<"	!";
	<blockquote>
	<font color=red>ERROR:</font> &nbsp; Invalid hostname!
	</blockquote>
	</body>
	</html>
	!
    exit;
}

$| = 1;
close STDERR;
open STDERR, ">&STDOUT";
@command = (@{ $bin->{$validtype}->{command} }, $validhost);

print "<br><hr width=50%><br><br>\n";
print "% <b>", join(" ", @command), "</b>\n<pre>\n"; 
#     $bin->{$validtype}->{string}, " packets.\n<pre>\n";

system { $command[0] } @command;
print <<"	!";
	</pre>
	</body>
	</html>
	!

exit;
