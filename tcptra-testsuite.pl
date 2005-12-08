#!/usr/bin/perl
# vim:set ts=4 sw=4 ai:
#
# (c) Copyright 2003, Michel C. Toren <mct@toren.net>
# mct, Sun Jun  1 23:54:39 EDT 2003

use strict;

my $tcptra = shift || "tcptraceroute";
my $host = shift || "michael.toren.net";
my $loopback = shift || "127.0.0.1";

print <<"EOT";

                    ---------------------------
                tcptraceroute test suite version 1.03
                Please send results to mct\@toren.net
                    ---------------------------

The current time is ${\(scalar localtime)} (${\(scalar gmtime)} GMT)

EOT

sub findsource($)
{
	use Socket;
	my $host = shift;
	my $udp = getprotobyname("udp") or die "getprotobyname: $!\n";
	socket(S, PF_INET, SOCK_DGRAM, $udp) or die "scoket: $!\n";
	my $s = sockaddr_in 1, (inet_aton $host or die "Unknown host: $host\n");
	connect S, $s or die "connect: $!\n";
	return inet_ntoa((sockaddr_in getsockname S)[1]);
}

sub run($)
{
	my $command = shift;
	my $output = qx($command);
	my $exit = $? >> 8;
	my $signal = $? & 127;
	$output =~ s/^/> /mg;
	$output =~ s/>\s*$//s;
	return wantarray ? ($output, $exit, $signal) : $output;
}

sub uname
{
	print "Executing 'uname -a' to determine system type:\n";
	my ($output, $exit, $signal) = run "uname -a 2>&1";
	print $output;
	print "Failed!  Exit code $exit",
		($signal ?  ", signal $signal" : ""), "\n"
			if ($exit != 0);
	print "\n";
}

sub ver
{
	print "Executing '$tcptra -d -v' to determine version:\n";
	my ($output, $exit, $signal) = run "$tcptra -d -v 2>&1";
	print $output;
	print "Failed!  Exit code $exit",
		($signal ?  ", signal $signal" : ""), "\n"
			if ($exit != 0);
	print "\n";
}

sub trace($)
{
	my $host = shift;
	print "Executing '$tcptra $host':\n";
	my ($output, $exit, $signal) = run "$tcptra $host 2>&1";
	print $output;

	print "Failed!  Exit code $exit",
		($signal ?  ", signal $signal" : ""), "\n"
			if ($exit != 0);

	print "\n";
}

sub linklayer($)
{
	my $host = shift;
	print "Attempting to determine linklayer type used to reach $host...\n";
	my ($output, $exit, $signal) = run "$tcptra -d -f 255 -m 255 -q 1 $host 2>&1";

	if ($exit != 0)
	{
		print "Failed!  Exit code $exit",
			($signal ?  ", signal $signal" : ""), "\n\n";
		return;
	}

	my ($snaplen)		= ($output =~ /^> debug:\s+.*\s+SNAPLEN: (\d+)/m);
	my ($datalink)		= ($output =~ /^> debug:\s+.*\s+datalink: (\d+)/m);
	my ($datalinkoffset)= ($output =~ /^> debug:\s+.*\s+datalinkoffset: (\d+)/m);
	my ($datalinkname)	= ($output =~ /^> debug:\s+.*\s+datalinkname: ([^\s]+)/m);
	my ($device)		= ($output =~ /^> debug:\s+.*\s+device: ([^\s]+)/m);
	my ($trackport)		= ($output =~ /^> debug:\s+.*\s+o_trackport: ([^\s]+)/m);
	my ($noselect)		= ($output =~ /^> debug:\s+.*\s+o_noselect: ([^\s]+)/m);

	print "Device $device, type $datalinkname, offset $datalinkoffset, snaplen $snaplen, o_noselect $noselect, o_trackport $trackport\n";
	print "\n";
}

uname;
ver;

print "Warning: findsource($loopback) != $loopback, but instead ",
	findsource $loopback, "?\n\n"
		unless (findsource $loopback eq $loopback);

trace "-f 1 -m 1 $loopback";
trace $host;
trace "-f 1 -m 1 " . findsource $host;
linklayer $host;
