#!/usr/bin/perl
#
# SSH known_hosts file bruteforcer
#
# v1.5 - Xavier Mertens <xavier(at)rootshell(dot)be>
#
# This Perl script read a SSH known_host file containing hashed hosts and try to find hostnames
# or IP addresses
#
# 20101103 : Created
# 20101116 : v1.1 added support for IP range - Pawe� R�a�ski <rozie(at)poczta(dot)onet(dot)pl>
# 20101228 : v1.2 change to NetAddr::IP, needs less memory, IPv6 ready - Pawe� R�a�ski <rozie(at)poczta(dot)onet(dot)pl>
# 20110114 : v1.3 added support for IPv6 - Pawe� R�a�ski <rozie(at)poczta(dot)onet(dot)pl>
# 20120307 : v1.4 added "Dictionary" mode - Hal Pomeranz <hal(at)deer(dash)run(dot)com>
#
# Todo
# ----
# - Increase performances
# - Consider cleaning up -i option - $MAXIP, $ipMode and so on - -r has all functions and IPv6 support.

use strict;
use warnings;
use Getopt::Std;
use Digest::HMAC_SHA1;
use MIME::Base64;
use NetAddr::IP qw(:lower);

my $MAXLEN = 8;                            # Maximum hostnames length to check
my $MAXIP  = 4294967296; # 2^32            # The whole IPv4 space

my @saltStr   = ();
my @base64Str = ();
my $idx       = 0;
my %options   = ();
my $currentPwd = undef;

sub searchHash($);

# Process the arguments
getopts("d:D:f:l:s:r:ivh", \%options);

# Some help is sometimes useful
if ($options{h}) {
        print <<EOF;
Usage: known_hosts_bruteforcer.pl [options]

  -d <domain>   Specify a domain name to append to hostnames (default: none)
  -D <file>     Specify dictionary of words to use (instead of bruteforce)
  -f <file>     Specify the known_hosts file to bruteforce (default: \$HOME/.ssh/known_hosts)
  -i            Bruteforce IP addresses (default: hostnames)
  -l <integer>  Specify the hostname maximum length (default: 8)
  -s <string>   Specify an initial IP address or password (default: none)
  -r <IP/mask>  Specify IP range to be checked
  -v            Verbose output
  -h            Print this help, then exit
EOF
        exit;
}

# SSH Keyfile to process (default: $HOME/.ssh/known_hosts)
my $knownhostFile = ($options{f} ne "") ? $options{f} : $ENV{HOME} . "/.ssh/known_hosts";
if (! -r $knownhostFile) {
        print STDERR "Cannot read file $knownhostFile ...\n";
        exit 1;
}

# Max password length (default: 8)
my $passwordLen = ($options{l} ne "") ? $options{l} : $MAXLEN;
if ($passwordLen < 1 || $passwordLen > 30) {
        print STDERR "Invalid maximum password length: $passwordLen ...\n";
        exit 1;
}

# Domain name to append
my $domainName = $options{d};

# Verbose mode
my $verbose = ($options{v}) ? 1 : 0;

# IP address mode
my $ipMode = ($options{i}) ? 1 : 0;

# IP range mode
my $ipRange = $options{r};

# Starting IP or password?
# To increase the speed of run the script across multiple computers,
# an initial hostname or IP address can be given
my $initialStr = $options{s};

# First read the known_hosts file and populate the lists
# Only hashed hosts are processed
($verbose) && print STDERR "Reading hashes from $knownhostFile ...\n";
open(HOSTFILE, "$knownhostFile") || die "Cannot open $knownhostFile";
while(<HOSTFILE>) {
        my ($hostHash, $keyType, $publicKey) = split(/ /);
        my ($dummy, $one)  = ("", "");
        if ($hostHash =~ m/\|1\|/) {
                ($dummy, $one, $saltStr[$idx], $base64Str[$idx]) = split(/\|/, $hostHash);
                $idx++;
        }
}
close(HOSTFILE);

# ---------
# Main Loop
# ---------

if (defined($options{'D'})) {
    open(INP, "< $options{'D'}") || 
        die "Unable to read dictionary file $options{'D'}: $!\n";
    while (<INP>) {
        chomp;
        if (my $line = searchHash($_)) {
            printf("*** Found host: %s (line %d) ***\n", $_, $line + 1);
        }
    }
    close(INP);
    exit();
}


my $loops=0;
# This block will be executed only for IP range check
if ($ipRange){
        print "Running IP range mode\n";
	my $block = new NetAddr::IP ($ipRange);
	my $count=$block->num();
	my $ver=$block->version();

	if ($ver == 4){
		print "IPv4 detected on input\n";
		for ($loops=0;$loops<$count;$loops++){
			my $tmpHost=$block->nth($loops);
                	my $addr=new NetAddr::IP ($tmpHost);
	                $tmpHost=($addr->addr);
			if (my $line = searchHash($tmpHost)) {
				printf("*** Found host: %s (line %d) ***\n", $tmpHost, $line + 1);
			}
			($verbose) && (($loops % 1000) == 0) && print STDERR "Testing: $tmpHost ($loops probes) ...\n";
	        }
	}
	elsif ($ver == 6){
		print "IPv6 detected on input\n";
		for ($loops=0;$loops<$count;$loops++){
                        my $tmpHost=$block->nth($loops);
                        my $addr=new NetAddr::IP ($tmpHost);
                        $tmpHost=($addr->addr);
			my $tmpHostShort=($addr->short);
                        if (my $line = searchHash($tmpHost)) {
                                printf("*** Found host: %s (line %d) ***\n", $tmpHost, $line + 1);
                        }
                        if (my $line = searchHash($tmpHostShort)) {
                                printf("*** Found host: %s (line %d) ***\n", $tmpHostShort, $line + 1);
                        }
                        ($verbose) && (($loops % 1000) == 0) && print STDERR "Testing: $tmpHost && $tmpHostShort ($loops probes) ...\n";
                }
	}
        # Inform that all was checked and finish program
        print "Whole range checked.\n";
        exit 0;
}

while(1) {
        my $initialIP = undef;
        my $tmpHost = undef;
        if ($ipMode) {
                
                # Generate an IP address using the main loop counter
                # Don't go beyond the IPv4 scope (2^32 addresses)
                if ($loops > $MAXIP) {
                        print "Done.\n";
                        exit 0;
                }

                # If we have an initial IP, check the syntax and use it
                if ($initialStr ne "") {
                        my $ip = new Net::IP($initialStr);
                        $initialIP = $ip->intip();
                }
                else {
                        $initialIP = 0;
                }
                $tmpHost = sprintf("%vd", pack("N", $loops + $initialIP));
        }
        else {
                # Generate a temporary hostname (starting with an initial value if provided)
                $tmpHost = generateHostname($initialStr);
                if (length($tmpHost) > $passwordLen) {
                        print "Done.\n";
                        exit 0;
                }

                # Append the domain name if provided
                if ($domainName) {
                        $tmpHost = $tmpHost . "." . $domainName;
                }
        }

        # In verbose mode, display a line every 1000 attempts
        ($verbose) && (($loops % 1000) == 0) && print STDERR "Testing: $tmpHost ($loops probes) ...\n";

        if (my $line = searchHash($tmpHost)) {
                printf("*** Found host: %s (line %d) ***\n", $tmpHost, $line + 1);
        }

        $loops++;
}

#
# Generate SHA1 hashes of a hostname/IP and compare it to the available hashes
# Returns the line index of the initial known_hosts file
#
sub searchHash($) {
        my $host = shift;
        ($host) || return 0;

        # Process the list containing our hashes
        # For each one, generate a new hash and compare it
        for (my $i = 0; $i < scalar(@saltStr); $i++) {
                my $decoded = decode_base64($saltStr[$i]);
                my $hmac = Digest::HMAC_SHA1->new($decoded);
                $hmac->add($host);
                my $digest = $hmac->b64digest;
                $digest .= "="; # Quick fix ;-)
                if ($digest eq $base64Str[$i]) {
                        return $i;
                }
        }
        return 0;
}

#
# Generate a hostname based on a given set of allowed caracters
# This sub-routine is based on:
# bruteforce 0.01 alpha
# Written by Tony Bhimani
# (C) Copyright 2004
# http://www.xenocafe.com
#

sub generateHostname {
        my $initialPwd = shift;

        my $alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-";
        my @tmpPwd = ();
        my $firstChar = substr($alphabet, 0, 1);
        my $lastChar = substr($alphabet, length($alphabet)-1, 1);

        # If an initial password is provided, start with this one
        if ($initialPwd ne "" && $currentPwd eq "") {
                $currentPwd = $initialPwd;
                return $currentPwd;
        }

        # No password so start with the first character in our alphabet
        if ($currentPwd eq "") {
                $currentPwd= $firstChar;
                return $currentPwd;
        }

        # If the current password is all of the last character in the alphabet
        # then reset it with the first character of the alphabet plus 1 length greater
        if ($currentPwd eq fillString(length($currentPwd), $lastChar)) {
                $currentPwd = fillString(length($currentPwd) + 1, $firstChar);
                return $currentPwd;
        }
  
        # Convert the password to an array
        @tmpPwd = split(//, $currentPwd);
  
        # Get the length of the password - 1 (zero based index)
        my $x = scalar(@tmpPwd) - 1;

        # This portion adjusts the characters
        # We go through the array starting with the end of the array and work our way backwords
        # if the character is the last one in the alphabet, we change it to the first character
        # then move to the next array character
        # if we aren't looking at the last alphabet character then we change the array character
        # to the next higher value and exit the loop
        while (1) {
                my $iTemp = getPos($alphabet, $tmpPwd[$x]);
  
                if ($iTemp == getPos($alphabet, $lastChar)) {
                        @tmpPwd[$x] = $firstChar;
                        $x--;
                } else {
                        @tmpPwd[$x] = substr($alphabet, $iTemp + 1, 1);
                        last;
                }
        }
  
        # Convert the array back into a string and return the new password to try
        $currentPwd = join("", @tmpPwd);
    
        return $currentPwd;
}

#
# Fill a string with the same caracter
#

sub fillString {
        my ($len, $char) = (shift, shift);
        my $str = "";
        for (my $i=0; $i<$len; $i++) {
                $str .= $char;
        }
        return $str;
}

#
# Return the position of a caracter in a string
#

sub getPos {
        my ($alphabet, $char) = (shift, shift);
        for (my $i=0; $i<length($alphabet); $i++) {
                if ($char eq substr($alphabet, $i, 1)) {
                        return $i;
                }
        }
}

# Eof
