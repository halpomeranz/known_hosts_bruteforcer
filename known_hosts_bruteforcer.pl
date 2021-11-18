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
# 20211117 : v1.5 added thread support - Adrian Popa <adrian.popa.gh(do-these-things-still-work?)gmail.com>
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
use Net::IP;
use threads;
use Thread::Pool;  # libthread-pool-perl on Debian/Ubuntu
use Math::BigInt;
use Data::Dumper;

my $MAXLEN = 8;                            # Maximum hostnames length to check
my $MAXIP  = 4294967296; # 2^32            # The whole IPv4 space

my @saltStr   = ();
my @base64Str = ();
my $idx       = 0;
my %options   = ();
my $currentPwd = undef;

sub searchHash($);

# Process the arguments
getopts("d:D:f:l:s:t:r:ivh", \%options);

# Some help is sometimes useful
if ($options{h}) {
        print <<EOF;
Usage: known_hosts_bruteforcer.pl [options]

  -d <domain>   Specify a domain name to append to hostnames (default: none)
  -D <file>     Specify dictionary of words to use (instead of bruteforce)
  -f <file>     Specify the known_hosts file to bruteforce (default: \$HOME/.ssh/known_hosts)
  -i            Bruteforce IP addresses (default: hostnames)
  -l <integer>  Specify the hostname maximum length (default: 8)
  -s <string>   Specify an initial hostname (default: none)
  -r <IP/mask>  Specify IP range to be checked
  -t <integer>  Specify how many threads to use (default: 2)
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

# Threads
my $maxThreads = $options{t} || "2";

# Starting IP or password?
# To increase the speed of run the script across multiple computers,
# an initial hostname can be given
my $initialStr = $options{s} || "";

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
($verbose) && print STDERR "Loaded $idx hashes\n";

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
#if ($ipRange){
#        print "Running IP range mode\n";
#        
#	searchIPRange($ipRange);
#        # Inform that all was checked and finish program
#        print "Whole range checked.\n";
#        exit 0;
#}


if ($ipMode || $ipRange) {

        my $prefix = $ipRange || "0.0.0.0/0";
        # if the IP range is too big (>20 for IPv4, > 110 for IPv6)
        # split it into smaller ranges, and run threaded
        my $ipPrefix = new NetAddr::IP($prefix);
        my $prefixSize = $ipPrefix->masklen();
        my $ipVersion = $ipPrefix->version();
        #($verbose) && print STDERR "Parsed prefixSize $prefixSize and version $ipVersion\n";
        my $splitSize = 20;
        $splitSize = 110 if ($ipVersion == 6);
        my @prefixes = ();
        if( $prefixSize < $splitSize ){
                # split the original prefix into lots of $splitSize
                # warning - for IPv6, this migth consume lots of memory

                my $totalAddressSpaceSize = $ipPrefix->num() + 2; #the module ignores network/broadcast
                my $firstPrefixStr = $ipPrefix->network()->addr()."/".$splitSize;
                ($verbose) && print STDERR "Splitting $prefix into subnets of size $splitSize\n";
                #($verbose) && print STDERR "First prefix is $firstPrefixStr\n";
                my $firstPrefix = new NetAddr::IP($firstPrefixStr);
                my $currentIP = $ipPrefix->bigint();
                my $lastAddressSpaceIP = $currentIP + $totalAddressSpaceSize;
                my $subnetSize = $firstPrefix->num() + 2 ; #the module ignores network/broadcast
                ($verbose) && print STDERR "Split $totalAddressSpaceSize into chunks of $subnetSize IPs (".int($totalAddressSpaceSize/$subnetSize)." subnets). This is single-threaded and may hog the CPU.\n";

                my $lastPrefix = $firstPrefix;
                push @prefixes, $firstPrefix->cidr();
                my $startTime = time;
                while($currentIP + $subnetSize < $lastAddressSpaceIP){
                        #print STDERR "lastPrefix: $lastPrefix, subnetSize $subnetSize, as number:".$lastPrefix->bigint()."\n";
                        #since Net::IP can't take an integer + mask in the constructor, we need an intermediary object
                        my $temp = new NetAddr::IP($lastPrefix->bigint() + $subnetSize);
                        $lastPrefix =  new NetAddr::IP($temp->network()->addr()."/".$splitSize );
                        push @prefixes, $lastPrefix->cidr();
                        $currentIP += $subnetSize; #move to next subnet
                }
                my $endTime = time;
                ($verbose) && print STDERR "Created array of ".scalar(@prefixes)." subnets. Took ".($endTime - $startTime)." seconds\n";
                #($verbose) && print STDERR Dumper(\@prefixes);
        }
        else{
                # small enough to go solo
                push @prefixes, $ipPrefix->cidr();
        }

        # now we can start the threads and process @prefixes
        ($verbose) && print STDERR "Starting threaded execution $maxThreads threads\n";
        my $pool = Thread::Pool->new({
                optimize => 'cpu', # default: 'memory'        
                do => 'searchIPRange',
                monitor => sub { print STDERR "[Pool] monitor with @_\n"},
                pre_post_monitor_only => 0, # default: 0 = also for "do"
                
                checkpoint => sub { print STDERR "[Pool] checkpointing\n" },
                frequency => 1000,
                
                autoshutdown => 1, # default: 1 = yes
                
                workers => $maxThreads,     # default: 1
                maxjobs => $maxThreads*5,     # default: 5 * workers
                minjobs => $maxThreads*5/2,      # default: maxjobs / 2
                
        });
        #load the pool with prefixes
        #($verbose) && print STDERR "Maxworkers: ".$pool->workers()."\n";
        foreach my $prefix (@prefixes){
                ($verbose) && print STDERR "Queuing thread for $prefix\n";
                $pool->job($prefix);
        }
        $pool->shutdown;

        ($verbose) && print STDERR "Whole range checked.\n";
}

exit(0);
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
        ($verbose) && (($loops % 1024) == 0) && print STDERR "Testing: $tmpHost ($loops probes) ...\n";

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
# Search for hashes in a specific IP range
# This runs as a single thread
#

sub searchIPRange {
        my $ipRange = shift;
        my $block = new NetAddr::IP ($ipRange);
	my $count=$block->num();
	my $ver=$block->version();

	if ($ver == 4){
		#print "IPv4 detected on input\n";
		for ($loops=0;$loops<$count;$loops++){
			my $tmpHost=$block->nth($loops)->addr();
                	#my $addr=new NetAddr::IP ($tmpHost);
	                #$tmpHost=($addr->addr);
			if (my $line = searchHash($tmpHost)) {
				printf("*** Found host: %s (line %d) ***\n", $tmpHost, $line + 1);
			}
			($verbose) && (($loops % 1024) == 0) && print STDERR "Testing: $tmpHost ($loops probes) ...\n";
	        }
                #nth ignores network and broadcast IP. We process them here
                foreach my $ip ($block->network()->addr(), $block->broadcast()->addr()){
                        if (my $line = searchHash($ip)) {
				printf("*** Found host: %s (line %d) ***\n", $ip, $line + 1);
			}
                }

	}
	elsif ($ver == 6){
		#print "IPv6 detected on input\n";
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
                #nth ignores network and broadcast IP. We process them here
                foreach my $ip ($block->network()->addr(), $block->broadcast()->addr()){
                        if (my $line = searchHash($ip)) {
				printf("*** Found host: %s (line %d) ***\n", $ip, $line + 1);
			}
                }
	}
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
