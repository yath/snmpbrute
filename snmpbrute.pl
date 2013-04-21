#!/usr/bin/perl
# Copyright (c) 2013 Sebastian Schmidt <yath+snmpbrute@yath.de>
#
# Licensed under the GNU GPL Version 2.
#
# For educational purposes only!

use strict;
use warnings;
use IO::Socket::INET;
use NSNMP;
use Net::Pcap;
use IO::Select;
use Getopt::Std;

# some globals...
my %options;
my %snmptypes;
my %rids;
my $child;
my $pwfile;

sub get_next_community {
    unless ($pwfile) {
        open($pwfile, "<", $options{infile}) or
            die "Unable to open $options{infile}: $!";
    }
    my $ret = <$pwfile>;
    if (!defined($ret)) {
        close $pwfile;
    } else {
        $ret =~ s/[\r\n]//g;
    }

    return $ret;
}

sub get_socket {
    my ($peer) = @_;

    my $sock = IO::Socket::INET->new(
        PeerAddr => $peer,
        Proto => "udp",
    ) or die "Unable to connect to $peer: $!";

    return $sock;
}

sub get_snmp_request_id {
    my ($community) = @_;
    while(1) {
        my $rid = int rand(2**31);
        if (exists $rids{$rid} && $rids{$rid}->timeout < time) {
            next;
        }
        $rids{$rid} = [$community, time+$options{timeout}];
        return pack "N", $rid;
    }
}

sub get_snmp_pdu {
    my ($community, @oids) = @_;

    return map {
        NSNMP->encode(type => NSNMP::GET_REQUEST,
            request_id => get_snmp_request_id($community),
            varbindlist =>  [[$_, NSNMP::NULL, ""]],
            community => $community,
        )
    } @oids;
}

sub get_pcap_with_filter {
    my ($localport) = @_;

    my $err;
    my $pcap = Net::Pcap::open_live($options{device}, $options{snaplen}, $options{promisc}, 0, \$err)
        or die "Can't open device $options{device}: $err\n";

    my $filter;
    my $filterstr = "src host $options{host} and src port $options{port} and dst port $localport";
    my $ret = Net::Pcap::compile($pcap, \$filter,$filterstr, 1, 32);
    if ($ret == -1) {
        die "cannot compile filter string '$filterstr': ".Net::Pcap::geterr($pcap)."\n";
    }

    Net::Pcap::setfilter($pcap, $filter);

    return $pcap;
}

sub read_n_bytes {
    my ($fh, $n) = @_;

    my $ret = "";
    do {
        my $buf;
        my $r = read($fh, $buf, $n-length($ret));
        if ($r == 0) {
            last;
        } elsif ($r == -1) {
            die "error on read($fh, \$buf, @{[$n-length($ret)]}: $!";
        } else {
            $ret .= $buf;
        }
    } while (length $ret < $n);
    return $ret;
}

sub hexdump {
    my ($data) = @_;
    my @data = map { ord } split(//, $data);
    push(@data, undef) while @data % 16; # pad

    for (my $offset = 0; $offset+16 <= @data; $offset += 16) {
        printf('%08x  '.('% 2s 'x8)." ".('% 2s 'x8).' |'.('%1s'x16)."|\n", $offset,
            (map {defined $data[$_] ? sprintf('%02x', $data[$_])
                   : '  ' } $offset..$offset+15),
            (map { (defined $data[$_] && ($data[$_] >= 32 && $data[$_] <= 126)) ? chr $data[$_] :
                   defined $data[$_] ? "." :
                   " " } $offset..$offset+15)
        );
    }
}

sub escape {
    my ($data) = @_;
    $data =~ s/([^\x20-\x7e]|["\\])/
        $& eq '"' ? '\\"' :
        $& eq '\\' ? '\\\\' :
        sprintf('\\x%02x', ord $&)/ge;
    return $data;
}

sub get_snmp_type {
    my ($type) = @_;
    unless ($snmptypes{_init}) {
        for (qw(INTEGER OCTET_STRING NULL OBJECT_IDENTIFIER SEQUENCE
                IpAddress Counter32 Gauge32 TimeTicks GET_REQUEST
                GET_NEXT_REQUEST GET_RESPONSE SET_REQUEST)) {
            eval "\$snmptypes{+NSNMP::$_} = \"$_\";";
        }
        $snmptypes{_init} = 1;
    }
    
    return $snmptypes{$type} || escape($type);
}

sub dump_packet {
    my ($data) = @_;

    my $decoded = NSNMP->decode(substr($data, $options{offset}));
    unless ($decoded) {
        print "Received invalid SNMP packet. Dump (including all protocol headers) follows: \n";
        hexdump($data);
        return;
    } else {
        my $rid = unpack("N", $decoded->request_id);
        printf('SNMP reply: v%d, type "%s", community "%s" [requested: "%s"], request_id %d, error_status %d'."\n",
            $decoded->version, get_snmp_type($decoded->type), (map { escape $_ } $decoded->community,
            $rids{$rid}->[0]), $rid, $decoded->error_status);
    }
}

sub process_snmp_reply {
    my ($fh) = @_;
    my $buf;

    my $len = unpack("L", read_n_bytes($fh, 4));

    my $data = read_n_bytes($fh, $len);
    dump_packet $data;
}

sub cleanup_rids {
    my $now = time;
    delete @rids{grep { $rids{$_}->[1] < $now } keys %rids};
}

sub usage {
    print <<EOF;
Usage: $0 -i <interface> -h <host> -l <community file> [-o oid[,oid[,oid]]]
          [-O <offset>] [-d delay] [-p port] [-s snaplen] [-p] [-t timeout]

    -o Comma-separated list of OIDs to try (fully numeric, no MIBs)
       Defaults to .1.3.6.1.2.1.1.1.0,.1.3.6.1.2.1.1.3.0

    -O Payload offset (e.g. size of ethernet+ip+udp header)
       Defaults to 42

    -d Delay in miliseconds between each GetRequest
       Defaults to 10

    -p Port, if different than 161

    -s Bytes to capture with libpcap
       Defaults to 1024

    -P If set, put device into promiscous mode

    -t Maximum time to wait for an SNMP reply in seconds
       Defaults to 5
       Note: That doesn't make the scanning slower, just uses more memory.
EOF
    exit 1;
}

sub get_options {
    my %o;
    getopts("o:O:i:h:p:d:s:Pl:", \%o);
    if ($o{o}) {
        $options{oids} = [split /,/, $o{o}];
    } else {
        $options{oids} = [qw(.1.3.6.1.2.1.1.1.0 .1.3.6.1.2.1.1.3.0)],
    }

    $options{offset} = $o{O}  || 0x2a;
    $options{delay} = $o{d}   || 10;
    $options{host} = $o{h}    || usage;
    $options{port} = $o{p}    || 161;
    $options{device} = $o{i}  || usage;
    $options{infile} = $o{l}  || usage;
    $options{snaplen} = $o{s} || 1024;
    $options{promisc} = defined $o{P} ? 1 : 0;
    $options{timeout} = $o{t} || 5;
}

sub parent_main {
    my ($reader, $writer, $sock) = @_;

    $| = 1;
    print "Waiting for child to become ready... ";
    my $ret = eval {
        local $SIG{ALRM} = sub {die "ALARM\n"};
        alarm 5;
        return scalar <$reader>;
    };
    alarm 0;
    { no warnings "uninitialized";
        if ($@ && $@ eq "ALARM\n") {
            die "timeout\n";
        } elsif ($@) {
            die "unknown error: $@";
        } elsif ($ret eq "ERR\n") {
            exit 1;
        } elsif ($ret ne "OK\n") {
            defined $ret or $ret = '<undef>';
            die "child responded with '$ret'? #wat";
        }
    }
    print "ok.\n";

    print "Running.\n";

    my @oids = map { NSNMP->encode_oid($_) } @{$options{oids}};
    
    my $sel = IO::Select->new($reader);

    # clean up after 5000 iterations
    my ($i, $cleanup) = (5000)x2;

    while(defined(my $community = get_next_community())) {
        if (my @rfh = $sel->can_read($options{delay}/1000)) {
            warn "Got ".@rfh." FHs from select()?" if @rfh > 1;
            process_snmp_reply($rfh[0]);
        } else {
            # timeout - send next snmp request
            foreach my $pdu (get_snmp_pdu($community, @oids)) {
                $sock->send($pdu);
            }
        }
        if (--$i < 0) {
            cleanup_rids;
            $i = $cleanup;
        }
    }
    sleep $options{timeout};
}

sub child_main {
    my ($reader, $writer, $localport) = @_;

    my $pcap = eval { get_pcap_with_filter($localport) };
    if ($@) {
        warn $@;
        print $writer "ERR\n";
        exit 1;
    }

    print $writer "OK\n";

    Net::Pcap::loop($pcap, 0, sub {
        my ($user_data, $header, $packet) = @_;
        print $writer pack("L", length $packet);
        print $writer $packet;
    }, "");
}

sub terminate {
    if ($child) {
        kill("TERM", $child);
        select(undef, undef, undef, 0.1);
        kill("KILL", $child);
    }
    exit;
}

sub main {
    get_options;

    my ($tochild_r, $tochild_w);
    pipe($tochild_r, $tochild_w);

    my ($toparent_r, $toparent_w);
    pipe($toparent_r, $toparent_w);

    # open socket here so we already have the src port in the child
    my $sock = get_socket($options{host}.":".$options{port});

    my $ret = fork;
    if ($ret > 0) {
        # parent
        $child = $ret; # global, for sub terminate
        $SIG{$_} = \&terminate for (qw(INT TERM HUP QUIT ABRT PIPE));
        close $tochild_r;
        close $toparent_w;
        $tochild_w->autoflush(1);
        parent_main($toparent_r, $tochild_w, $sock);
        terminate;
    } elsif ($ret == 0) {
        # child
        close $tochild_w;
        close $toparent_r;
        $toparent_w->autoflush(1);

        my $localport = $sock->sockport();
        close $sock;

        child_main($tochild_r, $toparent_w, $localport);
    } elsif ($ret == -1) {
        die "Cannot fork: $!";
    }
}


main
