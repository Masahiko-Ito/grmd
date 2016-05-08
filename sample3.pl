#! /usr/bin/perl
use strict;
require 'grm.pl';
my ($host, $port, $sts1, $sts2, $i, $rec);
#
if (@ARGV != 2){
    printf("usage: $0 host port\n");
    exit 1;
}
($host, $port) = @ARGV;
#
for ($i = 0; $i < 100; $i++){
    $sts1 = &grm_lock($host, $port, "p3", "r1.txt", "x", "poipoi");
    if ($sts1 ne "OK"){
        print "lock error p3, r1.txt\n";
        exit 1;
    }

    $sts2 = &grm_lock($host, $port, "p3", "r2.txt", "x", "poipoi");

    while ($sts2 eq "DEADLOCK"){
        print "p3 DEADLOCK retry\n";

        $sts1 = &grm_unlock($host, $port, "p3", "r1.txt", "poipoi");
        if ($sts1 ne "OK"){
            print "unlock error p3, r1.txt\n";
            exit 1;
        }

        $sts1 = &grm_lock($host, $port, "p3", "r1.txt", "x", "poipoi");
        if ($sts1 ne "OK"){
            print "lock error p3, r1.txt\n";
            exit 1;
        }

        $sts2 = &grm_lock($host, $port, "p3", "r2.txt", "x", "poipoi");
    }

    if ($sts2 ne "OK"){
        print "lock error p3, r2.txt\n";
        exit 1;
    }

    open(FD1, "<r1.txt");
    $rec = <FD1>;
    close(FD1);
    $rec++;
    open(FD1, ">r1.txt");
    print FD1 $rec;
    close(FD1);

    open(FD2, "<r2.txt");
    $rec = <FD2>;
    close(FD2);
    $rec++;
    open(FD2, ">r2.txt");
    print FD2 $rec;
    close(FD2);

    $sts1 = &grm_unlock($host, $port, "p3", "r1.txt", "poipoi");
    if ($sts1 ne "OK"){
        print "unlock error p3, r1.txt\n";
        exit 1;
    }

    $sts2 = &grm_unlock($host, $port, "p3", "r2.txt", "poipoi");
    if ($sts2 ne "OK"){
        print "unlock error p3, r2.txt\n";
        exit 1;
    }
}
