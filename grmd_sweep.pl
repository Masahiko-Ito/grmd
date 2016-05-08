#! /usr/bin/perl
use strict;
require 'grm.pl';
my ($host, $port, $responce, @stat_pid_resid_status_keystring, $stat, $pid, $resid, $status, $keystring, $i);
#
if (@ARGV != 2){
    printf("usage: $0 host port\n");
    exit 1;
}
($host, $port) = @ARGV;
#
$responce = &grm_getpr($host, $port, "system");
@stat_pid_resid_status_keystring = split(/\n/, $responce);
foreach $i (@stat_pid_resid_status_keystring){
    ($stat, $pid, $resid, $status, $keystring) = split(/\t/, $i);
    if ($pid =~ /^[0-9][0-9]*$/){
        if (kill(0, $pid) == 0){
            &grm_unlock($host, $port, $pid, $resid, $keystring);
        }
    }
}
