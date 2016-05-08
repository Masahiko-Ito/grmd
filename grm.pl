use strict;
use IO::Socket;
#
# ��ǽ:��¾����
# ����:host, port, pid, resid, lockmode, keystring
# ����:status
# ��  :$status = grm_lock("localhost", "20100", "process1", "resource1", "SHARE_LOCK", "Gehime");
#
# lockmode : SHARE_LOCK, SL, S
#            EXCLUSIVE_LOCK, EL, X
#
sub grm_lock(){
    my ($host, $port, $pid, $resid, $lockmode, $keystring) = @_;
    my ($sts, $handle);

    $handle = IO::Socket::INET->new(Proto     => "tcp",
                                PeerAddr  => $host,
                                PeerPort  => $port);
    if ($handle == 0){
        printf("can't connect to port $port on $host: $! \n");
        return "NG";
    }
    $handle->autoflush(1);              # so output gets there right away

    printf($handle "lock\t$pid\t$resid\t$lockmode\t$keystring\n");
    $sts = <$handle>;
    chop $sts;
    
    close($handle);

    return ($sts);
}
#
# ��ǽ:��¾��λ
# ����:host, port, pid, resid, keystring
# ����:status
# ��  :$status = grm_unlock("localhost", "20100", "process1", "resource1", "Gehime");
#
sub grm_unlock(){
    my ($host, $port, $pid, $resid, $keystring) = @_;
    my ($sts, $handle);

    $handle = IO::Socket::INET->new(Proto     => "tcp",
                                PeerAddr  => $host,
                                PeerPort  => $port);
    if ($handle == 0){
        printf("can't connect to port $port on $host: $! \n");
        return "NG";
    }
    $handle->autoflush(1);              # so output gets there right away

    printf($handle "unlock\t$pid\t$resid\t$keystring\n");
    $sts = <$handle>;
    chop $sts;
    
    close($handle);

    return ($sts);
}
#
# ��ǽ:�꥽��������ɽ��(pid-resid)
# ����:host, port, keystring
# ����:status
# ��  :$status = grm_spr("localhost", "20100", "Gehime");
#
sub grm_spr(){
    my ($host, $port, $keystring) = @_;
    my ($sts, $handle);

    $handle = IO::Socket::INET->new(Proto     => "tcp",
                                PeerAddr  => $host,
                                PeerPort  => $port);
    if ($handle == 0){
        printf("can't connect to port $port on $host: $! \n");
        return "NG";
    }
    $handle->autoflush(1);              # so output gets there right away

    printf($handle "spr\t$keystring\n");
    $sts = <$handle>;
    chop $sts;
    
    close($handle);

    return ($sts);
}
#
# ��ǽ:�꥽��������ɽ��(resid-pid)
# ����:host, port, keystring
# ����:status
# ��  :$status = grm_srp("localhost", "20100", "Gehime");
#
sub grm_srp(){
    my ($host, $port, $keystring) = @_;
    my ($sts, $handle);

    $handle = IO::Socket::INET->new(Proto     => "tcp",
                                PeerAddr  => $host,
                                PeerPort  => $port);
    if ($handle == 0){
        printf("can't connect to port $port on $host: $! \n");
        return "NG";
    }
    $handle->autoflush(1);              # so output gets there right away

    printf($handle "srp\t$keystring\n");
    $sts = <$handle>;
    chop $sts;
    
    close($handle);

    return ($sts);
}
#
# ��ǽ:�꥽�������ּ���(pid-resid)
# ����:host, port, keystring
# ����:status pid resid res_status keystr
# ��  :$responce = grm_getpr("localhost", "20100", "Gehime");
#      @stat_pid_resid_status_keystr = split(/\n/, $responce);
#      foreach $i (@stat_pid_resid_status_keystr){
#          ($stat, $pid, $resid, $status, $keystr) = split(/\t/, $i);
#      }
#
sub grm_getpr(){
    my ($host, $port, $keystring) = @_;
    my ($sts, $responce, $handle);

    $handle = IO::Socket::INET->new(Proto     => "tcp",
                                PeerAddr  => $host,
                                PeerPort  => $port);
    if ($handle == 0){
        printf("can't connect to port $port on $host: $! \n");
        return "NG";
    }
    $handle->autoflush(1);              # so output gets there right away

    $responce = "";

    printf($handle "getpr\t$keystring\n");
    while ($sts = <$handle>){
        $responce .= $sts;
    }
    
    close($handle);

    return ($responce);
}
#
# ��ǽ:�꥽�������ּ���(resid-pid)
# ����:host, port, keystring
# ����:status resid pid res_status keystr
# ��  :$responce = grm_getrp("localhost", "20100", "Gehime");
#      @stat_resid_pid_status_keystr = split(/\n/, $responce);
#      foreach $i (@stat_resid_pid_status_keystr){
#          ($stat, $resid, $pid, $status, $keystr) = split(/\t/, $i);
#      }
#
sub grm_getrp(){
    my ($host, $port, $keystring) = @_;
    my ($sts, $responce, $handle);

    $handle = IO::Socket::INET->new(Proto     => "tcp",
                                PeerAddr  => $host,
                                PeerPort  => $port);
    if ($handle == 0){
        printf("can't connect to port $port on $host: $! \n");
        return "NG";
    }
    $handle->autoflush(1);              # so output gets there right away

    $responce = "";

    printf($handle "getrp\t$keystring\n");
    while ($sts = <$handle>){
        $responce .= $sts;
    }
    
    close($handle);

    return ($responce);
}
#----------------------------------------------------------------------

1;
