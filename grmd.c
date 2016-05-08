/*
 * grmd.c: General Resource Management Daemon
 *
 * Copyright 2004 Masahiko Ito <m-ito@mbox.kyoto-inet.or.jp>
 *
 *      grmd is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 *      grmd is distributed in the hope that it will be useful,
 *      but WITHOUT ANY WARRANTY; without even the implied warranty of
 *      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *      GNU General Public License for more details.
 *
 *      You should have received a copy of the GNU General Public License
 *      along with this program; if not, write to the Free Software
 *      Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 **************************************************************************
 *
 * Webpage: http://myh.no-ip.org/~tyserv/grmd/
 *
 **************************************************************************
 *
 * History
 * v0.1 2004.06.18 Masahiko Ito <m-ito@mbox.kyoto-inet.or.jp>
 *      Create
 */

/*
 * usage    : grmd hostname port queue_count admin_keystring_file
 *
 * !! command separater is TAB(0x09) !!
 *
 * command  : lock pid resid mode keystring
 *   mode   : SHARE_LOCK, SL, EXCLUSIVE_LOCK, EL
 * responce : OK, DEADLOCK, NG, UNKNOWN STATUS
 *
 * command  : unlock pid resid keystring
 * responce : OK, NG, UNKNOWN STATUS
 *
 * command  : spr admin_keystring
 * responce : OK, NG, UNKNOWN STATUS
 *
 * command  : srp admin_keystring
 * responce : OK, NG, UNKNOWN STATUS
 *
 * responce : UNKNOWN COMMAND
 *            NOT ALLOWED
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <arpa/inet.h>

#include <tcpd.h>
#include <syslog.h>

#include "grm.h"

#define DAEMON_NAME "grmd"
#define BUF_LEN (1024)
#define NULL_STR ""
#define FALSE (0)
#define TRUE (!FALSE)

extern int hosts_clt();
char ipstr[16];
int allow_severity = LOG_INFO;
int deny_severity = LOG_WARNING;

unsigned short Socket_port;
int Socket_wait_queue;

int S_waiting, S_sock;
char Tmp_buf[BUF_LEN];
char In_buf[BUF_LEN];
char Out_buf[BUF_LEN];

char *Keystring_file;

int Sigchld_cnt = 0;

void SigTrap();

int get_param();
char *Command;
char *Pid;
char *Resid;
char *Mode;
char *Keystr;
char *Adminkeystr;

int sock_read();
int sock_write();
int wait_child();
int modetoi();

extern int hosts_ctl();

int main(argc, argv)
int argc;
char *argv[];
{
    struct hostent *myhost;
    struct sockaddr_in me;
    struct sockaddr_in caddr;
    socklen_t caddr_len;
    FILE *fp;
    char admin_keystring[MAX_IDLEN + 1];

    int ret, fd, status, wait_status;

/*
 * show help
 */
    if (argc < 5 || strncmp(argv[1], "-h", strlen("-h")) == 0
        || strncmp(argv[1], "--help", strlen("--help")) == 0) {
        fprintf(stderr,
                "\nusage : %-s hostname port queue_count admin_keystring_file\n\n",
                DAEMON_NAME);
        exit(0);
    }

/*
 * set signal trap
 */
    signal(SIGHUP, SigTrap);
    signal(SIGTERM, SigTrap);
    signal(SIGCHLD, SigTrap);

    signal(SIGINT, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);

/*
 * set administrator key string
 */
    Keystring_file = argv[4];
    if ((fp = fopen(Keystring_file, "r")) == (FILE *) NULL) {
        fprintf(stderr, "can't open keystring file(%-s), crashed.\n",
                Keystring_file);
        fprintf(stderr, "errno=%d\n", errno);
        exit(1);
    }
    if (fgets(admin_keystring, sizeof admin_keystring, fp) ==
        (char *) NULL) {
        fprintf(stderr, "can't read keystring file(%-s), crashed.\n",
                Keystring_file);
        exit(1);
    }
    if (fclose(fp) != 0) {
        fprintf(stderr, "can't close keystring file(%-s), crashed.\n",
                Keystring_file);
        exit(1);
    }
    if (admin_keystring[strlen(admin_keystring) - 1] == '\n') {
        admin_keystring[strlen(admin_keystring) - 1] = '\0';
    }
    if (grm_setkeystr(admin_keystring) == -1) {
        fprintf(stderr, "can't set administrator key string, crashed.\n");
        exit(1);
    }

/*
 * set initial environment 
 */
#ifndef __CYGWIN__
    if ((fd = open("/dev/tty", O_RDWR)) >= 0) {
        ioctl(fd, TIOCNOTTY, (char *) NULL);
        close(fd);
    }
#endif
    chdir("/");
    umask(077);
    close(0);
    errno = 0;

/*
 * make socket
 */
    if ((myhost = gethostbyname(argv[1])) == (struct hostent *) NULL) {
        fprintf(stderr, "can't gethostbyname(%-s), crashed.\n", argv[1]);
        exit(1);
    }
    bzero((char *) &me, sizeof me);
    me.sin_family = AF_INET;
    Socket_port = atoi(argv[2]);
    me.sin_port = htons(Socket_port);
    bcopy(myhost->h_addr, (char *) &me.sin_addr, myhost->h_length);

/*
 * ready socket
 */
    if ((S_waiting = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "can't create socket : %s\n", strerror(errno));
        exit(1);
    }
    if (bind(S_waiting, (struct sockaddr *) &me, sizeof me) == -1) {
        fprintf(stderr, "can't bind : %s\n", strerror(errno));
        exit(1);
    }

    Socket_wait_queue = atoi(argv[3]);
    if (listen(S_waiting, Socket_wait_queue) == -1) {
        fprintf(stderr, "can't listen : %s\n", strerror(errno));
        exit(1);
    }

/*
 * forever loop
 */
    while (TRUE) {

/*
 * accept from client(open socket)
 */
        errno = 0;
        caddr_len = sizeof caddr;
        S_sock = accept(S_waiting, (struct sockaddr *) &caddr, &caddr_len);
        while (S_sock < 0 && errno == EINTR) {
            errno = 0;
            S_sock =
                accept(S_waiting, (struct sockaddr *) &caddr, &caddr_len);
        }

        if (S_sock < 0) {
            fprintf(stderr, "can't accept : %s\n", strerror(errno));
            grm_rmmsgq(Keystring_file);
            exit(1);
        }

/*
 * read message from client
 */
        bzero(In_buf, BUF_LEN);
        ret = sock_read(S_sock, In_buf, BUF_LEN);

/*
 * kill zombi
 */
        wait_child();

/*
 * access control (/etc/hosts.allow, /etc/hosts.deny)
 */
        ipstr[(sizeof ipstr) - 1] = '\0';
        strncpy((char *) ipstr, (char *) inet_ntoa(caddr.sin_addr),
                (sizeof ipstr) - 1);
        if (hosts_ctl(DAEMON_NAME, STRING_UNKNOWN, ipstr, STRING_UNKNOWN)) {    /* access allow */

/*
 * parse parameter
 */
            get_param(In_buf);

/*
 * lock
 */
            if (strncmp(Command, "lock", strlen("lock")) == 0 ||
                strncmp(Command, "LOCK", strlen("LOCK")) == 0) {
                status = grm_lock(Pid, Resid, modetoi(Mode), Keystr);
                if (status == OK) {
                    strncpy(Out_buf, "OK\n", (sizeof Out_buf) - 1);
                } else if (status == DEADLOCK) {
                    strncpy(Out_buf, "DEADLOCK\n", (sizeof Out_buf) - 1);
                } else if (status == WAIT) {
                    wait_status =
                        grm_wait(Pid, Resid, S_waiting, Keystring_file);
                    if (wait_status == 0) {     /* fork success */
                        strncpy(Out_buf, "OK\n", (sizeof Out_buf) - 1);
                    } else if (wait_status == -2) {     /* fork success but error */
                        strncpy(Out_buf, "NG\n", (sizeof Out_buf) - 1);
                    } else if (wait_status > 0) {       /* fork success, no need answer */
                        strncpy(Out_buf, "OK\n", (sizeof Out_buf) - 1);
                    } else if (wait_status == -1) {     /* fork failure */
                        strncpy(Out_buf, "NG\n", (sizeof Out_buf) - 1);
                    } else {
                        strncpy(Out_buf, "UNKNOWN STATUS\n",
                                (sizeof Out_buf) - 1);
                    }
                } else if (status == NG) {
                    strncpy(Out_buf, "NG\n", (sizeof Out_buf) - 1);
                } else {
                    strncpy(Out_buf, "UNKNOWN STATUS\n",
                            (sizeof Out_buf) - 1);
                }
/*
 * unlock
 */
            } else if (strncmp(Command, "unlock", strlen("unlock")) == 0 ||
                       strncmp(Command, "UNLOCK", strlen("UNLOCK")) == 0) {
                status = grm_unlock(Pid, Resid, Keystr);
                if (status == 0) {
                    grm_wakeup(Resid, Keystring_file);
                    strncpy(Out_buf, "OK\n", (sizeof Out_buf) - 1);
                } else if (status == -1) {
                    strncpy(Out_buf, "NG\n", (sizeof Out_buf) - 1);
                } else {
                    strncpy(Out_buf, "UNKNOWN STATUS\n",
                            (sizeof Out_buf) - 1);
                }
/*
 * spr
 */
            } else if (strncmp(Command, "spr", strlen("spr")) == 0 ||
                       strncmp(Command, "SPR", strlen("SPR")) == 0) {
                status = grm_spr(Adminkeystr);
                if (status == 0) {
                    strncpy(Out_buf, "OK\n", (sizeof Out_buf) - 1);
                } else if (status == -1) {
                    strncpy(Out_buf, "NG\n", (sizeof Out_buf) - 1);
                } else {
                    strncpy(Out_buf, "UNKNOWN STATUS\n",
                            (sizeof Out_buf) - 1);
                }
/*
 * srp
 */
            } else if (strncmp(Command, "srp", strlen("srp")) == 0 ||
                       strncmp(Command, "SRP", strlen("SRP")) == 0) {
                status = grm_srp(Adminkeystr);
                if (status == 0) {
                    strncpy(Out_buf, "OK\n", (sizeof Out_buf) - 1);
                } else if (status == -1) {
                    strncpy(Out_buf, "NG\n", (sizeof Out_buf) - 1);
                } else {
                    strncpy(Out_buf, "UNKNOWN STATUS\n",
                            (sizeof Out_buf) - 1);
                }
/*
 * unknown
 */
            } else {
                strncpy(Out_buf, "UNKNOWN COMMAND\n",
                        (sizeof Out_buf) - 1);
            }

/*
 * return from wait status and exit
 */
            if (strncmp(Command, "lock", strlen("lock")) == 0 ||
                strncmp(Command, "LOCK", strlen("LOCK")) == 0) {
                if (status == WAIT) {
                    if (wait_status == 0 || wait_status == -2) {
                        sock_write(S_sock, Out_buf, strlen(Out_buf));
                        exit(0);
                    }
                }
            }
        } else {                /* access denied */
            strncpy(Out_buf, "NOT ALLOWED\n", (sizeof Out_buf) - 1);
        }

/*
 * no write message to client because child process write message to client
 */
        if ((strncmp(Command, "lock", strlen("lock")) == 0 ||
             strncmp(Command, "LOCK", strlen("LOCK")) == 0) &&
            status == WAIT && wait_status > 0) {
            /* do nothing */
/*
 * write message to client
 */
        } else {                /* write message to client */
            sock_write(S_sock, Out_buf, strlen(Out_buf));
        }

        close(S_sock);
    }
}

/*
 * signal trap
 */
void SigTrap(sig)
int sig;
{
    signal(sig, SIG_IGN);

    switch (sig) {
    case SIGHUP:
        signal(sig, SigTrap);
        break;
    case SIGCHLD:
        Sigchld_cnt++;
        signal(sig, SigTrap);
        break;
    case SIGTERM:
        close(S_sock);
        close(S_waiting);
        fprintf(stderr, "SIGTERM catched and normal shutdown\n");
        grm_rmmsgq(Keystring_file);
        exit(0);
        break;
    default:
        close(S_sock);
        close(S_waiting);
        fprintf(stderr, "signal(%d) catched and exit\n", sig);
        grm_rmmsgq(Keystring_file);
        exit(0);
        break;
    }
}

/*
 * wait child
 */
int wait_child()
{
#if 0
    int ret, status;

    if (Sigchld_cnt > 0) {
        errno = 0;
        ret = wait(&status);
        while (ret < 0 && errno == EINTR) {
            errno = 0;
            ret = wait(&status);
        }
        if (ret > 0) {
            Sigchld_cnt--;
        }
        while (ret > 0 && Sigchld_cnt > 0) {
            errno = 0;
            ret = wait(&status);
            while (ret < 0 && errno == EINTR) {
                errno = 0;
                ret = wait(&status);
            }
            if (ret > 0) {
                Sigchld_cnt--;
            }
        }
    }
#else
    if (Sigchld_cnt > 0) {
        while (waitpid(-1, (int *)NULL, WNOHANG) > 0){
            Sigchld_cnt--;
        }
        if (Sigchld_cnt < 0){
            Sigchld_cnt = 0;
        }
    }
#endif
    return 0;
}

/*
 * get pid, resid, mode
 */
int get_param(buf)
char *buf;
{
    char *p1, *p2, *p3, *p4, *p5;

    Command = Pid = Resid = Mode = Keystr = NULL_STR;

    if ((p1 = strchr(buf, '\t')) == (char *) NULL) {
        if ((p1 = strchr(buf, '\r')) == (char *) NULL) {
            if ((p1 = strchr(buf, '\n')) == (char *) NULL) {
                return -1;
            }
        }
        *p1 = '\0';
        Command = buf;
        return 0;
    }
    *p1 = '\0';
    Command = buf;

    if (strncmp(Command, "spr", strlen("spr")) == 0 ||
        strncmp(Command, "SPR", strlen("SPR")) == 0 ||
        strncmp(Command, "srp", strlen("srp")) == 0 ||
        strncmp(Command, "SRP", strlen("SRP")) == 0) {
        p1++;
        if ((p2 = strchr(p1, '\t')) == (char *) NULL) {
            if ((p2 = strchr(p1, '\r')) == (char *) NULL) {
                if ((p2 = strchr(p1, '\n')) == (char *) NULL) {
                    return -1;
                }
            }
            *p2 = '\0';
            Adminkeystr = p1;
            return 0;
        }
        *p2 = '\0';
        Adminkeystr = p1;

        return 0;
    }

    p1++;
    if ((p2 = strchr(p1, '\t')) == (char *) NULL) {
        if ((p2 = strchr(p1, '\r')) == (char *) NULL) {
            if ((p2 = strchr(p1, '\n')) == (char *) NULL) {
                return -1;
            }
        }
        *p2 = '\0';
        Pid = p1;
        return 0;
    }
    *p2 = '\0';
    Pid = p1;

    p2++;
    if ((p3 = strchr(p2, '\t')) == (char *) NULL) {
        if ((p3 = strchr(p2, '\r')) == (char *) NULL) {
            if ((p3 = strchr(p2, '\n')) == (char *) NULL) {
                return -1;
            }
        }
        *p3 = '\0';
        Resid = p2;
        return 0;
    }
    *p3 = '\0';
    Resid = p2;

    if (strncmp(Command, "unlock", strlen("unlock")) == 0 ||
        strncmp(Command, "UNLOCK", strlen("UNLOCK")) == 0) {
        p3++;
        if ((p4 = strchr(p3, '\t')) == (char *) NULL) {
            if ((p4 = strchr(p3, '\r')) == (char *) NULL) {
                if ((p4 = strchr(p3, '\n')) == (char *) NULL) {
                    return -1;
                }
            }
            *p4 = '\0';
            Keystr = p3;
            return 0;
        }
        *p4 = '\0';
        Keystr = p3;

        return 0;
    }

    p3++;
    if ((p4 = strchr(p3, '\t')) == (char *) NULL) {
        if ((p4 = strchr(p3, '\r')) == (char *) NULL) {
            if ((p4 = strchr(p3, '\n')) == (char *) NULL) {
                return -1;
            }
        }
        *p4 = '\0';
        Mode = p3;
        return 0;
    }
    *p4 = '\0';
    Mode = p3;

    p4++;
    if ((p5 = strchr(p4, '\t')) == (char *) NULL) {
        if ((p5 = strchr(p4, '\r')) == (char *) NULL) {
            if ((p5 = strchr(p4, '\n')) == (char *) NULL) {
                return -1;
            }
        }
        *p5 = '\0';
        Keystr = p4;
        return 0;
    }
    *p5 = '\0';
    Keystr = p4;

    return 0;
}

int sock_read(s, buf, len)
int s;
char *buf;
int len;
{
    int ret, cnt = 0, rem_cnt = (len > BUF_LEN ? BUF_LEN : len);

    *buf = '\0';
    while (strchr(buf, '\n') == (char *) NULL &&
           strchr(buf, '\r') == (char *) NULL && rem_cnt > 0) {
        errno = 0;
        ret = read(s, Tmp_buf, sizeof Tmp_buf);
        while (ret < 0 && errno == EINTR) {
            errno = 0;
            ret = read(s, Tmp_buf, sizeof Tmp_buf);
        }
        if (ret <= 0) {
            *buf = '\0';
            return -1;
        }
        memcpy(buf + cnt, Tmp_buf, (ret > rem_cnt ? rem_cnt : ret));
        cnt += (ret > rem_cnt ? rem_cnt : ret);
        rem_cnt -= (ret > rem_cnt ? rem_cnt : ret);
        *(buf + (cnt >= BUF_LEN ? cnt - 1 : cnt)) = '\0';
    }

    return (cnt >= BUF_LEN ? cnt - 1 : cnt);
}

int sock_write(s, buf, len)
int s;
char *buf;
int len;
{
    int ret, cnt = 0, rem_cnt = (len > BUF_LEN ? BUF_LEN : len);

    while (rem_cnt > 0) {
        if ((ret = write(s, buf + cnt, rem_cnt)) <= 0) {
            return -1;
        }
        cnt += ret;
        rem_cnt -= ret;
    }
    return cnt;
}

int modetoi(mode)
char *mode;
{
    if (strncmp(mode, "share_lock", strlen("share_lock")) == 0 ||
        strncmp(mode, "SHARE_LOCK", strlen("SHARE_LOCK")) == 0 ||
        strncmp(mode, "sl", strlen("sl")) == 0 ||
        strncmp(mode, "SL", strlen("SL")) == 0 ||
        strncmp(mode, "s", strlen("s")) == 0 ||
        strncmp(mode, "S", strlen("S")) == 0) {
        return SHARE_LOCK;
    } else if (strncmp(mode, "exclusive_lock", strlen("exclusive_lock")) ==
               0
               || strncmp(mode, "EXCLUSIVE_LOCK",
                          strlen("EXCLUSIVE_LOCK")) == 0
               || strncmp(mode, "el", strlen("el")) == 0
               || strncmp(mode, "EL", strlen("EL")) == 0
               || strncmp(mode, "x", strlen("x")) == 0
               || strncmp(mode, "X", strlen("X")) == 0) {
        return EXCLUSIVE_LOCK;
    }
    return -1;
}
