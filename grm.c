/*
 * grm.c: General resource management functions
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
 *      2004.06.18 Masahiko Ito <m-ito@mbox.kyoto-inet.or.jp>
 *      Create
 */

/*
 *
 *-------------------------------------------------------------------------
 * int grm_lock(pid, resid, mode, keystr)
 *
 *   function     : Lock resource.
 *
 *   char *pid    : Process id. pid must be unique in system.
 *   char *resid  : Resource id.
 *   int  mode    : SHARE_LOCK, EXCLUSIVE_LOCK
 *   char *keystr : key string.
 *
 *   return       : OK        resource was locked. resource status is setted to
 *                            SHARE_LOCK|EXCLUSIVE_LOCK.
 *                  DEADLOCK  deadlock happen. resource was not locked.
 *                            all resource which you have must be unlocked.
 *                  WAIT      resource is already locked by another process.
 *                            resource status is setted to SHARE_WAIT|EXCLUSIVE_WAIT.
 *                  NG        lock failure.
 *
 *   SHARE_LOCK wait locking resource, when previous process have 
 *   `EXCLUSIVE_LOCK|SHARE_WAIT|EXCLUSIVE_WAIT' status in resource.
 *
 *   EXCLUSIVE_LOCK wait locking resource, when previous process have 
 *   `SHARE_LOCK|EXCLUSIVE_LOCK|SHARE_WAIT|EXCLUSIVE_WAIT' status in resource,
 *
 *-------------------------------------------------------------------------
 * int grm_wait(pid, resid, fd_sock, path)
 *
 *   function    : wait resource(into sleep mode).
 *
 *   char *pid   : Process id. pid must be unique in system.
 *   char *resid : Resource id.
 *   int fd_sock : file descripter to close in child process.
 *   char *path  : path to admin_keystring_file for making msgkey.
 *
 *   return for parent : Process id in operating system(> 0)
 *                       -1 fork failure.
 *   return for child  : 0  success to return from wait status.
 *                       -2 wait failure.
 *
 *-------------------------------------------------------------------------
 * int grm_unlock(pid, resid, keystring)
 *
 *   function     : Unlock resource.
 *
 *   char *pid    : Process id. pid must be unique in system.
 *   char *resid  : Resource id.
 *   char *keystr : key string which was specified by grm_lock().
 *
 *   return       : 0        resource was unlocked.
 *                  -1       unlock failure.
 *
 *-------------------------------------------------------------------------
 * int grm_wakeup(resid, path)
 *
 *   function    : wakeup process in wait status.
 *
 *   char *resid : Resource id.
 *   char *path  : path to admin_keystring_file for making msgkey.
 *
 *   return      : 0        wakeup success.
 *                 -1       wakeup failure.
 *
 *-------------------------------------------------------------------------
 * int grm_setkeystr(admin_keystr)
 *
 *   function           : set key string for administrator.
 *
 *   char *admin_keystr : key string for administrator.
 *
 *   return             : 0   set success.
 *                        -1  set failure.
 *  
 *-------------------------------------------------------------------------
 * int grm_spr(admin_keystr)
 *
 *   function           : show resource structure pid(H) resid(V)
 *
 *   char *admin_keystr : key string for administrator.
 *
 *   return             : 0   sccess.
 *                        -1  failure.
 *  
 *-------------------------------------------------------------------------
 * int grm_srp(admin_keystr)
 *
 *   function           : show resource structure resid(H) pid(V)
 *
 *   char *admin_keystr : key string for administrator.
 *
 *   return             : 0   sccess.
 *                        -1  failure.
 *  
 *-------------------------------------------------------------------------
 * int grm_rmmsgq(path)
 *
 *   char *path  : path to admin_keystring_file for making msgkey.
 *
 *   function : remove msgq for lock
 *
 *   return   : 0   sccess
 *              -1  failure
 *
 *-------------------------------------------------------------------------
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>

#include "grm.h"

#define FALSE		(0)
#define TRUE		(!FALSE)

#define BUF_LEN		(512)

struct msgbuf2 {
    long int type;
    char data[BUF_LEN];
};

static struct pid_resid *ExistPidResid();
static struct pid_resid *CreatePidResid();
static int DestroyPidResid();
static int ExclCheck();
static int IsUnused();
static int Deadlocl();
/*
 * structure which keep resource status
 */
struct pid_resid {
    char *pid;
    char *resid;
    int status;                 /* SHARE_WAIT, EXCLUSIVE_WAIT, SHARE_LOCK, EXCLUSIVE_LOCK */
    char *keystr;
    long msgtype;

    struct pid_resid *pid_prev_pid_ptr;
    struct pid_resid *pid_next_pid_ptr;

    struct pid_resid *pid_prev_resid_ptr;
    struct pid_resid *pid_next_resid_ptr;

    struct pid_resid *resid_prev_resid_ptr;
    struct pid_resid *resid_next_resid_ptr;

    struct pid_resid *resid_prev_pid_ptr;
    struct pid_resid *resid_next_pid_ptr;
};
/*
 * first pointer to pid_resid(H:pid V:resid)
 */
static struct pid_resid *pid_prev_ptr = (struct pid_resid *) NULL;
static struct pid_resid *pid_next_ptr = (struct pid_resid *) NULL;
/*
 * first pointer to pid_resid(H:resid V:pid)
 */
static struct pid_resid *resid_prev_ptr = (struct pid_resid *) NULL;
static struct pid_resid *resid_next_ptr = (struct pid_resid *) NULL;

/*
 * key string for administrator
 */
static char *AdminKeyStr = (char *) NULL;

/* 
 * ============================================================
 * USER FUNCTIONS DEFINITION START
 * ============================================================
 */

/*
 * function : lock resource
 */
int grm_lock(pid, resid, mode, keystr)
char *pid;                      /* process id, max MAX_IDLEN bytes */
char *resid;                    /* resource id, max MAX_IDLEN bytes */
int mode;                       /* SHARE_LOCK, EXCLUSIVE_LOCK */
char *keystr;                   /* key string, max MAX_IDLEN bytes */
{
    int stat;
    struct pid_resid *pid_resid;

    if (mode != SHARE_LOCK && mode != EXCLUSIVE_LOCK) {
        fprintf(stderr, "grm_lock mode error(mode=%d)\n", mode);
        return NG;
    }
#if 0
    if ((pid_resid = (struct pid_resid *) ExistPidResid(pid, resid))
        != (struct pid_resid *) NULL) {
        fprintf(stderr, "grm_lock already locked(pid=%-s, resid=%-s)\n",
                pid, resid);
        return NG;
    } else {
        if ((pid_resid =
             (struct pid_resid *) CreatePidResid(pid, resid,
                                                 keystr)) ==
            (struct pid_resid *) NULL) {
            return NG;
        }
    }
#else
    if ((pid_resid = (struct pid_resid *) ExistPidResid(pid, resid))
        != (struct pid_resid *) NULL) {
        if (pid_resid->status == SHARE_LOCK){
            if (mode == SHARE_LOCK){
                return OK;
            }else{ /* EXCLUSIVE_LOCK */
                if (DestroyPidResid(pid, resid, keystr) == -1) {
                    return NG;
                }
            }
        }else if (pid_resid->status == EXCLUSIVE_LOCK){
            if (mode == SHARE_LOCK){
                return OK;
            }else{ /* EXCLUSIVE_LOCK */
                return OK;
            }
        }else{
            fprintf(stderr, "grm_lock status error(pid=%-s, resid=%-s, status=%d)\n", pid, resid, pid_resid->status);
            return NG;
        }
    }
    if ((pid_resid =
         (struct pid_resid *) CreatePidResid(pid, resid,
                                             keystr)) ==
        (struct pid_resid *) NULL) {
        return NG;
    }
#endif

    stat = ExclCheck(pid, resid, mode);
    if (stat == OK) {
        pid_resid->status = mode;
        return OK;
    } else if (stat == DEADLOCK) {
        if (DestroyPidResid(pid, resid, keystr) == -1) {
            return NG;
        } else {
            return DEADLOCK;
        }
    } else {
        if (mode == SHARE_LOCK) {
            pid_resid->status = SHARE_WAIT;
        } else {
            pid_resid->status = EXCLUSIVE_WAIT;
        }
        return WAIT;
    }
}

/*
 * function : wait
 */
int grm_wait(pid, resid, fd_sock, path)
char *pid;                      /* process id, max MAX_IDLEN bytes */
char *resid;                    /* resource id, max MAX_IDLEN bytes */
int fd_sock;                    /* file descripter to close in child process */
char *path;                     /* path to admin_keystring_file for making msgkey */
{
    struct pid_resid *pid_residw;
    struct pid_resid *pid_residww;
    struct msgbuf2 msgbuf;
    int msqid, forkpid;


    if ((forkpid = fork()) == 0) {      /* child */
/*
 * search for resource to wait
 */
        pid_residw = pid_next_ptr;
        while (pid_residw != (struct pid_resid *) NULL
               && strncmp(pid_residw->pid, pid, MAX_IDLEN) != 0) {
            pid_residw = pid_residw->pid_next_pid_ptr;
        }

        pid_residww = pid_residw;
        while (pid_residww != (struct pid_resid *) NULL
               && strncmp(pid_residww->resid, resid, MAX_IDLEN) != 0) {
            pid_residww = pid_residww->pid_next_resid_ptr;
        }

        if (pid_residww == (struct pid_resid *) NULL) {
            fprintf(stderr,
                    "grm_wait resource not found(pid=%-s, resid=%-s)\n",
                    pid, resid);
            return -2;
        }
/*
 * child main
 */

        if (close(fd_sock) == -1) {
            fprintf(stderr,
                    "grm_wait socket close error(pid=%-s, resid=%-s)\n",
                    pid, resid);
            return -2;
        }

        if ((msqid =
             msgget((key_t) ftok(path, 0), 0600 | IPC_CREAT)) == -1) {
            fprintf(stderr,
                    "grm_wait msgget error(pid=%-s, resid=%-s, path=%-s)\n",
                    pid, resid, path);
            return -2;
        }

        if (msgrcv(msqid, &msgbuf, BUF_LEN, pid_residww->msgtype, 0) == -1) {
            fprintf(stderr, "grm_wait msgrcv error(pid=%-s, resid=%-s)\n",
                    pid, resid);
            return -2;
        }

        if (strncmp(msgbuf.data, "WAKEUP", strlen("WAKEUP")) != 0) {
            fprintf(stderr,
                    "grm_wait unexpected wakeup(pid=%-s, resid=%-s)\n",
                    pid, resid);
            return -2;
        }

        return forkpid;
    } else {                    /* parent */
        return forkpid;
    }
}

/*
 * function : unlock resource
 */
int grm_unlock(pid, resid, keystr)
char *pid;                      /* process id, max MAX_IDLEN bytes */
char *resid;                    /* resource id, max MAX_IDLEN bytes */
char *keystr;                   /* key string, max MAX_IDLEN bytes */
{
    struct pid_resid *pid_residw;
    struct pid_resid *pid_residww;

    pid_residw = pid_next_ptr;
    while (pid_residw != (struct pid_resid *) NULL
           && strncmp(pid_residw->pid, pid, MAX_IDLEN) != 0) {
        pid_residw = pid_residw->pid_next_pid_ptr;
    }

    pid_residww = pid_residw;
    while (pid_residww != (struct pid_resid *) NULL
           && strncmp(pid_residww->resid, resid, MAX_IDLEN) != 0) {
        pid_residww = pid_residww->pid_next_resid_ptr;
    }

    if (pid_residww == (struct pid_resid *) NULL) {
        fprintf(stderr,
                "grm_unlock resource not found(pid=%-s, resid=%-s)\n", pid,
                resid);
        return -1;
    }
    if (pid_residww->status == SHARE_WAIT
        || pid_residww->status == EXCLUSIVE_WAIT) {
        fprintf(stderr,
                "grm_unlock resource is not locked(pid=%-s, resid=%-s)\n",
                pid, resid);
        return -1;
    }

    return DestroyPidResid(pid, resid, keystr);
}

/*
 * function : wakeup process which wait resource
 */
int grm_wakeup(resid, path)
char *resid;                    /* resource id, max MAX_IDLEN bytes */
char *path;                     /* path to admin_keystring_file for making msgkey */
{
    struct msgbuf2 msgbuf;
    int msqid;
    struct pid_resid *pid_residw;
    struct pid_resid *pid_residww;

    pid_residw = resid_next_ptr;
    while (pid_residw != (struct pid_resid *) NULL
           && strncmp(pid_residw->resid, resid, MAX_IDLEN) != 0) {
        pid_residw = pid_residw->resid_next_resid_ptr;
    }

    pid_residww = pid_residw;
    if (pid_residww != (struct pid_resid *) NULL) {
        if (pid_residww->status == SHARE_WAIT) {
            while (pid_residww != (struct pid_resid *) NULL
                   && pid_residww->status == SHARE_WAIT) {
                if ((msqid =
                     msgget((key_t) ftok(path, 0),
                            0600 | IPC_CREAT)) == -1) {
                    fprintf(stderr,
                            "grm_wakeup msgget error(resid=%-s, path=%-s)\n",
                            resid, path);
                    return -1;
                }

                msgbuf.type = pid_residww->msgtype;
                strncpy(msgbuf.data, "WAKEUP\n", strlen("WAKEUP\n"));

                if (msgsnd(msqid, &msgbuf, strlen(msgbuf.data), 0) == -1) {
                    fprintf(stderr,
                            "grm_wakeup msgsnd error(resid=%-s, path=%-s)\n",
                            resid, path);
                    return -1;
                }
                pid_residww->status = SHARE_LOCK;
                pid_residww = pid_residww->resid_next_pid_ptr;
            }
        } else if (pid_residww->status == EXCLUSIVE_WAIT) {
            if ((msqid =
                 msgget((key_t) ftok(path, 0), 0600 | IPC_CREAT)) == -1) {
                fprintf(stderr,
                        "grm_wakeup msgget error(resid=%-s, path=%-s)\n",
                        resid, path);
                return -1;
            }

            msgbuf.type = pid_residww->msgtype;
            strncpy(msgbuf.data, "WAKEUP\n", strlen("WAKEUP\n"));

            if (msgsnd(msqid, &msgbuf, strlen(msgbuf.data), 0) == -1) {
                fprintf(stderr,
                        "grm_wakeup msgsnd error(resid=%-s, path=%-s)\n",
                        resid, path);
                return -1;
            }
            pid_residww->status = EXCLUSIVE_LOCK;
        }
    }
    return 0;
}

/*
 * function : set key string for administrator.
 */
int grm_setkeystr(admin_keystr)
char *admin_keystr;
{
    if (AdminKeyStr != (char *) NULL) {
        free(AdminKeyStr);
    }

    if ((AdminKeyStr =
         (char *) malloc(strlen(admin_keystr) <=
                         MAX_IDLEN ? strlen(admin_keystr) + 1 : MAX_IDLEN +
                         1)) == (char *) NULL) {
        fprintf(stderr,
                "grm_setkeystr AdminKeyStr allocate error(admin_keystr=%-s)\n",
                admin_keystr);
        return -1;
    }
    strncpy(AdminKeyStr, admin_keystr,
            strlen(admin_keystr) <=
            MAX_IDLEN ? strlen(admin_keystr) + 1 : MAX_IDLEN + 1);
    AdminKeyStr[strlen(admin_keystr) <=
                MAX_IDLEN ? strlen(admin_keystr) : MAX_IDLEN] = '\0';

    return 0;
}

/*
 * function : show resource structure pid(H) resid(V)
 */
int grm_spr(admin_keystr)
char *admin_keystr;
{
    struct pid_resid *pid_residw;
    struct pid_resid *pid_residww;

    if (strncmp(AdminKeyStr, admin_keystr, strlen(AdminKeyStr)) != 0
        || strlen(AdminKeyStr) != strlen(admin_keystr)) {
        fprintf(stderr, "grm_spr AdminKeyStr unmatch\n");
        return -1;
    }

    pid_residw = pid_next_ptr;
    while (pid_residw != (struct pid_resid *) NULL) {
        pid_residww = pid_residw;
        while (pid_residww != (struct pid_resid *) NULL) {
            fprintf(stderr, "pid=(%-s) resid=(%-s) ", pid_residww->pid,
                    pid_residww->resid);
            if (pid_residww->status == SHARE_LOCK) {
                fprintf(stderr, "SHARE_LOCK ");
            } else if (pid_residww->status == EXCLUSIVE_LOCK) {
                fprintf(stderr, "EXCLUSIVE_LOCK ");
            } else if (pid_residww->status == SHARE_WAIT) {
                fprintf(stderr, "SHARE_WAIT ");
            } else if (pid_residww->status == EXCLUSIVE_WAIT) {
                fprintf(stderr, "EXCLUSIVE_WAIT ");
            } else {
                fprintf(stderr, "unknow status ");
            }
            fprintf(stderr, "keystr=(%-s)\n", pid_residww->keystr);
            pid_residww = pid_residww->pid_next_resid_ptr;
        }
        pid_residw = pid_residw->pid_next_pid_ptr;
    }
    return 0;
}

/*
 * function : show resource structure resid(H) pid(V)
 */
int grm_srp(admin_keystr)
char *admin_keystr;
{
    struct pid_resid *pid_residw;
    struct pid_resid *pid_residww;

    if (strncmp(AdminKeyStr, admin_keystr, strlen(AdminKeyStr)) != 0
        || strlen(AdminKeyStr) != strlen(admin_keystr)) {
        fprintf(stderr, "grm_srp AdminKeyStr unmatch\n");
        return -1;
    }

    pid_residw = resid_next_ptr;
    while (pid_residw != (struct pid_resid *) NULL) {
        pid_residww = pid_residw;
        while (pid_residww != (struct pid_resid *) NULL) {
            fprintf(stderr, "resid=(%-s) pid=(%-s) ", pid_residww->resid,
                    pid_residww->pid);
            if (pid_residww->status == SHARE_LOCK) {
                fprintf(stderr, "SHARE_LOCK ");
            } else if (pid_residww->status == EXCLUSIVE_LOCK) {
                fprintf(stderr, "EXCLUSIVE_LOCK ");
            } else if (pid_residww->status == SHARE_WAIT) {
                fprintf(stderr, "SHARE_WAIT ");
            } else if (pid_residww->status == EXCLUSIVE_WAIT) {
                fprintf(stderr, "EXCLUSIVE_WAIT ");
            } else {
                fprintf(stderr, "unknow status ");
            }
            fprintf(stderr, "keystr=(%-s)\n", pid_residww->keystr);
            pid_residww = pid_residww->resid_next_pid_ptr;
        }
        pid_residw = pid_residw->resid_next_resid_ptr;
    }
    return 0;
}

/*
 * function : remove msgq for lock
 */
int grm_rmmsgq(path)
char *path;                     /* path to admin_keystring_file for making msgkey */
{
    int msqid;

    if ((msqid = msgget((key_t) ftok(path, 0), 0600 | IPC_CREAT)) == -1) {
        fprintf(stderr, "grm_rmmsgq msgget error(path=%-s)\n", path);
        return -1;
    }

    if (msgctl(msqid, IPC_RMID, NULL) == -1) {
        fprintf(stderr, "grm_rmmsgq msgctl remove error(path=%-s)\n",
                path);
        return -1;
    }

    return 0;
}

/* 
 * ============================================================
 * USER FUNCTIONS DEFINITION END
 * ============================================================
 */

/*
 * function : find resource structure
 * return : NULL, pointer to struct pid_resid
 */
static struct pid_resid *ExistPidResid(pid, resid)
char *pid;                      /* process id, max MAX_IDLEN bytes */
char *resid;                    /* resource id, max MAX_IDLEN bytes */
{
    struct pid_resid *pid_resid;
    struct pid_resid *pid_residw;

    pid_resid = pid_next_ptr;
    while (pid_resid != (struct pid_resid *) NULL) {
        if (strncmp(pid_resid->pid, pid, MAX_IDLEN) == 0) {     /* find pid in resource structure */
            pid_residw = pid_resid;
            while (pid_residw != (struct pid_resid *) NULL) {
                if (strncmp(pid_residw->resid, resid, MAX_IDLEN) == 0) {        /* find resid in resource structure */
                    return (struct pid_resid *) pid_residw;
                }
                pid_residw = pid_residw->pid_next_resid_ptr;
            }
        }
        pid_resid = pid_resid->pid_next_pid_ptr;
    }
    return (struct pid_resid *) NULL;
}

/*
 * function : create resource structure
 * return : NULL, pointer to struct pid_resid
 */
static struct pid_resid *CreatePidResid(pid, resid, keystr)
char *pid;                      /* process id, max MAX_IDLEN bytes */
char *resid;                    /* resource id, max MAX_IDLEN bytes */
char *keystr;                   /* key string, max MAX_IDLEN bytes */
{
    struct pid_resid *pid_resid;
    struct pid_resid *pid_residw;
    struct pid_resid *pid_residww;

/*
 * memory allocate
 */
    if ((pid_resid =
         (struct pid_resid *) malloc(sizeof(struct pid_resid))) ==
        (struct pid_resid *) NULL) {
        fprintf(stderr,
                "CreatePidResid pid_resid allocate error(pid=%-s resid=%-s)\n",
                pid, resid);
        return pid_resid;
    }
    if ((pid_resid->pid =
         (char *) malloc(strlen(pid) <=
                         MAX_IDLEN ? strlen(pid) + 1 : MAX_IDLEN + 1)) ==
        (char *) NULL) {
        fprintf(stderr,
                "CreatePidResid pid allocate error(pid=%-s resid=%-s)\n",
                pid, resid);
        free(pid_resid);
        return (struct pid_resid *) NULL;
    }
    if ((pid_resid->resid =
         (char *) malloc(strlen(resid) <=
                         MAX_IDLEN ? strlen(resid) + 1 : MAX_IDLEN + 1)) ==
        (char *) NULL) {
        fprintf(stderr,
                "CreatePidResid resid allocate error(pid=%-s resid=%-s)\n",
                pid, resid);
        free(pid_resid);
        free(pid_resid->pid);
        return (struct pid_resid *) NULL;
    }
    if ((pid_resid->keystr =
         (char *) malloc(strlen(keystr) <=
                         MAX_IDLEN ? strlen(keystr) + 1 : MAX_IDLEN +
                         1)) == (char *) NULL) {
        fprintf(stderr,
                "CreatePidResid key string allocate error(pid=%-s resid=%-s key string length=%d)\n",
                pid, resid,
                strlen(keystr) <=
                MAX_IDLEN ? strlen(keystr) + 1 : MAX_IDLEN + 1);
        free(pid_resid);
        free(pid_resid->pid);
        free(pid_resid->resid);
        return (struct pid_resid *) NULL;
    }

/*
 * initialize
 */
    pid_resid->pid[0] = '\0';
    pid_resid->resid[0] = '\0';
    pid_resid->keystr[0] = '\0';
    pid_resid->status = 0;      /* SHARE_WAIT, EXCLUSIVE_WAIT, SHARE_LOCK, EXCLUSIVE_LOCK */

    pid_resid->pid_prev_pid_ptr = (struct pid_resid *) NULL;
    pid_resid->pid_next_pid_ptr = (struct pid_resid *) NULL;

    pid_resid->pid_prev_resid_ptr = (struct pid_resid *) NULL;
    pid_resid->pid_next_resid_ptr = (struct pid_resid *) NULL;

    pid_resid->resid_prev_resid_ptr = (struct pid_resid *) NULL;
    pid_resid->resid_next_resid_ptr = (struct pid_resid *) NULL;

    pid_resid->resid_prev_pid_ptr = (struct pid_resid *) NULL;
    pid_resid->resid_next_pid_ptr = (struct pid_resid *) NULL;

/*
 * setting
 */
    strncpy(pid_resid->pid, pid,
            strlen(pid) <= MAX_IDLEN ? strlen(pid) + 1 : MAX_IDLEN + 1);
    pid_resid->pid[strlen(pid) <= MAX_IDLEN ? strlen(pid) : MAX_IDLEN] =
        '\0';

    strncpy(pid_resid->resid, resid,
            strlen(resid) <=
            MAX_IDLEN ? strlen(resid) + 1 : MAX_IDLEN + 1);
    pid_resid->resid[strlen(resid) <=
                     MAX_IDLEN ? strlen(resid) : MAX_IDLEN] = '\0';

    strncpy(pid_resid->keystr, keystr,
            strlen(keystr) <=
            MAX_IDLEN ? strlen(keystr) + 1 : MAX_IDLEN + 1);
    pid_resid->keystr[strlen(keystr) <=
                      MAX_IDLEN ? strlen(keystr) : MAX_IDLEN] = '\0';

    pid_resid->msgtype = abs((long) pid_resid);

    if (pid_prev_ptr == (struct pid_resid *) NULL && pid_next_ptr == (struct pid_resid *) NULL) {       /* first resource */
        pid_prev_ptr = pid_resid;
        pid_next_ptr = pid_resid;
    } else {
        pid_residw = pid_next_ptr;
        while (pid_residw != (struct pid_resid *) NULL
               && strncmp(pid_resid->pid, pid_residw->pid,
                          MAX_IDLEN) != 0) {
            pid_residw = pid_residw->pid_next_pid_ptr;
        }

        if (pid_residw == (struct pid_resid *) NULL) {  /* first pid */
            pid_resid->pid_prev_pid_ptr = pid_prev_ptr;
            pid_prev_ptr->pid_next_pid_ptr = pid_resid;
            pid_prev_ptr = pid_resid;
        } else {
            pid_residww = pid_residw;
            while (pid_residww->pid_next_resid_ptr !=
                   (struct pid_resid *) NULL) {
                pid_residww = pid_residww->pid_next_resid_ptr;
            }
            pid_residww->pid_next_resid_ptr = pid_resid;
            pid_resid->pid_prev_resid_ptr = pid_residww;
        }
    }

    if (resid_prev_ptr == (struct pid_resid *) NULL && resid_next_ptr == (struct pid_resid *) NULL) {   /* first resource */
        resid_prev_ptr = pid_resid;
        resid_next_ptr = pid_resid;
    } else {
        pid_residw = resid_next_ptr;
        while (pid_residw != (struct pid_resid *) NULL
               && strncmp(pid_resid->resid, pid_residw->resid,
                          MAX_IDLEN) != 0) {
            pid_residw = pid_residw->resid_next_resid_ptr;
        }

        if (pid_residw == (struct pid_resid *) NULL) {  /* first resource */
            pid_resid->resid_prev_resid_ptr = resid_prev_ptr;
            resid_prev_ptr->resid_next_resid_ptr = pid_resid;
            resid_prev_ptr = pid_resid;
        } else {
            pid_residww = pid_residw;
            while (pid_residww->resid_next_pid_ptr !=
                   (struct pid_resid *) NULL) {
                pid_residww = pid_residww->resid_next_pid_ptr;
            }
            pid_residww->resid_next_pid_ptr = pid_resid;
            pid_resid->resid_prev_pid_ptr = pid_residww;
        }
    }
    return (struct pid_resid *) pid_resid;
}

/*
 * function : destroy resource structure
 * return : -1,0
 */
static int DestroyPidResid(pid, resid, keystr)
char *pid;                      /* process id, max MAX_IDLEN bytes */
char *resid;                    /* resource id, max MAX_IDLEN bytes */
char *keystr;                   /* key string, max MAX_IDLEN bytes */
{
    struct pid_resid *pid_residw;
    struct pid_resid *pid_residww;

    pid_residw = pid_next_ptr;
    while (pid_residw != (struct pid_resid *) NULL
           && strncmp(pid_residw->pid, pid, MAX_IDLEN) != 0) {
        pid_residw = pid_residw->pid_next_pid_ptr;
    }
    if (pid_residw == (struct pid_resid *) NULL) {
        fprintf(stderr, "DestroyPidResid pid not found(pid=%-s)\n", pid);
        return -1;
    } else {
        pid_residww = pid_residw;
        while (pid_residww != (struct pid_resid *) NULL
               && strncmp(pid_residww->resid, resid, MAX_IDLEN) != 0) {
            pid_residww = pid_residww->pid_next_resid_ptr;
        }
        if (pid_residww == (struct pid_resid *) NULL) {
            fprintf(stderr, "DestroyPidResid resid not found(resid=%-s)\n",
                    resid);
            return -1;
        }
    }

    if (strncmp(pid_residww->keystr, keystr, strlen(pid_residww->keystr))
        != 0 || strlen(pid_residww->keystr) != strlen(keystr)) {
        fprintf(stderr,
                "DestroyPidResid key string unmatch(pid =%s resid=%-s)\n",
                pid, resid);
        return -1;
    }

    if (pid_residww->pid_prev_resid_ptr == (struct pid_resid *) NULL && pid_residww->pid_next_resid_ptr == (struct pid_resid *) NULL) { /* top pid without slave */
        if (pid_residww->pid_prev_pid_ptr == (struct pid_resid *) NULL && pid_residww->pid_next_pid_ptr == (struct pid_resid *) NULL) { /* no left and right */
            pid_next_ptr = (struct pid_resid *) NULL;
            pid_prev_ptr = (struct pid_resid *) NULL;
        } else if (pid_residww->pid_prev_pid_ptr == (struct pid_resid *) NULL) {        /* most left */
            pid_next_ptr = pid_residww->pid_next_pid_ptr;
            pid_residww->pid_next_pid_ptr->pid_prev_pid_ptr =
                (struct pid_resid *) NULL;
        } else if (pid_residww->pid_next_pid_ptr == (struct pid_resid *) NULL) {        /* most right */
            pid_prev_ptr = pid_residww->pid_prev_pid_ptr;
            pid_residww->pid_prev_pid_ptr->pid_next_pid_ptr =
                (struct pid_resid *) NULL;
        } else {                /* between left and right */
            pid_residww->pid_prev_pid_ptr->pid_next_pid_ptr =
                pid_residww->pid_next_pid_ptr;
            pid_residww->pid_next_pid_ptr->pid_prev_pid_ptr =
                pid_residww->pid_prev_pid_ptr;
        }
    } else if (pid_residww->pid_prev_resid_ptr == (struct pid_resid *) NULL) {  /* top pid with slave */
        if (pid_residww->pid_prev_pid_ptr == (struct pid_resid *) NULL && pid_residww->pid_next_pid_ptr == (struct pid_resid *) NULL) { /* no left and right */
            pid_next_ptr = pid_residww->pid_next_resid_ptr;
            pid_prev_ptr = pid_residww->pid_next_resid_ptr;
            pid_residww->pid_next_resid_ptr->pid_prev_resid_ptr =
                (struct pid_resid *) NULL;
        } else if (pid_residww->pid_prev_pid_ptr == (struct pid_resid *) NULL) {        /* most left */
            pid_next_ptr = pid_residww->pid_next_resid_ptr;
            pid_residww->pid_next_pid_ptr->pid_prev_pid_ptr =
                pid_residww->pid_next_resid_ptr;
            pid_residww->pid_next_resid_ptr->pid_prev_resid_ptr =
                (struct pid_resid *) NULL;
            pid_residww->pid_next_resid_ptr->pid_next_pid_ptr =
                pid_residww->pid_next_pid_ptr;
        } else if (pid_residww->pid_next_pid_ptr == (struct pid_resid *) NULL) {        /* most right */
            pid_prev_ptr = pid_residww->pid_next_resid_ptr;
            pid_residww->pid_prev_pid_ptr->pid_next_pid_ptr =
                pid_residww->pid_next_resid_ptr;
            pid_residww->pid_next_resid_ptr->pid_prev_resid_ptr =
                (struct pid_resid *) NULL;
            pid_residww->pid_next_resid_ptr->pid_prev_pid_ptr =
                pid_residww->pid_prev_pid_ptr;
        } else {                /* between left and right */
            pid_residww->pid_prev_pid_ptr->pid_next_pid_ptr =
                pid_residww->pid_next_resid_ptr;
            pid_residww->pid_next_pid_ptr->pid_prev_pid_ptr =
                pid_residww->pid_next_resid_ptr;
            pid_residww->pid_next_resid_ptr->pid_prev_resid_ptr =
                (struct pid_resid *) NULL;
            pid_residww->pid_next_resid_ptr->pid_next_pid_ptr =
                pid_residww->pid_next_pid_ptr;
            pid_residww->pid_next_resid_ptr->pid_prev_pid_ptr =
                pid_residww->pid_prev_pid_ptr;
        }
    } else if (pid_residww->pid_next_resid_ptr == (struct pid_resid *) NULL) {  /* bottom pid */
        if (pid_residww->pid_prev_pid_ptr == (struct pid_resid *) NULL && pid_residww->pid_next_pid_ptr == (struct pid_resid *) NULL) { /* no left and right */
            pid_residww->pid_prev_resid_ptr->pid_next_resid_ptr =
                (struct pid_resid *) NULL;
        } else if (pid_residww->pid_prev_pid_ptr == (struct pid_resid *) NULL) {        /* most left */
            pid_residww->pid_prev_resid_ptr->pid_next_resid_ptr =
                (struct pid_resid *) NULL;
        } else if (pid_residww->pid_next_pid_ptr == (struct pid_resid *) NULL) {        /* most right */
            pid_residww->pid_prev_resid_ptr->pid_next_resid_ptr =
                (struct pid_resid *) NULL;
        } else {                /* between left and right */
            pid_residww->pid_prev_resid_ptr->pid_next_resid_ptr =
                (struct pid_resid *) NULL;
        }
    } else {                    /* pid between top and bottom */
        if (pid_residww->pid_prev_pid_ptr == (struct pid_resid *) NULL && pid_residww->pid_next_pid_ptr == (struct pid_resid *) NULL) { /* no left and right */
            pid_residww->pid_next_resid_ptr->pid_prev_resid_ptr =
                pid_residww->pid_prev_resid_ptr;
            pid_residww->pid_prev_resid_ptr->pid_next_resid_ptr =
                pid_residww->pid_next_resid_ptr;
        } else if (pid_residww->pid_prev_pid_ptr == (struct pid_resid *) NULL) {        /* most left */
            pid_residww->pid_next_resid_ptr->pid_prev_resid_ptr =
                pid_residww->pid_prev_resid_ptr;
            pid_residww->pid_prev_resid_ptr->pid_next_resid_ptr =
                pid_residww->pid_next_resid_ptr;
        } else if (pid_residww->pid_next_pid_ptr == (struct pid_resid *) NULL) {        /* most right */
            pid_residww->pid_next_resid_ptr->pid_prev_resid_ptr =
                pid_residww->pid_prev_resid_ptr;
            pid_residww->pid_prev_resid_ptr->pid_next_resid_ptr =
                pid_residww->pid_next_resid_ptr;
        } else {                /* between left and right */
            pid_residww->pid_next_resid_ptr->pid_prev_resid_ptr =
                pid_residww->pid_prev_resid_ptr;
            pid_residww->pid_prev_resid_ptr->pid_next_resid_ptr =
                pid_residww->pid_next_resid_ptr;
        }
    }

    if (pid_residww->resid_prev_pid_ptr == (struct pid_resid *) NULL && pid_residww->resid_next_pid_ptr == (struct pid_resid *) NULL) { /* top pid without slave */
        if (pid_residww->resid_prev_resid_ptr == (struct pid_resid *) NULL && pid_residww->resid_next_resid_ptr == (struct pid_resid *) NULL) { /* no left and right */
            resid_next_ptr = (struct pid_resid *) NULL;
            resid_prev_ptr = (struct pid_resid *) NULL;
        } else if (pid_residww->resid_prev_resid_ptr == (struct pid_resid *) NULL) {    /* most left */
            resid_next_ptr = pid_residww->resid_next_resid_ptr;
            pid_residww->resid_next_resid_ptr->resid_prev_resid_ptr =
                (struct pid_resid *) NULL;
        } else if (pid_residww->resid_next_resid_ptr == (struct pid_resid *) NULL) {    /* most right */
            resid_prev_ptr = pid_residww->resid_prev_resid_ptr;
            pid_residww->resid_prev_resid_ptr->resid_next_resid_ptr =
                (struct pid_resid *) NULL;
        } else {                /* between left and right */
            pid_residww->resid_prev_resid_ptr->resid_next_resid_ptr =
                pid_residww->resid_next_resid_ptr;
            pid_residww->resid_next_resid_ptr->resid_prev_resid_ptr =
                pid_residww->resid_prev_resid_ptr;
        }
    } else if (pid_residww->resid_prev_pid_ptr == (struct pid_resid *) NULL) {  /* top pid with slave */
        if (pid_residww->resid_prev_resid_ptr == (struct pid_resid *) NULL && pid_residww->resid_next_resid_ptr == (struct pid_resid *) NULL) { /* no left and right */
            resid_next_ptr = pid_residww->resid_next_pid_ptr;
            resid_prev_ptr = pid_residww->resid_next_pid_ptr;
            pid_residww->resid_next_pid_ptr->resid_prev_pid_ptr =
                (struct pid_resid *) NULL;
        } else if (pid_residww->resid_prev_resid_ptr == (struct pid_resid *) NULL) {    /* most left */
            resid_next_ptr = pid_residww->resid_next_pid_ptr;
            pid_residww->resid_next_resid_ptr->resid_prev_resid_ptr =
                pid_residww->resid_next_pid_ptr;
            pid_residww->resid_next_pid_ptr->resid_prev_pid_ptr =
                (struct pid_resid *) NULL;
            pid_residww->resid_next_pid_ptr->resid_next_resid_ptr =
                pid_residww->resid_next_resid_ptr;
        } else if (pid_residww->resid_next_resid_ptr == (struct pid_resid *) NULL) {    /* most right */
            resid_prev_ptr = pid_residww->resid_next_pid_ptr;
            pid_residww->resid_prev_resid_ptr->resid_next_resid_ptr =
                pid_residww->resid_next_pid_ptr;
            pid_residww->resid_next_pid_ptr->resid_prev_pid_ptr =
                (struct pid_resid *) NULL;
            pid_residww->resid_next_pid_ptr->resid_prev_resid_ptr =
                pid_residww->resid_prev_resid_ptr;
        } else {                /* between left and right */
            pid_residww->resid_prev_resid_ptr->resid_next_resid_ptr =
                pid_residww->resid_next_pid_ptr;
            pid_residww->resid_next_resid_ptr->resid_prev_resid_ptr =
                pid_residww->resid_next_pid_ptr;
            pid_residww->resid_next_pid_ptr->resid_prev_pid_ptr =
                (struct pid_resid *) NULL;
            pid_residww->resid_next_pid_ptr->resid_next_resid_ptr =
                pid_residww->resid_next_resid_ptr;
            pid_residww->resid_next_pid_ptr->resid_prev_resid_ptr =
                pid_residww->resid_prev_resid_ptr;
        }
    } else if (pid_residww->resid_next_pid_ptr == (struct pid_resid *) NULL) {  /* bottom pid */
        if (pid_residww->resid_prev_resid_ptr == (struct pid_resid *) NULL && pid_residww->resid_next_resid_ptr == (struct pid_resid *) NULL) { /* no left and right */
            pid_residww->resid_prev_pid_ptr->resid_next_pid_ptr =
                (struct pid_resid *) NULL;
        } else if (pid_residww->resid_prev_resid_ptr == (struct pid_resid *) NULL) {    /* most left */
            pid_residww->resid_prev_pid_ptr->resid_next_pid_ptr =
                (struct pid_resid *) NULL;
        } else if (pid_residww->resid_next_resid_ptr == (struct pid_resid *) NULL) {    /* most right */
            pid_residww->resid_prev_pid_ptr->resid_next_pid_ptr =
                (struct pid_resid *) NULL;
        } else {                /* between left and right */
            pid_residww->resid_prev_pid_ptr->resid_next_pid_ptr =
                (struct pid_resid *) NULL;
        }
    } else {                    /* pid between top and bottom */
        if (pid_residww->resid_prev_resid_ptr == (struct pid_resid *) NULL && pid_residww->resid_next_resid_ptr == (struct pid_resid *) NULL) { /* no left and right */
            pid_residww->resid_next_pid_ptr->resid_prev_pid_ptr =
                pid_residww->resid_prev_pid_ptr;
            pid_residww->resid_prev_pid_ptr->resid_next_pid_ptr =
                pid_residww->resid_next_pid_ptr;
        } else if (pid_residww->resid_prev_resid_ptr == (struct pid_resid *) NULL) {    /* most left */
            pid_residww->resid_next_pid_ptr->resid_prev_pid_ptr =
                pid_residww->resid_prev_pid_ptr;
            pid_residww->resid_prev_pid_ptr->resid_next_pid_ptr =
                pid_residww->resid_next_pid_ptr;
        } else if (pid_residww->resid_next_resid_ptr == (struct pid_resid *) NULL) {    /* most right */
            pid_residww->resid_next_pid_ptr->resid_prev_pid_ptr =
                pid_residww->resid_prev_pid_ptr;
            pid_residww->resid_prev_pid_ptr->resid_next_pid_ptr =
                pid_residww->resid_next_pid_ptr;
        } else {                /* between left and right */
            pid_residww->resid_next_pid_ptr->resid_prev_pid_ptr =
                pid_residww->resid_prev_pid_ptr;
            pid_residww->resid_prev_pid_ptr->resid_next_pid_ptr =
                pid_residww->resid_next_pid_ptr;
        }
    }

    free(pid_residww->pid);
    free(pid_residww->resid);
    free(pid_residww->keystr);
    free(pid_residww);

    return 0;
}

/*
 * function : exclusiv check
 * return : OK, DEADLOCK, WAIT
 */
static int ExclCheck(pid, resid, mode)
char *pid;                      /* process id, max MAX_IDLEN bytes */
char *resid;                    /* resource id, max MAX_IDLEN bytes */
int mode;                       /* SHARE_LOCK, EXCLUSIVE_LOCK */
{
    if (IsUnused(pid, resid, mode)) {
        return OK;
    }

    if (Deadlocl(pid, pid, resid, mode)) {
        return DEADLOCK;
    } else {
        return WAIT;
    }
}

/*
 * function : unused resource check
 * return : FALSE, TRUE
 */
static int IsUnused(pid, resid, mode)
char *pid;                      /* process id, max MAX_IDLEN bytes */
char *resid;                    /* resource id, max MAX_IDLEN bytes */
int mode;                       /* SHARE_LOCK, EXCLUSIVE_LOCK */
{
    struct pid_resid *pid_residw;
    struct pid_resid *pid_residww;

    pid_residw = resid_next_ptr;
    while (pid_residw != (struct pid_resid *) NULL
           && strncmp(pid_residw->resid, resid, MAX_IDLEN) != 0) {
        pid_residw = pid_residw->resid_next_resid_ptr;
    }

    pid_residww = pid_residw;
    while (pid_residww != (struct pid_resid *) NULL
           && strncmp(pid_residww->pid, pid, MAX_IDLEN) != 0) {
        if (mode == SHARE_LOCK) {
            if (pid_residww->status == EXCLUSIVE_LOCK
                || pid_residww->status == EXCLUSIVE_WAIT
                || pid_residww->status == SHARE_WAIT) {
                return FALSE;
            }
        } else {
            if (pid_residww->status == EXCLUSIVE_LOCK
                || pid_residww->status == EXCLUSIVE_WAIT
                || pid_residww->status == SHARE_LOCK
                || pid_residww->status == SHARE_WAIT) {
                return FALSE;
            }
        }
        pid_residww = pid_residww->resid_next_pid_ptr;
    }
    return TRUE;
}

/*
 * function : deadlock check
 * return : FALSE, TRUE
 */
static int Deadlocl(pid1, pid, resid, mode)
char *pid1;                     /* first process id, max MAX_IDLEN bytes */
char *pid;                      /* process id, max MAX_IDLEN bytes */
char *resid;                    /* resource id, max MAX_IDLEN bytes */
int mode;                       /* SHARE_LOCK, EXCLUSIVE_LOCK */
{
    struct pid_resid *pid_residw;
    struct pid_resid *pid_residww;
    struct pid_resid *pid_residwww;

    pid_residw = resid_next_ptr;
    while (pid_residw != (struct pid_resid *) NULL
           && strncmp(resid, pid_residw->resid, MAX_IDLEN) != 0) {
        pid_residw = pid_residw->resid_next_resid_ptr;
    }

    pid_residww = pid_residw;
    while (pid_residww != (struct pid_resid *) NULL && strncmp(pid_residww->pid, pid, MAX_IDLEN) != 0) {        /* when PID is going to lock RESID with MODE, who let PID wait ? */

        if (((pid_residww->status == EXCLUSIVE_LOCK
              || pid_residww->status == EXCLUSIVE_WAIT
              || pid_residww->status == SHARE_WAIT) && mode == SHARE_LOCK)
            || ((pid_residww->status == EXCLUSIVE_LOCK || pid_residww->status == EXCLUSIVE_WAIT || pid_residww->status == SHARE_LOCK || pid_residww->status == SHARE_WAIT) && mode == EXCLUSIVE_LOCK)) {        /* found pid who locked resid already */
            if (strncmp(pid1, pid_residww->pid, MAX_IDLEN) == 0) {      /* pid who locked resid already == first pid then deadlock */
                return TRUE;
            }

            pid_residwww = pid_residww;
            while (pid_residwww->pid_prev_resid_ptr != (struct pid_resid *) NULL) {     /* return to top resource in pid */
                pid_residwww = pid_residwww->pid_prev_resid_ptr;
            }
            while (pid_residwww != (struct pid_resid *) NULL && pid_residwww->status != SHARE_WAIT && pid_residwww->status != EXCLUSIVE_WAIT) { /* find resource which pid wait */
                pid_residwww = pid_residwww->pid_next_resid_ptr;
            }
            if (pid_residwww != (struct pid_resid *) NULL) {    /* what's resource which is waited by pid who let wait previous pid ? */

                if (pid_residwww->status == SHARE_WAIT) {
                    if (Deadlocl(pid1, pid_residwww->pid, pid_residwww->resid, SHARE_LOCK)) {   /* recursive call deadlock */
                        return TRUE;
                    }
                } else {
                    if (Deadlocl(pid1, pid_residwww->pid, pid_residwww->resid, EXCLUSIVE_LOCK)) {       /* recursive call deadlock */
                        return TRUE;
                    }
                }
            }
        }
        pid_residww = pid_residww->resid_next_pid_ptr;
    }

    return FALSE;
}
