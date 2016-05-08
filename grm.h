/*
 * grm.h: Header file for General resource management functions
 *
 * Copyright 2007 Masahiko Ito <m-ito@myh.no-ip.org>
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
 * Masahiko Ito <m-ito@myh.no-ip.org>
 *
 **************************************************************************
 *
 * History
 *  2004.06.18 first release
 *  2007.01.29 add grm_getpr_xxx()
 *  2007.01.30 add grm_getrp_xxx()
 *  2007.02.14 change MAX_IDLEN 64 to 256
 *
 */

/*
 * mode and status
 */
#define	SHARE_LOCK	(1)
#define	EXCLUSIVE_LOCK	(2)
/*
 * status
 */
#define	SHARE_WAIT	(3)
#define	EXCLUSIVE_WAIT	(4)
/*
 * return of grm_lock()
 */
#define OK		(1)
#define WAIT		(2)
#define DEADLOCK	(3)
#define NG		(4)
/*
 * max length of pid, resid, keystring
 */
#define MAX_IDLEN	(256)
/*
 * user functions
 */
extern int grm_lock();
extern int grm_unlock();
extern int grm_setkeystr();
extern int grm_spr();
extern int grm_srp();
extern int grm_rmmsgq();
extern int grm_wait();
extern int grm_wakeup();
extern int grm_getpr_first();
extern int grm_getpr_next();
extern int grm_getpr_item();
extern int grm_getrp_first();
extern int grm_getrp_next();
extern int grm_getrp_item();
