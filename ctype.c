/*
 * libwrapで使用しているctype_b()がglibc-2.2.xからglibc-2.3.x
 * に移行した事により、ctype_b_loc()に変更されてしまった事に
 * 対する対応
 *
 * change Makefile to
 *   all: grmd.c grm.c grm.h ctype.c
 *    	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROG) grmd.c grm.c ctype.c $(LIBS)
 *
 */
short int **__ctype_b();
short int **__ctype_b_loc();

short int **__ctype_b()
{
    return (short int **) __ctype_b_loc();
}
