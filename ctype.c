/*
 * libwrap�ǻ��Ѥ��Ƥ���ctype_b()��glibc-2.2.x����glibc-2.3.x
 * �˰ܹԤ������ˤ�ꡢctype_b_loc()���ѹ�����Ƥ��ޤä�����
 * �Ф����б�
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
