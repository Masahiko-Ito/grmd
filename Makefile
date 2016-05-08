CC=cc
CFLAGS=-g -Wall # -v
LDFLAGS=
LIBS=-lwrap
PROG=grmd

PREFIX=/usr/local

all: grmd.c grm.c grm.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(PROG) grmd.c grm.c $(LIBS)
install:
	install -d $(PREFIX)/grmd/
	install -c -s grmd $(PREFIX)/bin/
	install -c -m 0600 keystring $(PREFIX)/grmd/
	install -c rc.grmd $(PREFIX)/grmd/
