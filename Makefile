PURECAP=-mabi=purecap
CC=/home/bg357/cheri/output/sdk/bin/cheri-unknown-freebsd-clang --sysroot=/home/bg357/cheri/output/rootfs-purecap128 -B/home/bg357/cheri/output/sdk -msoft-float $(PURECAP)

CFLAGS=-Wall -Werror
CFLAGS+=-O0
CFLAGS+=-std=c11
CFLAGS+=-c
CFLAGS+=-g
CFLAGS+=-Wno-error=unused-function
CFLAGS+=-Wno-error=unused-variable
CFLAGS+=-Wno-error=unused-label

#LFLAGS=-lcheri_caprevoke

all: libmrs.so test

mrs.o: mrs.c
	$(CC) $(CFLAGS) -fPIC mrs.c -o mrs.o

caprevoke.o: caprevoke.c
	$(CC) $(CFLAGS) -fPIC caprevoke.c -o caprevoke.o

libmrs.so: mrs.o caprevoke.o
	$(CC) -shared $(LFLAGS) mrs.o caprevoke.o -o libmrs.so

test.o: test.c
	$(CC) $(CFLAGS) test.c -o test.o

test: test.o libmrs.so
	$(CC) test.o -L. -lmrs -o test

clean:
	rm -rf mrs.o caprevoke.o test.o libmrs.so test
