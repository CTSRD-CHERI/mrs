PURECAP=-mabi=purecap
CC=/home/bg357/cheri/output/sdk/bin/cheri-unknown-freebsd-clang --sysroot=/home/bg357/cheri/output/rootfs128 -B/home/bg357/cheri/output/sdk -msoft-float $(PURECAP)

CFLAGS=-Wall -Werror
CFLAGS+=-O0
CFLAGS+=-std=c11
CFLAGS+=-c
CFLAGS+=-g
CFLAGS+=-Wno-error=unused-function
CFLAGS+=-Wno-error=unused-variable
CFLAGS+=-Wno-error=unused-label

all: libmrs.so

mrs.o: mrs.c
	$(CC) $(CFLAGS) -fPIC mrs.c -o mrs.o

libmrs.so: mrs.o
	$(CC) -shared mrs.o -o libmrs.so

clean:
	rm -rf mrs.o libmrs.so
