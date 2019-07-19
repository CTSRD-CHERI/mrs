OBJDIR=objects

CC=/home/bg357/cheri/output/sdk/bin/cheri-unknown-freebsd-clang --sysroot=/home/bg357/cheri/output/rootfs-purecap128 -B/home/bg357/cheri/output/sdk -msoft-float -mabi=purecap

CFLAGS=-Wall -Werror
#CFLAGS+=-O0
CFLAGS+=-std=c11
#CFLAGS+=-g
#CFLAGS+=-Wno-error=unused-function
#CFLAGS+=-Wno-error=unused-variable
#CFLAGS+=-Wno-error=unused-label

all: libmrs.so libjemalloc.so mrstest

# standalone

$(OBJDIR)/mrs-standalone.o: mrs.c
	$(CC) $(CFLAGS) -c -fPIC -DSTANDALONE mrs.c -o $(OBJDIR)/mrs-standalone.o

libmrs.so: $(OBJDIR)/mrs-standalone.o
	$(CC) -shared -lcheri_caprevoke $(OBJDIR)/mrs-standalone.o -o libmrs.so

# jemalloc

$(OBJDIR)/mrs-jemalloc.o: mrs.c
	$(CC) $(CFLAGS) -c -fPIC -DMALLOC_PREFIX=je mrs.c -o $(OBJDIR)/mrs-jemalloc.o

JEMSRCS=jemalloc.c arena.c background_thread.c base.c bin.c bitmap.c \
ckh.c ctl.c div.c extent.c extent_dss.c extent_mmap.c hash.c hooks.c \
large.c log.c malloc_io.c mutex.c mutex_pool.c nstime.c pages.c \
prng.c prof.c rtree.c stats.c sz.c tcache.c ticker.c tsd.c witness.c

JEMOBJPATHS=$(JEMSRCS:%.c=$(OBJDIR)/%.o)

$(JEMOBJPATHS): $(OBJDIR)/%.o : jemalloc/src/%.c
	$(CC) $(CFLAGS) -Ijemalloc/include -I. -DJEMALLOC_NO_RENAME -c -fPIC $< -o $@

libjemalloc.so : $(JEMOBJPATHS) $(OBJDIR)/mrs-jemalloc.o
	$(CC) -shared -lcheri_caprevoke $(OBJDIR)/mrs-jemalloc.o $(JEMOBJPATHS) -o libjemalloc.so

# test
mrstest: test/test.c
	$(CC) $(CFLAGS) test/test.c -o mrstest

clean:
	rm -rf libmrs.so libjemalloc.so mrstest objects/*
