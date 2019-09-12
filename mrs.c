/*-
 * Copyright (c) 2019 Brett F. Gutstein
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <cheri/cheric.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/tree.h>
#include <sys/caprevoke.h>
#include <cheri/caprevoke.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#include "printf.h"
#include "mrs.h"

// use mrs on a cheri-enabled system to make a legacy memory allocator that has
// been ported to purecap (1) immune to use-after-reallocation vulnerabilities
// (2) immune to vulnerabilities related to double free, incorrect (arbitrary)
// free, and exposure of allocator metadata. the allocator will already be
// spatially safe by virtue of running purecap.

// mrs can be built as a standalone shared library (#define STANDALONE) for use
// with LD_PRELOAD over an existing allocator - in this case it exports the
// malloc family and mmap fmaily symbols, and it gets the real ones from dlsym.

// mrs can also be linked into an existing cherified malloc implmenetaion
// (#define MALLOC_PREFIX <prefix>), in which case it exports only the malloc
// family symbols. the existing malloc implementation should be modified to use
// mrs_ prefixed versions of mmap family smybols, and its malloc and free
// functions should be prefixed with the defined malloc prefix (e.g.
// <prefix>_malloc) for mrs to consume.

// underlying mallocs must give out 16-byte aligned memory for revocation to work.

// TODO mrs may in the future export library functions that can be used to
// convert a cherified malloc into one that is temporally safe without paying
// all the performance costs of a shim layer.
//
// TODO mrs may in the future also have a more sophisticated quarantine with
// multiple lists and coalescing and MAP_GUARDing. however even with coalescing
// it is not possible to reduce the number of free() calls while using a shim
// layer.
//
// TODO mrs may in the future have more sophisticated multicore support, where
// each core has a copy of data structures used to validate allocations and
// frees. in the common case, these data structures can be checked without
// contention, and in case of a miss on one core it can check the others.
// multicore revocation with separate quarantines can also be used.

/*
 * Knobs:
 *
 * STANDALONE: build mrs as a standalone shared library
 * BYPASS_QUARANTINE: MADV_FREE page-multiple allocations and never free them back to the allocator
 * OFFLOAD_QUARANTINE: process full quarantines in a separate thread
 * DEBUG: print debug statements
 * PRINT_STATS: print statistics on exit
 * CLEAR_ALLOCATIONS: make sure that allocated regions are zeroed (contain no tags or data) before giving them out
 * SANITIZE: perform sanitization on mrs function calls, TODO? exit when desired property violated
 * LOCKS: make mrs thread safe with locks
 * CONCURRENT_REVOCATION_PASS: enable a concurrent revocation pass before the stop-the-world pass
 *
 * JUST_INTERPOSE: just call the real functions
 * JUST_BOOKKEEPING: just update data structures then call the real functions
 * JUST_QUARANTINE: just do bookkeeping and quarantining (no bitmap painting or revocation)
 * JUST_PAINT_BITMAP: do bookkeeping, quarantining, and bitmap painting but no revocation
 *
 * Values:
 *
 * MALLOC_PREFIX: build mrs linked into an existing malloc whose functions are prefixed with MALLOC_PREFIX
 * QUARANTINE_HIGHWATER: limit the quarantine size to QUARANTINE_HIGHWATER number of bytes
 * QUARANTINE_RATIO: limit the quarantine size to 1 / QUARANTINE_RATIO times the size of the heap (default 4)
 *
 */

/*
 * baseline functionality is protection against use-after-reallocation attacks,
 * protection against use-after-free attacks caused by allocator reuse of freed
 * memory for metadata, and protection against double-free and arbitrary free
 * attacks (an allocated region, identified by the base of the capability that
 * points to it, can only be freed once; non-allocated regions cannot be
 * freed). also protects against duplicate allocations.
 *
 * sanitization is validating the size of capabilities passed to free, TODO
 * validating that pages will not be munmapped or madvise free'd while there
 * are still valid allocations on them, validating the size and permissions of
 * capabilities returned by the memory allocator, validating that regions from
 * malloc and mmap are non-overlapping, checking at exit how many allocations
 * are outstanding. these checks may be useful when running a legacy or
 * untrusted malloc, or to debug cherifying a malloc/make going from non-cheri
 * malloc to temporally safe malloc easy.
 */

#define concat_resolved(a, b) a ## b
/* need a function without ## so args will be resolved */
#define concat(a, b) concat_resolved(a,b)

#define cheri_testsubset(x, y) __builtin_cheri_subset_test((x), (y))

/* function declarations and definitions */

void *mrs_malloc(size_t);
void mrs_free(void *);
void *mrs_calloc(size_t, size_t);
void *mrs_realloc(void *, size_t);
int mrs_posix_memalign(void **, size_t, size_t);
void *mrs_aligned_alloc(size_t, size_t);

void *malloc(size_t size) {
  return mrs_malloc(size);
}
void free(void *ptr) {
  return mrs_free(ptr);
}
void *calloc(size_t number, size_t size) {
  return mrs_calloc(number, size);
}
void *realloc(void *ptr, size_t size) {
  return mrs_realloc(ptr, size);
}
int posix_memalign(void **ptr, size_t alignment, size_t size) {
  return mrs_posix_memalign(ptr, alignment, size);
}
void *aligned_alloc(size_t alignment, size_t size) {
  return mrs_aligned_alloc(alignment, size);
}
#ifdef STANDALONE
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  return mrs_mmap(addr, len, prot, flags, fd, offset);
}
int munmap(void *addr, size_t len) {
  return mrs_munmap(addr, len);
}
int madvise(void *addr, size_t len, int behav) {
  return mrs_madvise(addr, len, behav);
}
int posix_madvise(void *addr, size_t len, int behav) {
  return mrs_posix_madvise(addr, len, behav);
}
#endif /* STANDALONE */

#ifdef MALLOC_PREFIX
void *concat(MALLOC_PREFIX,_malloc)(size_t size);
void concat(MALLOC_PREFIX,_free)(void *ptr);
void *concat(MALLOC_PREFIX,_calloc)(size_t, size_t);
void *concat(MALLOC_PREFIX,_realloc)(void *, size_t);
int concat(MALLOC_PREFIX,_posix_memalign)(void **, size_t, size_t);
void *concat(MALLOC_PREFIX,_aligned_alloc)(size_t, size_t);
#endif /* MALLOC_PREFIX */

/* globals */

/* store info about allocated region */
struct mrs_alloc_desc {
  void *allocated_region;
  struct mrs_alloc_desc *next;
};

volatile const struct caprevoke_info *cri;

static size_t page_size;
/* alignment requirement for allocations so they can be painted in the caprevoke bitmap */
static const size_t CAPREVOKE_BITMAP_ALIGNMENT = 16;
static const size_t NEW_DESCRIPTOR_BATCH_SIZE = 10000;
static const size_t MIN_REVOKE_HEAP_SIZE = 8 * 1024 * 1024;

static void *entire_shadow;

static struct mrs_alloc_desc *free_alloc_descs;

static size_t allocated_size;
static size_t max_allocated_size;
static size_t quarantine_size;
static size_t max_quarantine_size;
static struct mrs_alloc_desc *quarantine;
static struct mrs_alloc_desc *full_quarantine;

static void *(*real_malloc) (size_t);
static void (*real_free) (void *);
static void *(*real_calloc) (size_t, size_t);
static void *(*real_realloc) (void *, size_t);
static int (*real_posix_memalign) (void **, size_t, size_t);
static void *(*real_aligned_alloc) (size_t, size_t);

static void *(*real_mmap) (void *, size_t, int, int, int, off_t);
static int (*real_munmap) (void *, size_t);
static int (*real_madvise) (void *, size_t, int);
static int (*real_posix_madvise) (void *, size_t, int);

#ifdef LOCKS
/* locking */

/*
 * hack to initialize mutexes without calling malloc. without this, locking
 * operations in allocation functions would cause an infinite loop. the buf
 * size should be at least sizeof(struct pthread_mutex) from thr_private.h
 */
int _pthread_mutex_init_calloc_cb(pthread_mutex_t *mutex, void *(calloc_cb)(size_t, size_t));
#define create_lock(name) \
  pthread_mutex_t name; \
  char name ## _buf[256] __attribute__((aligned(16))); \
  void *name ## _storage() { \
    return name ## _buf; \
  }

create_lock(printf_lock);
create_lock(free_alloc_descs_lock);
create_lock(quarantine_lock);
create_lock(full_quarantine_lock);

#ifdef OFFLOAD_QUARANTINE
static void *full_quarantine_offload(void *);
/* shouldn't need hack because condition variables are not used in allocation routines */
pthread_cond_t full_quarantine_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t full_quarantine_ready = PTHREAD_COND_INITIALIZER;
#endif /* OFFLOAD_QUARANTINE */

#define mrs_lock(mtx) do {if (pthread_mutex_lock((mtx))) {printf("pthread error\n");exit(7);}} while (0)
#define mrs_unlock(mtx) do {if (pthread_mutex_unlock((mtx))) {printf("pthread error\n");exit(7);}} while (0)

#else /* LOCKS */

#define mrs_lock(mtx)
#define mrs_unlock(mtx)

#endif /* !LOCKS */

/* printf debugging */

void _putchar(char character) {
  write(2, &character, sizeof(char));
}

#define mrs_printf(fmt, ...) \
  do {mrs_lock(&printf_lock); printf(("mrs: " fmt), ##__VA_ARGS__); mrs_unlock(&printf_lock);} while (0)

#define mrs_printcap(name, cap) \
  mrs_printf("capability %s: v:%u s:%u p:%08lx b:%016lx l:%016lx, o:%lx t:%ld\n", (name), cheri_gettag((cap)), cheri_getsealed((cap)), cheri_getperm((cap)), cheri_getbase((cap)), cheri_getlen((cap)), cheri_getoffset((cap)), cheri_gettype((cap)))

#ifdef DEBUG

#define mrs_debug_printf(fmt, ...) \
  mrs_printf(fmt, ##__VA_ARGS__)

#define mrs_debug_printcap(name, cap) \
  mrs_printcap(name,cap)

#else /* DEBUG */

#define mrs_debug_printf(fmt, ...)
#define mrs_debug_printcap(name, cap)

#endif /* !DEBUG */

/* alloc_desc utilities */

struct mrs_alloc_desc *alloc_alloc_desc(void *allocated_region) {
  struct mrs_alloc_desc *ret;
  mrs_lock(&free_alloc_descs_lock);
  if (free_alloc_descs != NULL) {
    ret = free_alloc_descs;
    free_alloc_descs = free_alloc_descs->next;
    mrs_unlock(&free_alloc_descs_lock);
  } else {
    mrs_unlock(&free_alloc_descs_lock);

    mrs_debug_printf("alloc_alloc_desc: mapping new memory\n");
    struct mrs_alloc_desc *new_descs = (struct mrs_alloc_desc *)real_mmap(NULL, NEW_DESCRIPTOR_BATCH_SIZE * sizeof(struct mrs_alloc_desc), PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    if (new_descs == MAP_FAILED) {
      return NULL;
    }
    for (int i = 0; i < NEW_DESCRIPTOR_BATCH_SIZE - 2; i++) {
      new_descs[i].next = &new_descs[i + 1];
    }
    ret = &new_descs[NEW_DESCRIPTOR_BATCH_SIZE - 1];
    mrs_lock(&free_alloc_descs_lock);
    new_descs[NEW_DESCRIPTOR_BATCH_SIZE - 2].next = free_alloc_descs;
    free_alloc_descs = new_descs;
    mrs_unlock(&free_alloc_descs_lock);
  }

  ret->allocated_region = allocated_region;
  return ret;
}

/* initialization */
__attribute__((constructor))
static void init(void) {

#ifdef LOCKS
/* hack to initialize mutexes without calling malloc */
#define initialize_lock(name) \
  _pthread_mutex_init_calloc_cb(&name, name ## _storage)

initialize_lock(printf_lock);
initialize_lock(free_alloc_descs_lock);
initialize_lock(quarantine_lock);
initialize_lock(full_quarantine_lock);
#endif /* LOCKS */

#if defined(STANDALONE)
  real_malloc = dlsym(RTLD_NEXT, "malloc");
  real_free = dlsym(RTLD_NEXT, "free");
  real_calloc = dlsym(RTLD_NEXT, "calloc");
  real_realloc = dlsym(RTLD_NEXT, "realloc");
  real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
  real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
  real_mmap = dlsym(RTLD_NEXT, "mmap");
  real_munmap = dlsym(RTLD_NEXT, "munmap");
  real_madvise = dlsym(RTLD_NEXT, "madvise");
  real_posix_madvise = dlsym(RTLD_NEXT, "posix_madvise");
#elif /* STANDALONE */ defined(MALLOC_PREFIX)
  real_malloc = concat(MALLOC_PREFIX, _malloc);
  real_free = concat(MALLOC_PREFIX, _free);
  real_calloc = concat(MALLOC_PREFIX, _calloc);
  real_realloc = concat(MALLOC_PREFIX, _realloc);
  real_posix_memalign = concat(MALLOC_PREFIX, _posix_memalign);
  real_aligned_alloc = concat(MALLOC_PREFIX, _aligned_alloc);
  real_mmap = mmap;
  real_munmap = munmap;
  real_madvise = madvise;
  real_posix_madvise = posix_madvise;
#else /* !STANDALONE && MALLOC_PREFIX */
#error must build mrs with either STANDALONE or MALLOC_PREFIX defined
#endif /* !(STANDALONE || MALLOC_PREFIX) */

#ifdef OFFLOAD_QUARANTINE
  /* spawn offload thread XXX in purecap spwaning this thread in init() causes main() not to be called */
  pthread_t thd;
  if (pthread_create(&thd, NULL, full_quarantine_offload, NULL)) {
    mrs_printf("pthread error\n");
    exit(7);
  }
#endif /* OFFLOAD_QUARANTINE */

  page_size = getpagesize();
  if ((page_size & (page_size - 1)) != 0) {
    mrs_printf("page_size not power of 2\n");
    exit(7);
  }

  int res = caprevoke_shadow(CAPREVOKE_SHADOW_INFO_STRUCT, NULL, (void **)&cri);
  if (res != 0) {
    mrs_printf("error getting kernel counters\n");
    exit(7);
  }

  if (caprevoke_entire_shadow_cap(&entire_shadow)) {
    mrs_printf("error getting entire shadow cap\n");
    exit(7);
  }
}

#ifdef PRINT_STATS
__attribute__((destructor))
static void fini(void) {
  mrs_printf("fini: heap size %zu, max heap size %zu, quarantine size %zu, max quarantine size %zu\n", allocated_size, max_allocated_size, quarantine_size, max_quarantine_size);
}
#endif /* PRINT_STATS */

/* mrs functions */

void *mrs_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
#ifdef JUST_INTERPOSE
  return real_mmap(addr, len, prot, flags, fd, offset);
#endif /* JUST_INTERPOSE */
  mrs_debug_printf("mrs_mmap: called with addr %p len 0x%zx prot 0x%x flags 0x%x fd %d offset 0x%zx\n", addr, len, prot, flags, fd, offset);
  return real_mmap(addr, len, prot, flags, fd, offset);
}

int mrs_munmap(void *addr, size_t len) {
#ifdef JUST_INTERPOSE
    return real_munmap(addr, len);
#endif /* JUST_INTERPOSE */
  mrs_debug_printf("mrs_munmap: called\n");
  return real_munmap(addr, len);
}

/* TODO write these */
int mrs_madvise(void *addr, size_t len, int behav) {
#ifdef JUST_INTERPOSE
    return real_madvise(addr, len, behav);
#endif /* JUST_INTERPOSE */

  mrs_debug_printf("mrs_madvise: called behav %d\n", behav);
  return real_madvise(addr, len, behav);
}
int mrs_posix_madvise(void *addr, size_t len, int behav) {
#ifdef JUST_INTERPOSE
    return real_posix_madvise(addr, len, behav);
#endif /* JUST_INTERPOSE */

  mrs_debug_printf("mrs_posix_madvise: called\n");
  return real_posix_madvise(addr, len, behav);
}

void *mrs_malloc(size_t size) {
#ifdef JUST_INTERPOSE
    return real_malloc(size);
#endif /* JUST_INTERPOSE */

  /*mrs_debug_printf("mrs_malloc: called\n");*/

  if (size == 0) {
    return NULL;
  }

#ifdef STANDALONE
  /*
   * can't control alignment behavior, so make sure all allocations are aligned
   * for bitmap painting by increasing the size.
   */
  if (size < CAPREVOKE_BITMAP_ALIGNMENT) {
    mrs_printf("mrs_malloc: size under caprevoke alignment, increasing size\n");
    size = CAPREVOKE_BITMAP_ALIGNMENT;
  }
#endif /* STANDALONE */

  void *allocated_region = real_malloc(size);

#ifdef MALLOC_PREFIX
  if ((cheri_getbase(allocated_region) & (CAPREVOKE_BITMAP_ALIGNMENT - 1)) != 0) {
    mrs_printf("mrs_malloc: caprevoke bitmap alignment violated\n");
    exit(7);
  }
#endif /* MALLOC_PREFIX */

#ifdef SANITIZE
  if ((cheri_getlen(allocated_region) & (CAPREVOKE_BITMAP_ALIGNMENT - 1)) != 0) {
    mrs_printf("mrs_malloc: caprevoke bitmap size requirement violated, %zu\n", cheri_getlen(allocated_region));
    exit(7);
  }
#endif /* SANITIZE */

#ifdef CLEAR_ALLOCATIONS
  memset(allocated_region, 0, cheri_getlen(allocated_region));
#endif /* CLEAR_ALLOCATIONS */

  allocated_size += size;
  if (allocated_size > max_allocated_size) {
    max_allocated_size = allocated_size;
  }

  mrs_debug_printf("mrs_malloc: called size 0x%zx address %p\n", size, allocated_region);

  return allocated_region;
}

/*
 * currently, we can use the raw version of bitmap painting functions because we have data
 * structure synchronization that prevents double-frees and only one thread will be painting
 * the bitmap at once (ensured by the full_quarantine_lock). if we switch to full multicore,
 * with each core painting, we wil need to use (at least part of) the non-raw
 * functions. we will also need to use different caprevoke() calls.
 *
 * XXX we now don't prevent double frees and may move to multicore - in this
 * case need to think about bitmap safety
 */
static void flush_full_quarantine() {
  struct mrs_alloc_desc *iter = full_quarantine;
#if !defined(JUST_QUARANTINE)
  while (iter != NULL) {
    /*caprev_shadow_nomap_set(iter->shadow, iter->vmmap_cap, iter->allocated_region);*/
    caprev_shadow_nomap_set_raw(entire_shadow, cheri_getbase(iter->allocated_region), cheri_getbase(iter->allocated_region) + __builtin_align_up(cheri_getlen(iter->allocated_region), CAPREVOKE_BITMAP_ALIGNMENT));
    iter = iter->next;
  }
#endif /* !JUST_QUARANTINE */

#if !defined(JUST_QUARANTINE) && !defined(JUST_PAINT_BITMAP)
  atomic_thread_fence(memory_order_acq_rel); /* don't read epoch until all bitmap painting is done */
  caprevoke_epoch start_epoch = cri->epoch_enqueue;
  struct caprevoke_stats crst;
#ifdef CONCURRENT_REVOCATION_PASS
  const int MRS_CAPREVOKE_FLAGS = CAPREVOKE_LAST_PASS;
#else /* CONCURRENT_REVOCATION_PASS */
  const int MRS_CAPREVOKE_FLAGS = (CAPREVOKE_LAST_PASS | CAPREVOKE_LAST_NO_EARLY);
#endif
  while (!caprevoke_epoch_clears(cri->epoch_dequeue, start_epoch)) {
    caprevoke(MRS_CAPREVOKE_FLAGS, start_epoch, &crst);
  }
#endif /* !JUST_QUARANTINE && !JUST_PAINT_BITMAP */

  struct mrs_alloc_desc *prev;
  iter = full_quarantine;
  while (iter != NULL) {
#if !defined(JUST_QUARANTINE)
    /*caprev_shadow_nomap_clear(iter->shadow, iter->allocated_region);*/
    caprev_shadow_nomap_clear_raw(entire_shadow, cheri_getbase(iter->allocated_region), cheri_getbase(iter->allocated_region) + __builtin_align_up(cheri_getlen(iter->allocated_region), CAPREVOKE_BITMAP_ALIGNMENT));
    atomic_thread_fence(memory_order_release); /* don't construct a pointer to a previously revoked region until the bitmap is cleared. */
#endif /* !JUST_QUARANTINE */
    /* XXX now we don't have the vmmap capability again */
    real_free(iter->allocated_region);
#ifdef SANITIZE
    mrs_lock(&shadow_spaces_lock);
    iter->shadow_desc->allocations--;
    mrs_unlock(&shadow_spaces_lock);
#endif /* SANITIZE */
    prev = iter;
    iter = iter->next;
  }

  /* free the quarantined descriptors */
  mrs_lock(&free_alloc_descs_lock);
  prev->next = free_alloc_descs;
  free_alloc_descs = full_quarantine;
  mrs_unlock(&free_alloc_descs_lock);

  full_quarantine = NULL;
}

#ifdef OFFLOAD_QUARANTINE
static void *full_quarantine_offload(void *arg) {
  while (true) {
    mrs_lock(&full_quarantine_lock);
    while (full_quarantine == NULL) {
      mrs_debug_printf("full_quarantine_offload: waiting for full_quarantine to be ready\n");
      if (pthread_cond_wait(&full_quarantine_ready, &full_quarantine_lock)) {
        mrs_printf("pthread error\n");
        exit(7);
      }
    }
    mrs_debug_printf("full_quarantine_offload: full_quarantine ready\n");
    flush_full_quarantine();
    if (pthread_cond_signal(&full_quarantine_empty)) {
        mrs_printf("pthread error\n");
        exit(7);
    }
    mrs_unlock(&full_quarantine_lock);
  }
  return NULL;
}
#endif /* OFFLOAD_QUARANTINE */

void mrs_free(void *ptr) {
#ifdef JUST_INTERPOSE
    return real_free(ptr);
#endif /* JUST_INTERPOSE */

  mrs_debug_printf("mrs_free: called address %p\n", ptr);

  if (ptr == NULL) {
    return;
  }

#ifdef JUST_BOOKKEEPING
  real_free(ptr);
  return;
#endif /* JUST_BOOKKEEPING */

#ifdef BYPASS_QUARANTINE
  /*
   * if this is a full-page(s) allocation, bypass the quarantine by
   * MADV_FREEing it and never actually freeing it back to the allocator.
   * because we don't know allocator internals, the allocated size must
   * actually be a multiple of the page size.
   *
   * XXX munmap with MAP_GUARD more expensive but would cause trap on access
   *
   * TODO maybe coalesce in quarantine? can't reduce free calls unless we get a full page
   */
  vaddr_t base = cheri_getbase(ptr);
  size_t region_size = cheri_getlen(ptr);
  if (((base & (page_size - 1)) == 0) &&
      ((region_size & (page_size - 1)) == 0)) {
    mrs_debug_printf("mrs_free: page-multiple free, bypassing quarantine\n");
    /*real_madvise(alloc_desc->vmmap_cap, region_size, MADV_FREE); TODO need to lookup and rederive vmmap pointer*/
    return;
  }
#endif /* BYPASS_QUARANTINE */

  struct mrs_alloc_desc *alloc = alloc_alloc_desc(ptr);
  mrs_lock(&quarantine_lock);
  alloc->next = quarantine;
  quarantine = alloc;
  quarantine_size += cheri_getlen(alloc->allocated_region);
  if (quarantine_size > max_quarantine_size) {
    max_quarantine_size = quarantine_size;
  }

  bool should_revoke;

#if defined(QUARANTINE_HIGHWATER)
  should_revoke = (quarantine_size >= QUARANTINE_HIGHWATER);
#else /* QUARANTINE_HIGHWATER */

#  if !defined(QUARANTINE_RATIO)
#    define QUARANTINE_RATIO 4
#  endif /* !QUARANTINE_RATIO */

  should_revoke = (((allocated_size + quarantine_size) >= MIN_REVOKE_HEAP_SIZE) && ((quarantine_size * QUARANTINE_RATIO) >= (allocated_size + quarantine_size)));

#endif /* !QUARANTINE_HIGHWATER */

  if (should_revoke) {
    mrs_printf("mrs_free: passed quarantine threshold, revoking: allocated size %zu quarantine size %zu\n", allocated_size, quarantine_size);

    mrs_lock(&full_quarantine_lock);
#ifdef OFFLOAD_QUARANTINE
    while (full_quarantine != NULL) {
      mrs_debug_printf("mrs_free: waiting for full_quarantine to drain\n");
      if (pthread_cond_wait(&full_quarantine_empty, &full_quarantine_lock)) {
        mrs_printf("pthread error\n");
        exit(7);
      }
    }
    mrs_debug_printf("mrs_free: full_quarantine drained\n");
#endif /* OFFLOAD_QUARANTINE */

    full_quarantine = quarantine;
    quarantine = NULL;
    quarantine_size = 0;
    mrs_unlock(&quarantine_lock);

#ifdef OFFLOAD_QUARANTINE
    if (pthread_cond_signal(&full_quarantine_ready)) {
        mrs_printf("pthread error\n");
        exit(7);
    }
#else /* OFFLOAD_QUARANTINE */
    flush_full_quarantine();
#endif /* !OFFLOAD_QUARANTINE */
    mrs_unlock(&full_quarantine_lock);
  } else {
    mrs_unlock(&quarantine_lock);
  }
}

/*
 * calloc is used to bootstrap the thread library; it is called before the
 * constructor function of this library to allocate a thread and sleep queue.
 * we serve these allocations statically to avoid issues during bootstrap.
 * later calls to calloc will take place after init() so locking will work.
 */
void *mrs_calloc(size_t number, size_t size) {
  static int count = 0;
  static char thread[1968] __attribute__((aligned(16))) = {0}; //1968 sizeof struct pthread in libthr/thread/thr_private.h
  static char sleep_queue[128] __attribute__((aligned(16))) = {0}; //128 sizeof struct sleepqueue in libthr/thread/thr_private.h
  if (count == 0) {
    count++;
    return thread;
  } else if (count == 1) {
    count++;
    return sleep_queue;
  }
#ifdef JUST_INTERPOSE
    return real_calloc(number, size);
#endif /* JUST_INTERPOSE */


  /*mrs_debug_printf("mrs_calloc: called\n");*/

  if (number == 0 || size == 0) {
    return NULL;
  }

#ifdef STANDALONE
  /*
   * can't control alignment behavior, so make sure all allocations are aligned
   * for bitmap painting by increasing the size.
   */
  if ((number * size) < CAPREVOKE_BITMAP_ALIGNMENT) {
    mrs_printf("mrs_calloc: size under caprevoke alignment, increasing size\n");
    size = CAPREVOKE_BITMAP_ALIGNMENT;
  }
#endif /* STANDALONE */

  void *allocated_region = real_calloc(number, size);

#ifdef MALLOC_PREFIX
  if ((cheri_getbase(allocated_region) & (CAPREVOKE_BITMAP_ALIGNMENT - 1)) != 0) {
    mrs_printf("mrs_calloc: caprevoke bitmap alignment violated\n");
    exit(7);
  }
#endif /* MALLOC_PREFIX */

#ifdef SANITIZE
  if ((cheri_getlen(allocated_region) & (CAPREVOKE_BITMAP_ALIGNMENT - 1)) != 0) {
    mrs_printf("mrs_calloc: caprevoke bitmap size requirement violated, %zu\n", cheri_getlen(allocated_region));
    exit(7);
  }
#endif /* SANITIZE */

  /* TODO clear alloacation if SANITIZE? */

  allocated_size += size;
  if (allocated_size> max_allocated_size) {
    max_allocated_size = allocated_size;
  }

  mrs_debug_printf("mrs_calloc: exit called %d size 0x%zx address %p\n", number, size, allocated_region);

  return allocated_region;
}

/*
 * replace realloc with a malloc and free to avoid dangling pointers in case of
 * in-place realloc
 */
void *mrs_realloc(void *ptr, size_t size) {

#ifdef JUST_INTERPOSE
    return real_realloc(ptr, size);
#endif /* JUST_INTERPOSE */

  mrs_debug_printf("mrs_realloc: called ptr %p ptr size %zu new size %zu\n", ptr, cheri_getlen(ptr), size);

  if (size == 0) {
    mrs_free(ptr);
    return NULL;
  }

  if (ptr == NULL) {
    return mrs_malloc(size);
  }

  void *new_alloc = mrs_malloc(size);
  /* old object is not deallocated according to the spec */
  if (new_alloc == NULL) {
    return NULL;
  }
  size_t old_size = cheri_getlen(ptr);
  memcpy(new_alloc, ptr, size < old_size ? size : old_size);
  mrs_free(ptr);
  return new_alloc;
}

/* TODO write these */
int mrs_posix_memalign(void **ptr, size_t alignment, size_t size) {
#ifdef JUST_INTERPOSE
    return real_posix_memalign(ptr, alignment, size);
#endif /* JUST_INTERPOSE */

  mrs_printf("mrs_posix_memalign: called\n");
  return real_posix_memalign(ptr, alignment, size);
}
void *mrs_aligned_alloc(size_t alignment, size_t size) {
#ifdef JUST_INTERPOSE
    return real_aligned_alloc(alignment, size);
#endif /* JUST_INTERPOSE */

  mrs_printf("mrs_aligned_alloc: called\n");
  return real_aligned_alloc(alignment, size);
}
