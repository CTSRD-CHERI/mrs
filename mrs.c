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

#include <sys/types.h>
#include <sys/caprevoke.h>
#include <sys/mman.h>
#include <sys/tree.h>

#include <cheri/caprevoke.h>
#include <cheri/cheric.h>

#include <machine/vmparam.h>

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "printf.h"

/*
 * Knobs:
 *
 * BYPASS_QUARANTINE: MADV_FREE page-multiple allocations and never free them back to the allocator
 * OFFLOAD_QUARANTINE: process full quarantines in a separate thread
 * DEBUG: print debug statements
 * PRINT_STATS: print statistics on exit
 * CLEAR_ALLOCATIONS: make sure that allocated regions are zeroed (contain no tags or data) before giving them out
 * CONCURRENT_REVOCATION_PASS: enable a concurrent revocation pass before the stop-the-world pass
 *
 * JUST_INTERPOSE: just call the real functions
 * JUST_BOOKKEEPING: just update data structures then call the real functions
 * JUST_QUARANTINE: just do bookkeeping and quarantining (no bitmap painting or revocation)
 * JUST_PAINT_BITMAP: do bookkeeping, quarantining, and bitmap painting but no revocation
 *
 * Values:
 *
 * QUARANTINE_HIGHWATER: limit the quarantine size to QUARANTINE_HIGHWATER number of bytes
 * QUARANTINE_RATIO: limit the quarantine size to 1 / QUARANTINE_RATIO times the size of the heap (default 4)
 *
 */

/* functions */

#define cheri_testsubset(x, y) __builtin_cheri_subset_test((x), (y)) // TODO add to cheric.h

void *mrs_malloc(size_t);
void mrs_free(void *);
void *mrs_calloc(size_t, size_t);
void *mrs_realloc(void *, size_t);
int mrs_posix_memalign(void **, size_t, size_t);
void *mrs_aligned_alloc(size_t, size_t);

static void *mrs_calloc_bootstrap(size_t number, size_t size);

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

/* globals */

// TODO investigate replacing with linked list of arrays
struct mrs_alloc_desc {
  void *allocated_region;
  struct mrs_alloc_desc *next;
};

static size_t page_size;
/* alignment requirement for allocations so they can be painted in the caprevoke bitmap */
static const size_t CAPREVOKE_BITMAP_ALIGNMENT = sizeof(void *); // TODO VM_CAPREVOKE_GSZ_MEM_NOMAP from machine/vmparam.h
static const size_t NEW_DESCRIPTOR_BATCH_SIZE = 10000;
static const size_t MIN_REVOKE_HEAP_SIZE = 8 * 1024 * 1024;

volatile const struct caprevoke_info *cri;
static void *entire_shadow;

#ifndef OFFLOAD_QUARANTINE
static struct mrs_alloc_desc * free_alloc_descs;
#else /* !OFFLOAD_QUARANTINE */
static struct mrs_alloc_desc * _Atomic free_alloc_descs;
#endif /* OFFLOAD_QUARANTINE */

static size_t allocated_size; /* amount of memory that the allocator views as allocated (includes quarantine) */
static size_t max_allocated_size;
static size_t quarantine_size; /* amount of memory in quarantine */
static size_t max_quarantine_size;

static struct mrs_alloc_desc *quarantine;
static struct mrs_alloc_desc *full_quarantine;

static void *(*real_malloc) (size_t);
static void (*real_free) (void *);
static void *(*real_calloc) (size_t, size_t) = mrs_calloc_bootstrap; /* replaced on init */
static void *(*real_realloc) (void *, size_t);
static int (*real_posix_memalign) (void **, size_t, size_t);
static void *(*real_aligned_alloc) (size_t, size_t);

/* locks */

#if defined(DEBUG) || defined(OFFLOAD_QUARANTINE)

#define mrs_lock(mtx) do {if (pthread_mutex_lock((mtx))) {printf("pthread error\n");exit(7);}} while (0)
#define mrs_unlock(mtx) do {if (pthread_mutex_unlock((mtx))) {printf("pthread error\n");exit(7);}} while (0)

/*
 * hack to initialize mutexes without calling malloc. without this, locking
 * operations in allocation functions would cause an infinite loop. the buf
 * size should be at least sizeof(struct pthread_mutex) from thr_private.h
 */
#define create_lock(name) \
  pthread_mutex_t name; \
  char name ## _buf[256] __attribute__((aligned(16))); \
  void *name ## _storage() { \
    return name ## _buf; \
  }
int _pthread_mutex_init_calloc_cb(pthread_mutex_t *mutex, void *(calloc_cb)(size_t, size_t));
#define initialize_lock(name) \
  _pthread_mutex_init_calloc_cb(&name, name ## _storage)

#else /* DEBUG || OFFLOAD_QUARANTINE */

#define mrs_lock(mtx)
#define mrs_unlock(mtx)

#endif /* !DEBUG && !OFFLOAD_QUARANTINE */

#ifdef OFFLOAD_QUARANTINE
static void *full_quarantine_offload(void *);
create_lock(full_quarantine_lock);
/* no hack for these hack because condition variables are not used in allocation routines */
pthread_cond_t full_quarantine_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t full_quarantine_ready = PTHREAD_COND_INITIALIZER;
#endif /* OFFLOAD_QUARANTINE */

/* printf support: not thread safe */

void _putchar(char character) {
  write(2, &character, sizeof(char));
}

#define mrs_printf(fmt, ...) \
  do {printf(("mrs: " fmt), ##__VA_ARGS__);} while (0)

#define mrs_printcap(name, cap) \
  mrs_printf("capability %s: v:%u s:%u p:%08lx b:%016lx l:%016lx, o:%lx t:%ld\n", (name), cheri_gettag((cap)), cheri_getsealed((cap)), cheri_getperm((cap)), cheri_getbase((cap)), cheri_getlen((cap)), cheri_getoffset((cap)), cheri_gettype((cap)))

/* debugging */

#ifdef DEBUG

create_lock(printf_lock);

#define mrs_debug_printf(fmt, ...) \
  mrs_printf(fmt, ##__VA_ARGS__)

#define mrs_debug_printcap(name, cap) \
  mrs_printcap(name,cap)

#else /* DEBUG */

#define mrs_debug_printf(fmt, ...)
#define mrs_debug_printcap(name, cap)

#endif /* !DEBUG */

/* utilities */

static struct mrs_alloc_desc *alloc_alloc_desc(void *allocated_region) {

#ifndef OFFLOAD_QUARANTINE
  struct mrs_alloc_desc *ret;

  if (free_alloc_descs != NULL) {
    ret = free_alloc_descs;
    free_alloc_descs = free_alloc_descs->next;

  } else {
    mrs_debug_printf("alloc_alloc_desc: mapping new memory\n");
    struct mrs_alloc_desc *new_descs = (struct mrs_alloc_desc *)mmap(NULL, NEW_DESCRIPTOR_BATCH_SIZE * sizeof(struct mrs_alloc_desc), PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    if (new_descs == MAP_FAILED) {
      return NULL;
    }
    for (int i = 0; i < NEW_DESCRIPTOR_BATCH_SIZE - 2; i++) {
      new_descs[i].next = &new_descs[i + 1];
    }
    ret = &new_descs[NEW_DESCRIPTOR_BATCH_SIZE - 1];
    new_descs[NEW_DESCRIPTOR_BATCH_SIZE - 2].next = free_alloc_descs;
    free_alloc_descs = new_descs;
  }

  ret->allocated_region = allocated_region;
  return ret;

#else /* !OFFLOAD_QUARANTINE */

  struct mrs_alloc_desc *ret = free_alloc_descs;

  /*
   * XXX this should work even with additional consumers, which we don't have
   * in practice. can move the if (ret == NULL) check out of the do-while.
   */
  do {
    if (ret == NULL) {
      mrs_debug_printf("alloc_alloc_desc: mapping new memory\n");
      struct mrs_alloc_desc *new_descs = (struct mrs_alloc_desc *)mmap(NULL, NEW_DESCRIPTOR_BATCH_SIZE * sizeof(struct mrs_alloc_desc), PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
      if (new_descs == MAP_FAILED) {
        return NULL;
      }
      for (int i = 0; i < NEW_DESCRIPTOR_BATCH_SIZE - 2; i++) {
        new_descs[i].next = &new_descs[i + 1];
      }
      ret = &new_descs[NEW_DESCRIPTOR_BATCH_SIZE - 1];

      struct mrs_alloc_desc *ins = free_alloc_descs;
      do {
        new_descs[NEW_DESCRIPTOR_BATCH_SIZE - 2].next = ins;
      } while (!atomic_compare_exchange_weak(&free_alloc_descs, &ins, new_descs));
      break;
    }
  } while (!atomic_compare_exchange_weak(&free_alloc_descs, &ret, ret->next));

  ret->allocated_region = allocated_region;
  return ret;

#endif /* OFFLOAD_QUARANTINE */
}

/* constructor and destructor */

__attribute__((constructor))
static void init(void) {
  real_malloc = dlsym(RTLD_NEXT, "malloc");
  real_free = dlsym(RTLD_NEXT, "free");
  real_calloc = dlsym(RTLD_NEXT, "calloc");
  real_realloc = dlsym(RTLD_NEXT, "realloc");
  real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
  real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");

#ifdef DEBUG
  initialize_lock(printf_lock);
#endif /* DEBUG */

#ifdef OFFLOAD_QUARANTINE
  initialize_lock(full_quarantine_lock);

  pthread_t thd;
  if (pthread_create(&thd, NULL, full_quarantine_offload, NULL)) {
    mrs_printf("pthread error\n");
    exit(7);
  }
#endif /* OFFLOAD_QUARANTINE */

  page_size = getpagesize();
  if ((page_size & (page_size - 1)) != 0) {
    mrs_printf("page_size not a power of 2\n");
    exit(7);
  }

  int res = caprevoke_shadow(CAPREVOKE_SHADOW_INFO_STRUCT, NULL, (void **)&cri);
  if (res != 0) {
    mrs_printf("error getting kernel caprevoke counters\n");
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

void *mrs_malloc(size_t size) {
#ifdef JUST_INTERPOSE
    return real_malloc(size);
#endif /* JUST_INTERPOSE */

  /*mrs_debug_printf("mrs_malloc: called\n");*/

  if (size == 0) {
    return NULL;
  }

  void *allocated_region;

  /*
   * ensure that all allocations less than the shadow bitmap granule size are
   * aligned to that granule size, so that no two allocations will be governed
   * by the same shadow bit. allocators may implement alignment incorrectly,
   * this doesn't allow UAF bugs but may cause faults.
   */
  if (size < CAPREVOKE_BITMAP_ALIGNMENT) {
    /* use posix_memalign because unlike aligned_alloc it does not require size to be an integer multiple of alignment */
    if (real_posix_memalign(&allocated_region, CAPREVOKE_BITMAP_ALIGNMENT, size)) {
      mrs_debug_printf("mrs_malloc: error aligning allocation of size less than the shadow bitmap granule\n");
      return NULL;
    }
  } else {
    /*
     * currently, sizeof(void *) == CAPREVOKE_BITMAP_ALIGNMENT == 16, which means
     * that if size >= CAPREVOKE_BITMAP_ALIGNMENT it should be aligned to a
     * multiple of CAPREVOKE_BITMAP_ALIGNMENT (because it is possible to store a
     * pointer in the allocation and thus the alignment is guaranteed by malloc).
     */
    allocated_region = real_malloc(size);
    if (allocated_region == NULL) {
      return allocated_region;
    }
  }

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
 * calloc is used to bootstrap various system libraries so is called before
 * even the constructor function of this library. before the initializer is
 * called and real_calloc is set appropriately, use this bootstrap function to
 * serve allocations.
 */
static void *mrs_calloc_bootstrap(size_t number, size_t size) {
  const size_t BOOTSTRAP_CALLOC_SIZE = 1024 * 1024 * 4;
  static char mem[BOOTSTRAP_CALLOC_SIZE] __attribute((aligned(16))) = {0};
  static size_t offset = 0;

  size_t old_offset = offset;
  offset += (number * size);
  if (offset > BOOTSTRAP_CALLOC_SIZE) {
    mrs_printf("mrs_calloc_bootstrap: ran out of memory\n");
    exit(7);
  }
  return &mem[old_offset];
}

void *mrs_calloc(size_t number, size_t size) {
#ifdef JUST_INTERPOSE
    return real_calloc(number, size);
#endif /* JUST_INTERPOSE */

  /*mrs_debug_printf("mrs_calloc: called\n");*/

  if (number == 0 || size == 0) {
    return NULL;
  }

  void *allocated_region;

  /*
   * ensure that all allocations less than the shadow bitmap granule size are
   * aligned to that granule size, so that no two allocations will be governed
   * by the same shadow bit. allocators may implement alignment incorrectly,
   * this doesn't allow UAF bugs but may cause faults.
   */
  if (size < CAPREVOKE_BITMAP_ALIGNMENT) {
    /* use posix_memalign because unlike aligned_alloc it does not require size to be an integer multiple of alignment */
    if (real_posix_memalign(&allocated_region, CAPREVOKE_BITMAP_ALIGNMENT, number * size)) {
      mrs_debug_printf("mrs_calloc: error aligning allocation of size less than the shadow bitmap granule\n");
      return NULL;
    }
    memset(allocated_region, 0, cheri_getlen(allocated_region));
  } else {
    /*
     * currently, sizeof(void *) == CAPREVOKE_BITMAP_ALIGNMENT == 16, which means
     * that if size >= CAPREVOKE_BITMAP_ALIGNMENT it should be aligned to a
     * multiple of CAPREVOKE_BITMAP_ALIGNMENT (because it is possible to store a
     * pointer in the allocation and thus the alignment is guaranteed by calloc).
     */
    allocated_region = real_calloc(number, size);
    if (allocated_region == NULL) {
      return allocated_region;
    }
  }

  allocated_size += size;
  if (allocated_size > max_allocated_size) {
    max_allocated_size = allocated_size;
  }

  /* this causes problems if our library is initizlied before the thread library */
  /*mrs_debug_printf("mrs_calloc: exit called %d size 0x%zx address %p\n", number, size, allocated_region);*/

  return allocated_region;
}

int mrs_posix_memalign(void **ptr, size_t alignment, size_t size) {
#ifdef JUST_INTERPOSE
    return real_posix_memalign(ptr, alignment, size);
#endif /* JUST_INTERPOSE */

  mrs_debug_printf("mrs_posix_memalign: called ptr %p alignment %zu size %zu\n", ptr, alignment, size);

  if (alignment < CAPREVOKE_BITMAP_ALIGNMENT) {
    alignment = CAPREVOKE_BITMAP_ALIGNMENT;
  }

  int ret = real_posix_memalign(ptr, alignment, size);
  if (ret != 0) {
    return ret;
  }

  allocated_size += size;
  if (allocated_size > max_allocated_size) {
    max_allocated_size = allocated_size;
  }

  return ret;
}

void *mrs_aligned_alloc(size_t alignment, size_t size) {
#ifdef JUST_INTERPOSE
    return real_aligned_alloc(alignment, size);
#endif /* JUST_INTERPOSE */

  mrs_debug_printf("mrs_aligned_alloc: called alignment %zu size %zu\n", alignment, size);

  if (alignment < CAPREVOKE_BITMAP_ALIGNMENT) {
    alignment = CAPREVOKE_BITMAP_ALIGNMENT;
  }

  void *ret = real_aligned_alloc(alignment, size);
  if (ret == NULL) {
   return ret;
  }

  allocated_size += size;
  if (allocated_size > max_allocated_size) {
    max_allocated_size = allocated_size;
  }

  return ret;
}

/*
 * replace realloc with a malloc and free to avoid dangling pointers in case of
 * in-place realloc that shrinks the buffer. if ptr is not a real allocation,
 * mrs_free() won't free it, but its buffer will still get copied into a new
 * allocation.
 */
void *mrs_realloc(void *ptr, size_t size) {

#ifdef JUST_INTERPOSE
    return real_realloc(ptr, size);
#endif /* JUST_INTERPOSE */

  size_t old_size = cheri_getlen(ptr);
  mrs_debug_printf("mrs_realloc: called ptr %p ptr size %zu new size %zu\n", ptr, old_size, size);

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
  memcpy(new_alloc, ptr, size < old_size ? size : old_size);
  mrs_free(ptr);
  return new_alloc;
}


/*
 * the raw version of bitmap painting is sufficient in the single-threaded and
 * multi-threaded-with-locks cases. however, in the lockless multithreaded
 * case, we need to atomically check that the capability has not already been
 * revoked as we paint the bitmap. if we didn't do this atomically, a
 * revocation pass might happen between when a thread checks that the
 * capability has not been revoked and when it paints the bitmap, which would
 * result in the bitmap being painted in an improper epoch.
 *
 * note that none of the SPEC benchmarks are multithreaded, and when we do
 * revocation offload only the offload thread actually paints the bitmap.
 *
 * even without this check in the lockless multithreaded case, the result of
 * the bitmap being painted in an improper epoch would be a fault rather than
 * heap objects aliasing, which is not so bad.
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
    /* this will be a revoked capability, which the allocator must accept */
    real_free(iter->allocated_region);
    prev = iter;
    iter = iter->next;
  }

  /* free the quarantined descriptors */

#ifndef OFFLOAD_QUARANTINE
  prev->next = free_alloc_descs;
  free_alloc_descs = full_quarantine;
#else /* !OFFLOAD_QUARANTINE */
  struct mrs_alloc_desc *flist_head = free_alloc_descs;
  do {
    prev->next = flist_head;
  } while (!atomic_compare_exchange_weak(&free_alloc_descs, &flist_head, full_quarantine));
#endif /* OFFLOAD_QUARANTINE */

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

  /*
   * short-circuit if ptr has been revoked. if multiple threads, this should be
   * checked atomically as the bitmap is painted.
   */
  if (ptr == NULL || caprevoke_is_revoked(ptr)) {
    return;
  }

#ifdef JUST_BOOKKEEPING
  real_free(ptr);
  return;
#endif /* JUST_BOOKKEEPING */

  /* TODO XXX
   * we can't trust the base and len that are provided by the caller here, we need to get the original allocation's
   * capability from the allocator (or know if there isn't one)
   */

#ifdef BYPASS_QUARANTINE
  /*
   * if this is a full-page(s) allocation, bypass the quarantine by
   * MADV_FREEing it and never actually freeing it back to the allocator.
   * because we don't know allocator internals, the allocated size must
   * actually be a multiple of the page size.
   *
   * we can't actually do this in the slimmed-down shim layer because we don't
   * have the vmmap-bearing capability. coalescing in quarntine is perhaps less
   * useful to the shim because we may not know about allocator metadata.
   */
  vaddr_t base = cheri_getbase(ptr);
  size_t region_size = cheri_getlen(ptr);
  if (((base & (page_size - 1)) == 0) &&
      ((region_size & (page_size - 1)) == 0)) {
    mrs_debug_printf("mrs_free: page-multiple free, bypassing quarantine\n");
    /*real_madvise(alloc_desc->vmmap_cap, region_size, MADV_FREE);*/
    return;
  }
#endif /* BYPASS_QUARANTINE */

  struct mrs_alloc_desc *alloc = alloc_alloc_desc(ptr);
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

#if !defined(QUARANTINE_RATIO)
#  define QUARANTINE_RATIO 4
#endif /* !QUARANTINE_RATIO */

  should_revoke = ((allocated_size >= MIN_REVOKE_HEAP_SIZE) && ((quarantine_size * QUARANTINE_RATIO) >= allocated_size));

#endif /* !QUARANTINE_HIGHWATER */

  if (should_revoke) {
    mrs_debug_printf("mrs_free: passed quarantine threshold, revoking: allocated size %zu quarantine size %zu\n", allocated_size, quarantine_size);

#ifdef OFFLOAD_QUARANTINE
    mrs_lock(&full_quarantine_lock);
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

    allocated_size -= quarantine_size;
    quarantine_size = 0;

#ifdef OFFLOAD_QUARANTINE
    if (pthread_cond_signal(&full_quarantine_ready)) {
        mrs_printf("pthread error\n");
        exit(7);
    }
    mrs_unlock(&full_quarantine_lock);
#else /* OFFLOAD_QUARANTINE */
    flush_full_quarantine();
#endif /* !OFFLOAD_QUARANTINE */
  }
}
