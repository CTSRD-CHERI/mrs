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
 * MALLOC_PREFIX: build mrs linked into an existing malloc
 * QUARANTINE_HIGHWATER: the quarantine size in bytes at which to carry out revocation (default 2MB)
 * OFFLOAD_QUARANTINE: process full quarantines in a separate detached thread
 * SANITIZE: perform malloc sanitization on mrs function calls
 * DEBUG: print debug statements
 * NUM_SHADOW_DESCS: number of descriptors for shadow space capabilities (default 10_000)
 * NUM_ALLOC_DESCS: number of descriptors for outstanding allocations (default 1_000_000)
 *
 * TODO knobs for ablation study
 * TODO knob for zeroing/tag clearing on malloc
 * TODO knob for halting on guarantee violation rather than continuing
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
 * are outstanding. these checks could also 
 */

#define concat_resolved(a, b) a ## b
/* need a function without ## so args will be resolved */
#define concat(a, b) concat_resolved(a,b)

#define cheri_testsubset(x, y) __builtin_cheri_subset_test((x), (y))

#ifndef QUARANTINE_HIGHWATER
#define QUARANTINE_HIGHWATER (1024L * 1024 * 2)
#endif /* !QUARANTINE_HIGHWATER */

#ifndef NUM_SHADOW_DESCS
#define NUM_SHADOW_DESCS 10000
#endif /* !NUM_SHADOW_DESCS */

#ifndef NUM_ALLOC_DESCS
#define NUM_ALLOC_DESCS 1000000
#endif /* !NUM_ALLOC_DESCS */

void *malloc(size_t size) {
  return mrs_malloc(size);
}
void free(void *ptr) {
  return mrs_free(ptr);
}
/*void *calloc(size_t, size_t) {}*/
/*void *realloc(void *, size_t) {}*/
/*int posix_memalign(void **, size_t, size_t c) {}*/
/*void *aligned_alloc(size_t, size_t) {}*/
#ifdef STANDALONE
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  return mrs_mmap(addr, len, prot, flags, fd, offset);
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

/* store mapping between mmaped region and shadow space */
struct mrs_shadow_desc {
  void *mmap_region;
  void *shadow;
#ifdef SANITIZE
  int allocations;
#endif /* SANITIZE */
  struct mrs_shadow_desc *next;
  RB_ENTRY(mrs_shadow_desc) linkage;
};

/* store mapping between allocated region and mmaped region/shadow space */
struct mrs_alloc_desc {
  void *allocated_region;
  void *vmmap_cap; /* copy of allocated_region capability with VMMAP permission so it doesn't get revoked, for freeing back to allocator */
  void *shadow; /* local copy of shadow capability to avoid locking global shadow_spaces when !SANITIZE */
  struct mrs_shadow_desc *shadow_desc;
  struct mrs_alloc_desc *next;
  RB_ENTRY(mrs_alloc_desc) linkage;
};

static struct mrs_shadow_desc shadow_descs[NUM_SHADOW_DESCS];
static atomic_int shadow_descs_index;
static RB_HEAD(mrs_shadow_desc_head, mrs_shadow_desc) shadow_spaces;
static struct mrs_shadow_desc *free_shadow_descs;

static struct mrs_alloc_desc alloc_descs[NUM_ALLOC_DESCS];
static atomic_int alloc_descs_index;
static RB_HEAD(mrs_alloc_desc_head, mrs_alloc_desc) allocations;
static struct mrs_alloc_desc *free_alloc_descs;

static struct mrs_alloc_desc *quarantine;
static long quarantine_size;
static struct mrs_alloc_desc *full_quarantine;

static void* (*real_mmap) (void*, size_t, int, int, int, off_t);
static void* (*real_malloc) (size_t);
static void (*real_free) (void*);
/*static void* (*real_calloc) (size_t, size_t);*/
/*static void* (*real_realloc) (void *, size_t);*/
/*static int (*real_posix_memalign) (void **, size_t, size_t);*/
/*static void* (*real_aligned_alloc) (size_t, size_t);*/

/* locking */

/*
 * hack to initialize mutexes without calling malloc. the buf size should be at
 * least sizeof(struct pthread_mutex) from thr_private.h
 */
int _pthread_mutex_init_calloc_cb(pthread_mutex_t *mutex, void *(calloc_cb)(size_t, size_t));
#define create_lock(name) \
  pthread_mutex_t name; \
  char name ## _buf[256]; \
  void *name ## _storage() { \
    return name ## _buf; \
  }

create_lock(debug_lock);
create_lock(shadow_spaces_lock);
create_lock(free_shadow_descs_lock);
create_lock(allocations_lock);
create_lock(free_alloc_descs_lock);
create_lock(quarantine_lock);
create_lock(full_quarantine_lock);

#ifdef OFFLOAD_QUARANTINE
static void *full_quarantine_offload(void *);
/* shouldn't need hack because condition variables are not used in mrs_malloc() */
pthread_cond_t full_quarantine_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t full_quarantine_ready = PTHREAD_COND_INITIALIZER;
/* however, we need to JIT spawn the thread because spawning it from init() causes main() not to be executed */
bool offload_thread_spawned;
#endif /* OFFLOAD_QUARANTINE */

#define mrs_lock(mtx) do {if (pthread_mutex_lock((mtx))) {printf("pthread error\n");exit(7);}} while (0)
#define mrs_unlock(mtx) do {if (pthread_mutex_unlock((mtx))) {printf("pthread error\n");exit(7);}} while (0)

/* printf debugging */

void _putchar(char character) {
  write(2, &character, sizeof(char));
}

#ifdef DEBUG

#define mrs_debug_printf(fmt, ...) \
  do {mrs_lock(&debug_lock); printf(("mrs: " fmt), ##__VA_ARGS__); mrs_unlock(&debug_lock);} while (0)

#define mrs_debug_printcap(name, cap) \
  mrs_debug_printf("capability %s: v:%u s:%u p:%08lx b:%016lx l:%016lx, o:%lx t:%ld\n", (name), cheri_gettag((cap)), cheri_getsealed((cap)), cheri_getperm((cap)), cheri_getbase((cap)), cheri_getlen((cap)), cheri_getoffset((cap)), cheri_gettype((cap)))

#else /* DEBUG */

#define mrs_debug_printf(fmt, ...)
#define mrs_debug_printcap(name, cap)

#endif /* !DEBUG */

/* shadow_desc utilities */

struct mrs_shadow_desc *alloc_shadow_desc(void *mmap_region, void *shadow) {
  struct mrs_shadow_desc *ret;

  /* allocate from store until it is empty, then use free list */
  if (shadow_descs_index < NUM_SHADOW_DESCS) {
    int idx = atomic_fetch_add_explicit(&shadow_descs_index, 1, memory_order_relaxed);
    if (idx < NUM_SHADOW_DESCS) {
      ret = &shadow_descs[idx];
      ret->mmap_region = mmap_region;
      ret->shadow = shadow;
      return ret;
    }
  }

  mrs_lock(&free_shadow_descs_lock);
  if (free_shadow_descs != NULL) {
    ret = free_shadow_descs;
    free_shadow_descs = free_shadow_descs->next;
  } else {
    mrs_unlock(&free_shadow_descs_lock);
    return NULL;
  }
  mrs_unlock(&free_shadow_descs_lock);

  ret->mmap_region = mmap_region;
  ret->shadow = shadow;
  return ret;
}

// TODO free_shadow_desc

static vaddr_t mrs_shadow_desc_cmp(struct mrs_shadow_desc *e1, struct mrs_shadow_desc *e2) {
  return cheri_getbase(e1->mmap_region) - cheri_getbase(e2->mmap_region);
}

RB_PROTOTYPE_STATIC(mrs_shadow_desc_head, mrs_shadow_desc, linkage, mrs_shadow_desc_cmp);
RB_GENERATE_STATIC(mrs_shadow_desc_head, mrs_shadow_desc, linkage, mrs_shadow_desc_cmp);

static struct mrs_shadow_desc *add_shadow_desc(struct mrs_shadow_desc *add) {
  return RB_INSERT(mrs_shadow_desc_head, &shadow_spaces, add);
}

static struct mrs_shadow_desc *remove_shadow_desc(struct mrs_shadow_desc *rem) {
  return RB_REMOVE(mrs_shadow_desc_head, &shadow_spaces, rem);
}

static struct mrs_shadow_desc *lookup_shadow_desc_by_mmap(void *mmap_region) {
  struct mrs_shadow_desc lookup = {0};
  lookup.mmap_region = mmap_region;
  return RB_FIND(mrs_shadow_desc_head, &shadow_spaces, &lookup);
}

static struct mrs_shadow_desc *lookup_shadow_desc_by_allocation(void *allocated_region) {
  struct mrs_shadow_desc *iter = RB_ROOT(&shadow_spaces);
  while (iter) {
    if (cheri_getbase(allocated_region) < cheri_getbase(iter->mmap_region)) {
      iter = RB_LEFT(iter, linkage);
    } else if (cheri_testsubset(iter->mmap_region, allocated_region)) {
      return iter;
    } else {
      iter = RB_RIGHT(iter, linkage);
    }
  }
  return NULL;
}

/* alloc_desc utilities */

/* there is no free_alloc_desc because descriptors are batch-freed when the quarantine is flushed */
struct mrs_alloc_desc *alloc_alloc_desc(void *allocated_region, struct mrs_shadow_desc *shadow_desc) {
  struct mrs_alloc_desc *ret;

  /* allocate from store until it is empty, then use free list */
  if (alloc_descs_index < NUM_ALLOC_DESCS) {
    int idx = atomic_fetch_add_explicit(&alloc_descs_index, 1, memory_order_relaxed);
    if (idx < NUM_ALLOC_DESCS) {
      ret = &alloc_descs[idx];
      ret->allocated_region = allocated_region;
      ret->shadow = shadow_desc->shadow;
      ret->shadow_desc = shadow_desc;
      return ret;
    }
  }

  mrs_lock(&free_alloc_descs_lock);
  if (free_alloc_descs != NULL) {
    ret = free_alloc_descs;
    free_alloc_descs = free_alloc_descs->next;
  } else {
    mrs_unlock(&free_alloc_descs_lock);
    return NULL;
  }
  mrs_unlock(&free_alloc_descs_lock);

  ret->allocated_region = allocated_region;
  /* derive cap to allocated_region with VMMAP set */
  // TODO representability?
  void *offset = cheri_setoffset(shadow_desc->mmap_region, cheri_getbase(allocated_region) - cheri_getbase(shadow_desc->mmap_region));
  ret->vmmap_cap = cheri_csetbounds(offset, cheri_getlen(allocated_region));
  ret->shadow = shadow_desc->shadow;
  ret->shadow_desc = shadow_desc;
  return ret;
}

static vaddr_t mrs_alloc_desc_cmp(struct mrs_alloc_desc *e1, struct mrs_alloc_desc *e2) {
  return cheri_getbase(e1->allocated_region) - cheri_getbase(e2->allocated_region);
}

RB_PROTOTYPE_STATIC(mrs_alloc_desc_head, mrs_alloc_desc, linkage, mrs_alloc_desc_cmp);
RB_GENERATE_STATIC(mrs_alloc_desc_head, mrs_alloc_desc, linkage, mrs_alloc_desc_cmp);

static struct mrs_alloc_desc *add_alloc_desc(struct mrs_alloc_desc *add) {
  return RB_INSERT(mrs_alloc_desc_head, &allocations, add);
}

static struct mrs_alloc_desc *remove_alloc_desc(struct mrs_alloc_desc *rem) {
  return RB_REMOVE(mrs_alloc_desc_head, &allocations, rem);
}

static struct mrs_alloc_desc *lookup_alloc_desc(void *alloc) {
  struct mrs_alloc_desc lookup = {0};
  lookup.allocated_region = alloc;
  return  RB_FIND(mrs_alloc_desc_head, &allocations, &lookup);
}

/* initialization */

__attribute__((constructor))
static inline void init() {
/* hack to initialize mutexes without calling malloc */
#define initialize_lock(name) \
  _pthread_mutex_init_calloc_cb(&name, name ## _storage)

initialize_lock(debug_lock);
initialize_lock(shadow_spaces_lock);
initialize_lock(free_shadow_descs_lock);
initialize_lock(allocations_lock);
initialize_lock(free_alloc_descs_lock);
initialize_lock(quarantine_lock);
initialize_lock(full_quarantine_lock);

#if defined(STANDALONE)
  real_malloc = dlsym(RTLD_NEXT, "malloc");
  real_free = dlsym(RTLD_NEXT, "free");
  real_mmap = dlsym(RTLD_NEXT, "mmap");
  /*real_calloc = dlsym(RTLD_NEXT, "calloc");*/
  /*real_realloc = dlsym(RTLD_NEXT, "realloc");*/
  /*real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");*/
  /*real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");*/
#elif defined(MALLOC_PREFIX)
  real_malloc = concat(MALLOC_PREFIX, _malloc);
  real_free = concat(MALLOC_PREFIX, _free);
  real_mmap = mmap;
  /*real_calloc = concat(MALLOC_PREFIX, _calloc);*/
  /*real_realloc = concat(MALLOC_PREFIX, _realloc);*/
  /*real_posix_memalign = concat(MALLOC_PREFIX, _posix_memalign);*/
  /*real_aligned_alloc = concat(MALLOC_PREFIX, _aligned_alloc);*/
#else
#error must build mrs with either STANDALONE or MALLOC_PREFIX defined
#endif

  mrs_debug_printf("init: complete\n");
}

/* mrs functions */

void *mrs_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  mrs_debug_printf("mrs_mmap: called with addr %p len 0x%zx prot 0x%x flags 0x%x fd %d offset 0x%zx\n", addr, len, prot, flags, fd, offset);

  void *mmap_region = real_mmap(addr, len, prot, flags, fd, offset);
  if (mmap_region == MAP_FAILED) {
    mrs_debug_printf("mrs_mmap: error in mmap errno %d\n", errno);
    return MAP_FAILED;
  }

  void *shadow;
  if (caprevoke_shadow(CAPREVOKE_SHADOW_NOVMMAP, mmap_region, &shadow)) {
    mrs_debug_printf("mrs_mmap: error in caprevoke_shadow errno %d\n", errno);
    return MAP_FAILED;
  }

  struct mrs_shadow_desc *add = alloc_shadow_desc(mmap_region, shadow);
  if (add == NULL) {
    // TODO real munmap
    mrs_debug_printf("mrs_mmap: error allocating shadow descriptor\n");
    return MAP_FAILED;
  }

  mrs_lock(&shadow_spaces_lock);
  if (add_shadow_desc(add)) {
    mrs_unlock(&shadow_spaces_lock);
    // TODO real munmap
    mrs_debug_printf("mrs_mmap: error inserting shadow descriptor\n");
    return MAP_FAILED;
  }
  mrs_unlock(&shadow_spaces_lock);

  /*mrs_debug_printf("mrs_mmap: mmap returned %p caprevoke_shadow returned %p\n", mb, sh);*/
  return mmap_region;
}

// TODO munmap madvise etc

void *mrs_malloc(size_t size) {

  /*mrs_debug_printf("mrs_malloc: enter\n");*/

  void *allocated_region = real_malloc(size);

  /*
   * find the shadow space corresponding to the allocated region
   * and create a descriptor for it.
   */
  mrs_lock(&shadow_spaces_lock);
  void *shadow_desc = lookup_shadow_desc_by_allocation(allocated_region);
  if (shadow_desc == NULL) {
    mrs_unlock(&shadow_spaces_lock);
    mrs_debug_printf("mrs_malloc: looking up shadow space failed\n");
    real_free(allocated_region);
    return NULL;
  }

  struct mrs_alloc_desc *ins = alloc_alloc_desc(allocated_region, shadow_desc);
  if (ins == NULL) {
    mrs_unlock(&shadow_spaces_lock);
    mrs_debug_printf("mrs_malloc: ran out of allocation descriptors\n");
    real_free(allocated_region);
    return NULL;
  }

#ifdef SANITIZE
  shadow_desc->allocations++;
#endif /* SANITIZE */
  mrs_unlock(&shadow_spaces_lock);

  /* add the descriptor to our red-black tree */
  mrs_lock(&allocations_lock);
  if (add_alloc_desc(ins)) {
    mrs_unlock(&allocations_lock);
    mrs_debug_printf("mrs_malloc: duplicate allocation\n");
    real_free(allocated_region);
    return NULL;
  }
  mrs_unlock(&allocations_lock);

  mrs_debug_printf("mrs_malloc: called size 0x%zx address %p\n", size, allocated_region);

  return allocated_region;
}

/*
 * currently, we can use the raw version of bitmap painting functions because we have data
 * structure synchronization that prevents double-frees and only one thread will be painting
 * the bitmap at once (ensured by the full_quarantine_lock). if we switch to full multicore,
 * with each core painting concurrently, we wil need to use (at least part of) the non-raw
 * functions. we will also need to use different caprevoke() calls.
 */
void flush_full_quarantine() {
  struct mrs_alloc_desc *iter = full_quarantine;
  while (iter != NULL) {
    caprev_shadow_nomap_set(iter->shadow, iter->allocated_region, iter->allocated_region);
    iter = iter->next;
  }

  struct caprevoke_stats crst;
  caprevoke(CAPREVOKE_LAST_PASS|CAPREVOKE_IGNORE_START, 0, &crst);

  struct mrs_alloc_desc *prev;
  iter = full_quarantine;
  while (iter != NULL) {
    caprev_shadow_nomap_clear(iter->shadow, iter->allocated_region);
    real_free(iter->vmmap_cap);
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
        mrs_debug_printf("pthread error\n");
        exit(7);
      }
    }
    mrs_debug_printf("full_quarantine_offload: full_quarantine ready\n");
    flush_full_quarantine();
    if (pthread_cond_signal(&full_quarantine_empty)) {
        mrs_debug_printf("pthread error\n");
        exit(7);
    }
    mrs_unlock(&full_quarantine_lock);
  }
  return NULL;
}
#endif /* OFFLOAD_QUARANTINE */

void mrs_free(void *ptr) {

  mrs_debug_printf("mrs_free: called address %p\n", ptr);

  if (ptr == NULL) {
    return;
  }

  /* find, validate, and remove the allocation descriptor */
  mrs_lock(&allocations_lock);
  struct mrs_alloc_desc *alloc_desc = lookup_alloc_desc(ptr);
  if (alloc_desc == NULL) {
    mrs_debug_printf("mrs_free: freed base address not allocated\n");
    mrs_unlock(&allocations_lock);
    return;
  }

#ifdef SANITIZE
  if (cheri_getlen(ptr)!= cheri_getlen(alloc_desc->allocated_region)) {
    mrs_debug_printf("mrs_free: freed base address size mismatch cap len 0x%zx alloc size 0x%zx\n", cheri_getlen(ptr), cheri_getlen(alloc_desc->allocated_region));
    mrs_unlock(&allocations_lock);
    return;
  }
#endif /* SANITIZE */

  RB_REMOVE(mrs_alloc_desc_head, &allocations, alloc_desc);
  if (remove_alloc_desc(alloc_desc) == NULL) {
    mrs_debug_printf("mrs_free: could not remove alloc descriptor\n");
    mrs_unlock(&allocations_lock);
    return;
  }
  mrs_unlock(&allocations_lock);

  /* add the allocation descriptor to quarantine */
  mrs_lock(&quarantine_lock);
  alloc_desc->next = quarantine;
  quarantine = alloc_desc;
  quarantine_size += cheri_getlen(alloc_desc->allocated_region);

  if (quarantine_size >= QUARANTINE_HIGHWATER) {
    mrs_debug_printf("mrs_free: passed quarantine highwater of %lu, revoking\n", QUARANTINE_HIGHWATER);

    mrs_lock(&full_quarantine_lock);
#ifdef OFFLOAD_QUARANTINE
    while (full_quarantine != NULL) {
      mrs_debug_printf("mrs_free: waiting for full_quarantine to drain\n");
      if (pthread_cond_wait(&full_quarantine_empty, &full_quarantine_lock)) {
        mrs_debug_printf("pthread error\n");
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
    if (!offload_thread_spawned) {
      pthread_t thd;
      if (pthread_create(&thd, NULL, full_quarantine_offload, NULL)) {
        mrs_debug_printf("pthread error\n");
        exit(7);
      }
      offload_thread_spawned = true;
    }
    if (pthread_cond_signal(&full_quarantine_ready)) {
        mrs_debug_printf("pthread error\n");
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
