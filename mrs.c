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

#include "mrs.h"
#include "printf.h"

// use mrs on a cheri-enabled system to make a legacy memory allocator that has
// been ported to purecap (1) immune to use-after-reallocation vulnerabilities
// (2) immune to vulnerabilities related to double free, incorrect (arbitrary)
// free, and exposure of allocator metadata. the allocator will already be
// spatially safe by virtue of running purecap.

// mrs can be built as a standalone shared library (#define STANDALONE) for use
// with LD_PRELOAD over an existing allocator - in this case it exports the
// malloc, free, and mmap symbols, and it gets the real ones from dlsym.

// mrs can also be linked into an existing cherified malloc implmenetaion
// (#define MALLOC_PREFIX <prefix>), in which case it exports only the malloc
// and free symbols. the malloc implementation should be modified to use
// mrs_mmap instead of mmap, and its malloc and free functions should be
// prefixed with the defined malloc prefix (e.g. <prefix>_malloc) for mrs to
// consume.

// TODO mrs may also export library functions that can be used to convert a
// cherified malloc into one that is temporally safe without paying the
// performance costs of a shim layer.

/*
 * Knobs:
 *
 * STANDALONE: build mrs as a standalone shared library
 * MALLOC_PREFIX: build mrs linked into an existing malloc
 * QUARANTINE_HIGHWATER: the quarantine size in bytes at which to carry out revocation
 * CONCURRENT: include locks to make mrs thread safe
 * DEBUG: print debug statements
 * OFFLOAD_QUARANTINE: process the quarantine in a separate detached thread
 *
 */

#define concat_resolved(a, b) a ## b
#define concat(a, b) concat_resolved(a,b) // need a function without ## so args will be resolved

#ifdef MALLOC_PREFIX
void *concat(MALLOC_PREFIX,_malloc)(size_t size);
void concat(MALLOC_PREFIX,_free)(void *ptr);
void *concat(MALLOC_PREFIX,_calloc)(size_t, size_t);
void *concat(MALLOC_PREFIX,_realloc)(void *, size_t);
int concat(MALLOC_PREFIX,_posix_memalign)(void **, size_t, size_t);
void *concat(MALLOC_PREFIX,_aligned_alloc)(size_t, size_t);
#endif /* MALLOC_PREFIX */

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

#ifndef QUARANTINE_HIGHWATER
#define QUARANTINE_HIGHWATER (1024L * 1024 * 2)
#endif /* !QUARANTINE_HIGHWATER */

/* printf debugging */

// TODO multicore add lock
#define DEBUG 1

#ifdef DEBUG
void _putchar(char character) {
  write(2, &character, sizeof(char));
}
#endif /* DEBUG */

#define mrs_debug_printf(fmt, ...) \
  do {if (DEBUG) printf(("mrs: " fmt), ##__VA_ARGS__); } while (0)

#define mrs_debug_printcap(name, cap) \
  mrs_debug_printf("capability %s: v:%u s:%u p:%08lx b:%016lx l:%016lx, o:%lx t:%ld\n", (name), cheri_gettag((cap)), cheri_getsealed((cap)), cheri_getperm((cap)), cheri_getbase((cap)), cheri_getlen((cap)), cheri_getoffset((cap)), cheri_gettype((cap)))

/* cheri c utilities */

#define cheri_testsubset(x, y) __builtin_cheri_subset_test((x), (y))

/* locking */

#ifdef CONCURRENT

pthread_mutex_t giant_lock;
// hack to initialize mutexes without calling malloc
int _pthread_mutex_init_calloc_cb(pthread_mutex_t *mutex, void *(calloc_cb)(size_t, size_t));
char giant_lock_buf[4096]; //XXX at least sizeof(struct pthread_mutex) from thr_mutex.c
void *get_giant_lock_storage() {
  return giant_lock_buf;
}
#define mrs_lock(mtx) pthread_mutex_lock((mtx))
#define mrs_unlock(mtx) pthread_mutex_unlock((mtx))

#else /* !CONCURRENT */

#define mrs_lock(mtx)
#define mrs_unlock(mtx)

#endif /* CONCURRENT */

/* globals */

struct mrs_params {
  struct mrs_shadow_desc *shadow_spaces;
  RB_HEAD(mrs_alloc_desc_head, mrs_alloc_desc) allocations;
  struct mrs_alloc_desc *quarantine;
  long quarantine_size;
  bool initialized;
  void* (*real_mmap) (void*, size_t, int, int, int, off_t);
  void* (*real_malloc) (size_t);
  void (*real_free) (void*);
  /*void* (*real_calloc) (size_t, size_t);*/
  /*void* (*real_realloc) (void *, size_t);*/
  /*int (*real_posix_memalign) (void **, size_t, size_t);*/
  /*void* (*real_aligned_alloc) (size_t, size_t);*/
};

static struct mrs_params params = {0};// {0, {0}, 0, 0, 1, mmap, je_malloc, je_free};

__attribute__((constructor))
static inline void init() {
  mrs_debug_printf("init: enter\n");
  // TODO atomic or investigate library init function
  if (!params.initialized) {

#ifdef CONCURRENT
  _pthread_mutex_init_calloc_cb(&giant_lock, get_giant_lock_storage); // if we don't init this way, the pthread functions will call malloc
#endif /* CONCURRENT */

#if defined(STANDALONE)
    params.real_malloc = dlsym(RTLD_NEXT, "malloc");
    params.real_free = dlsym(RTLD_NEXT, "free");
    params.real_mmap = dlsym(RTLD_NEXT, "mmap");
    /*params.real_calloc = dlsym(RTLD_NEXT, "calloc");*/
    /*params.real_realloc = dlsym(RTLD_NEXT, "realloc");*/
    /*params.real_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");*/
    /*params.real_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");*/
#elif defined(MALLOC_PREFIX)
    params.real_malloc = concat(MALLOC_PREFIX, _malloc);
    params.real_free = concat(MALLOC_PREFIX, _free);
    params.real_mmap = mmap;
    /*params.real_calloc = concat(MALLOC_PREFIX, _calloc);*/
    /*params.real_realloc = concat(MALLOC_PREFIX, _realloc);*/
    /*params.real_posix_memalign = concat(MALLOC_PREFIX, _posix_memalign);*/
    /*params.real_aligned_alloc = concat(MALLOC_PREFIX, _aligned_alloc);*/
#else
#error must build mrs with either STANDALONE or MALLOC_PREFIX defined
#endif
    params.initialized = true;
  }
  mrs_debug_printf("init: exit\n");
}

// ---------------------------------- MMAP -> SHADOW SPACE MAPPING
// TODO support removal and free list of descriptors, use better data
// structures; this wants a red-black tree with coalescing (on insertion) and
// splitting (on removal), but how can we do this nicely with capabilities?
// XXX we may not actually need to handle coalescing or splitting, since
// CHERIfied allocators won't allocate across mmap boundaries (and may not
// munmap sub-regions)

struct mrs_shadow_desc {
  struct mrs_shadow_desc *next;
  void *mapped;
  void *shadow;
  // TODO count number of corresponding allocs to validate munmap
};

static const int NUM_SHADOW_DESCS = 1000;
static int shadow_desc_index = 0;
static struct mrs_shadow_desc shadow_descs[NUM_SHADOW_DESCS];


static int insert_shadow_desc(void *mapped, void *shadow) {

  if (shadow_desc_index == NUM_SHADOW_DESCS) {
    mrs_debug_printf("insert_shadow_desc: maximum number of shadow_descs exceeded\n");
    return -1;
  }

  struct mrs_shadow_desc *ins = &shadow_descs[shadow_desc_index];
  shadow_desc_index++;

  ins->next = NULL;
  ins->mapped = mapped;
  ins->shadow = shadow;

  if (params.shadow_spaces == NULL) {
    params.shadow_spaces = ins;
  } else {
    struct mrs_shadow_desc *iter = params.shadow_spaces;
    if (cheri_getbase(ins->mapped) < cheri_getbase(iter->mapped)) {
      ins->next = iter;
      params.shadow_spaces = ins;
    } else while ((iter->next != NULL) && (cheri_getbase(ins->mapped) > cheri_getbase(iter->next->mapped))) {
      iter = iter->next;
    }
    ins->next = iter->next;
    iter->next = ins;
  }

  return 0;
}

/**
 * Given a capability returned by malloc, return the shadow descriptor for its
 * corresponding shadow space.
 **/
static void *lookup_shadow_desc(void *alloc) {
  struct mrs_shadow_desc *iter = params.shadow_spaces;
  while (iter != NULL) {
    if (cheri_testsubset(iter->mapped, alloc)) {
      return iter;
    }
    iter = iter->next;
  }
  return NULL;
}

// ---------------------------------- END MMAP -> SHADOW SPACE MAPPING

// ------------------- ALLOCATED REGIONS 
// TODO support free list of descriptors

struct mrs_alloc_desc {
  void *alloc;
  struct mrs_shadow_desc *shadow_desc;
  struct mrs_alloc_desc *qnext;
  RB_ENTRY(mrs_alloc_desc) linkage;
};

static vaddr_t mrs_alloc_desc_cmp(struct mrs_alloc_desc *e1, struct mrs_alloc_desc *e2) {
  return cheri_getbase(e1->alloc) - cheri_getbase(e2->alloc);
}

RB_PROTOTYPE(mrs_alloc_desc_head, mrs_alloc_desc, linkage, mrs_alloc_desc_cmp);
RB_GENERATE(mrs_alloc_desc_head, mrs_alloc_desc, linkage, mrs_alloc_desc_cmp);

static const int NUM_ALLOC_DESCS = 1000;
static int alloc_desc_index = 0;
static struct mrs_alloc_desc alloc_descs[NUM_ALLOC_DESCS];


static int insert_alloc_desc(void *alloc, struct mrs_shadow_desc *shadow_desc) {
  if (alloc_desc_index == NUM_ALLOC_DESCS) {
    mrs_debug_printf("insert_alloc_desc: maximum number of alloc_descs exceeded\n");
    return -1;
  }

  struct mrs_alloc_desc *ins = &alloc_descs[alloc_desc_index];
  alloc_desc_index++;
  ins->alloc = alloc;
  ins->shadow_desc = shadow_desc;

  if (RB_INSERT(mrs_alloc_desc_head, &params.allocations, ins)) {
    mrs_debug_printf("insert_alloc_desc: duplicate insert\n");
    return -1;
  }

  return 0;
}

static struct mrs_alloc_desc *lookup_alloc_desc(void *alloc) {
  struct mrs_alloc_desc lookup = {0};
  lookup.alloc = alloc;
  struct mrs_alloc_desc *ret = RB_FIND(mrs_alloc_desc_head, &params.allocations, &lookup);
  return ret;
}

// ------------------- END ALLOCATED REGIONS

void *mrs_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  /*init_params();*/

  mrs_debug_printf("mrs_mmap: called with addr %p len 0x%zx prot 0x%x flags 0x%x fd %d offset 0x%zx\n", addr, len, prot, flags, fd, offset);

  void *mb = params.real_mmap(addr, len, prot, flags, fd, offset);

  mrs_lock(&giant_lock);
  if (mb ==  MAP_FAILED) {
    mrs_debug_printf("mrs_mmap: error in mmap errno %d\n", errno);
    mrs_unlock(&giant_lock);
    return MAP_FAILED;
  }

  void *sh;
  if (caprevoke_shadow(CAPREVOKE_SHADOW_NOVMMAP, mb, &sh)) {
    mrs_debug_printf("mrs_mmap: error in caprevoke_shadow errno %d\n", errno);
    mrs_unlock(&giant_lock);
    return MAP_FAILED;
  }

  if (insert_shadow_desc(mb, sh)) {
    mrs_debug_printf("mrs_mmap: recording newly mapped region\n");
    mrs_unlock(&giant_lock);
    return MAP_FAILED;
  }

  mrs_unlock(&giant_lock);
  /*mrs_debug_printf("mrs_mmap: mmap returned %p caprevoke_shadow returned %p\n", mb, sh);*/

  return mb;
}

// TODO munmap madvise etc

/* TODO after revocation, we want to make sure there are no tags in the freed memory before it's given back to the application. zero things out. */
void *mrs_malloc(size_t size) {
  /*init_params();*/

  /*mrs_debug_printf("mrs_malloc: enter\n");*/

  void *alloc = params.real_malloc(size);

  /* TODO
   *
   * - validate size returned from real malloc
   * - sanitize/validate capabilities passed to consumer (check permissions incl. VMMAP, check bounds are not too large)
   *
   */

  mrs_lock(&giant_lock);
  void *sh = lookup_shadow_desc(alloc);
  if (sh == NULL) {
    mrs_debug_printf("\nmrs_malloc: looking up shadow space failed\n");
    params.real_free(alloc);
    mrs_unlock(&giant_lock);
    return NULL;
  }

  if (insert_alloc_desc(alloc, sh)) {
    mrs_debug_printf("\nmrs_malloc: inserting alloc descriptor failed\n");
    params.real_free(alloc);
    mrs_unlock(&giant_lock);
    return NULL;
  }
  mrs_unlock(&giant_lock);

  mrs_debug_printf("mrs_malloc: called size 0x%zx address %p\n", size, alloc);

  return alloc;
}

void *mrs_flush_quarantine(void *quarantine) {
  struct mrs_alloc_desc *iter = (struct mrs_alloc_desc *)quarantine;
  while (iter != NULL) {
    // TODO use raw version when available
    caprev_shadow_nomap_set(iter->shadow_desc->shadow, iter->alloc, iter->alloc);
    iter = iter->qnext;
  }

  // TODO fix
  struct caprevoke_stats crst;
  uint64_t oepoch;
  caprevoke(CAPREVOKE_JUST_THE_TIME, 0, &crst);
  oepoch = crst.epoch;
  caprevoke(CAPREVOKE_LAST_PASS, oepoch, &crst);

  iter = (struct mrs_alloc_desc *)quarantine;
  while (iter != NULL) {
    caprev_shadow_nomap_clear(iter->shadow_desc->shadow, iter->alloc);
    // XXX once revoker runs the tag will be cleared
    params.real_free(iter->alloc);
    iter = iter->qnext;
  }


  return NULL;
}

/* TODO if a full page is freed, we may want to do munmap or mprotect (or
 * special MPROT_QUARANTINE later). we also want to coalesce in quarantine and
 * measure the quarantine size by number of physical pages occupied .*/
/* TODO atexit how many things are not freed? */
void mrs_free(void *ptr) {
  /*init_params();*/

  mrs_debug_printf("mrs_free: called address %p\n", ptr);

  if (ptr == NULL) {
    return;
  }


  mrs_lock(&giant_lock);
  struct mrs_alloc_desc *alloc_desc = lookup_alloc_desc(ptr);

  if (alloc_desc == NULL) {
    mrs_debug_printf("mrs_free: freed base address not allocated\n");
    mrs_unlock(&giant_lock);
    exit(7);
  }

  if (cheri_getlen(ptr)!= cheri_getlen(alloc_desc->alloc)) {
    mrs_debug_printf("mrs_free: freed base address size mismatch cap len 0x%zx alloc size 0x%zx\n", cheri_getlen(ptr), cheri_getlen(alloc_desc->alloc));
    mrs_unlock(&giant_lock);
    exit(7);
  }

  /* TODO
   *
   * - better validation
   * - add it to the quarantine list, use data structures to set appropriate shadow bitmap
   * - free descriptor
   * - if quarantine full, run revoker and free memory
   *
   */

  RB_REMOVE(mrs_alloc_desc_head, &params.allocations, alloc_desc);
  alloc_desc->qnext = params.quarantine;
  params.quarantine = alloc_desc;
  params.quarantine_size += cheri_getlen(alloc_desc->alloc);

  if (params.quarantine_size >= QUARANTINE_HIGHWATER) {
    mrs_debug_printf("mrs_free: passed quarantine highwater of %lu, revoking\n", QUARANTINE_HIGHWATER);

#ifdef OFFLOAD_QUARANTINE
    pthread_t thd;
    pthread_create(&thd, NULL, mrs_flush_quarantine, params.quarantine);
    pthread_detach(thd);
#else /* !OFFLOAD_QUARANTINE */
    mrs_flush_quarantine(params.quarantine);
#endif /* OFFLOAD_QUARANTINE */
    params.quarantine = NULL;
    params.quarantine_size = 0;
  }
  mrs_unlock(&giant_lock);
}
