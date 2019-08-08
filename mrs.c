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

// TODO mrs may in the future export library functions that can be used to
// convert a cherified malloc into one that is temporally safe without paying
// all the performance costs of a shim layer.

/*
 * Knobs:
 *
 * STANDALONE: build mrs as a standalone shared library
 * MALLOC_PREFIX: build mrs linked into an existing malloc
 * CONCURRENT: include locks to make mrs thread-safe
 * QUARANTINE_HIGHWATER: the quarantine size in bytes at which to carry out revocation (default 2MB)
 * OFFLOAD_QUARANTINE: process the quarantine in a separate detached thread (requires CONCURRENT)
 * SANITIZE: perform additional sanitization on mrs function calls
 * DEBUG: print debug statements
 * NUM_SHADOW_DESCS: number of descriptors for shadow space capabilities (default 10_000)
 * NUM_ALLOC_DESCS: number of descriptors for outstanding allocations (default 1_000_000)
 */

/*
 * Baseline sanitization is protection against use-after-reallocation attacks,
 * protection against use-after-free attacks caused by allocator reuse of freed
 * memory for metadata, and protection against double-free and arbitrary free
 * attacks (an allocated region, identified by the base of the capability that
 * points to it, can only be freed once; non-allocated regions cannot be
 * freed).
 *
 * Additional sanitization is validating the size of capabilities passed to
 * free, TODO validating that pages will not be munmapped or madvise free'd
 * while there are still valid allocations on them, ensuring that allocated
 * regions do not contain any capabilities (are zeroed before allocation),
 * validating the size and permissions of capabilities returned by the memory
 * allocator, determining at exit the number of outstanding alocations, ...
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

#ifndef NUM_SHADOW_DESCS
#define NUM_SHADOW_DESCS 10000
#endif /* !NUM_SHADOW_DESCS */

#ifndef NUM_ALLOC_DESCS
#define NUM_ALLOC_DESCS 1000000
#endif /* !NUM_ALLOC_DESCS */


/* cheri c utilities */

#define cheri_testsubset(x, y) __builtin_cheri_subset_test((x), (y))

/* globals */ // TODO static

/* store mapping between mmaped region and shadow space */
struct mrs_shadow_desc {
  void *mmap_region;
  void *shadow;
  int allocations; // TODO count number of corresponding allocs to validate munmap
  struct mrs_shadow_desc *next;
};

/* store mapping between allocated region and mmaped region/shadow space */
struct mrs_alloc_desc {
  void *allocated_region;
  void *shadow; /* local copy of shadow capability to avoid locking global shadow_spaces when !SANITIZE */
  struct mrs_shadow_desc *shadow_desc;
  struct mrs_alloc_desc *next;
  RB_ENTRY(mrs_alloc_desc) linkage;
};

struct mrs_shadow_desc shadow_descs[NUM_SHADOW_DESCS];
struct mrs_shadow_desc *shadow_spaces;
struct mrs_shadow_desc *free_shadow_descs;

struct mrs_alloc_desc alloc_descs[NUM_ALLOC_DESCS];
RB_HEAD(mrs_alloc_desc_head, mrs_alloc_desc) allocations;
struct mrs_alloc_desc *free_alloc_descs;

struct mrs_alloc_desc *quarantine;
long quarantine_size;

void* (*real_mmap) (void*, size_t, int, int, int, off_t);
void* (*real_malloc) (size_t);
void (*real_free) (void*);
/*void* (*real_calloc) (size_t, size_t);*/
/*void* (*real_realloc) (void *, size_t);*/
/*int (*real_posix_memalign) (void **, size_t, size_t);*/
/*void* (*real_aligned_alloc) (size_t, size_t);*/

/* locking */

#ifdef CONCURRENT
// hack to initialize mutexes without calling malloc
// XXX the buf size should be at least sizeof(struct pthread_mutex) from thr_private.h
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

#define mrs_lock(mtx) pthread_mutex_lock((mtx))
#define mrs_unlock(mtx) pthread_mutex_unlock((mtx))

#else /* CONCURRENT */

#define mrs_lock(mtx)
#define mrs_unlock(mtx)

#endif /* !CONCURRENT */

/* printf debugging */

#ifdef DEBUG

#include "printf.h"
void _putchar(char character) {
  write(2, &character, sizeof(char));
}

#define mrs_debug_printf(fmt, ...) \
  do {mrs_lock(&debug_lock); printf(("mrs: " fmt), ##__VA_ARGS__); mrs_unlock(&debug_lock);} while (0)

#define mrs_debug_printcap(name, cap) \
  mrs_debug_printf("capability %s: v:%u s:%u p:%08lx b:%016lx l:%016lx, o:%lx t:%ld\n", (name), cheri_gettag((cap)), cheri_getsealed((cap)), cheri_getperm((cap)), cheri_getbase((cap)), cheri_getlen((cap)), cheri_getoffset((cap)), cheri_gettype((cap)))

#else /* DEBUG */

#define mrs_debug_printf(fmt, ...)
#define mrs_debug_printcap(name, cap)

#endif /* !DEBUG */

// TODO multicore add lock, fix this if check, don't enable this by default

/* shadow_desc utilities */

void shadow_desc_list_insert(struct mrs_shadow_desc **list, struct mrs_shadow_desc *elem) {
  if (list == NULL || elem == NULL) {
    return;
  }
  elem->next = *list;
  *list = elem;
}

struct mrs_shadow_desc *shadow_desc_list_remove(struct mrs_shadow_desc **list) {
  if (list == NULL || *list == NULL) {
    return NULL;
  }
  struct mrs_shadow_desc *ret = *list;
  *list = (*list)->next;
  ret->next = NULL;
  return ret;
}

// TODO red black tree

static int insert_shadow_desc(void *mapped, void *shadow) {

  struct mrs_shadow_desc *ins = shadow_desc_list_remove(&free_shadow_descs);
  if (ins == NULL) {
    mrs_debug_printf("insert_shadow_desc: maximum number of shadow_descs exceeded\n");
    return -1;
  }
  ins->mmap_region = mapped;
  ins->shadow = shadow;

  if (shadow_spaces == NULL) {
    shadow_spaces = ins;
  } else {
    struct mrs_shadow_desc *iter = shadow_spaces;
    if (cheri_getbase(ins->mmap_region) < cheri_getbase(iter->mmap_region)) {
      ins->next = iter;
      shadow_spaces = ins;
    } else while ((iter->next != NULL) && (cheri_getbase(ins->mmap_region) > cheri_getbase(iter->next->mmap_region))) {
      iter = iter->next;
    }
    ins->next = iter->next;
    iter->next = ins;
  }

  return 0;
}

// TODO remove shadow desc and munmap

/**
 * Given a capability returned by malloc, return the shadow descriptor for its
 * corresponding shadow space. TODO iterate over rbtree
 **/
static void *lookup_shadow_desc(void *alloc) {
  struct mrs_shadow_desc *iter = shadow_spaces;
  while (iter != NULL) {
    if (cheri_testsubset(iter->mmap_region, alloc)) {
      return iter;
    }
    iter = iter->next;
  }
  return NULL;
}

/* alloc_desc utilities */

void alloc_desc_list_insert(struct mrs_alloc_desc **list, struct mrs_alloc_desc *elem) {
  if (list == NULL || elem == NULL) {
    return;
  }
  elem->next = *list;
  *list = elem;
}

struct mrs_alloc_desc *alloc_desc_list_remove(struct mrs_alloc_desc **list) {
  if (list == NULL || *list == NULL) {
    return NULL;
  }
  struct mrs_alloc_desc *ret = *list;
  *list = (*list)->next;
  ret->next = NULL;
  return ret;
}

static vaddr_t mrs_alloc_desc_cmp(struct mrs_alloc_desc *e1, struct mrs_alloc_desc *e2) {
  return cheri_getbase(e1->allocated_region) - cheri_getbase(e2->allocated_region);
}

RB_PROTOTYPE(mrs_alloc_desc_head, mrs_alloc_desc, linkage, mrs_alloc_desc_cmp);
RB_GENERATE(mrs_alloc_desc_head, mrs_alloc_desc, linkage, mrs_alloc_desc_cmp);

static int insert_alloc_desc(void *alloc, struct mrs_shadow_desc *shadow_desc) {
  struct mrs_alloc_desc *ins = alloc_desc_list_remove(&free_alloc_descs);
  if (ins == NULL) {
    mrs_debug_printf("insert_alloc_desc: maximum number of alloc_descs exceeded\n");
    return -1;
  }
  ins->allocated_region = alloc;
  ins->shadow_desc = shadow_desc;

  if (RB_INSERT(mrs_alloc_desc_head, &allocations, ins)) {
    mrs_debug_printf("insert_alloc_desc: duplicate insert\n");
    return -1;
  }

  return 0;
}

static int remove_alloc_desc(struct mrs_alloc_desc *rem) {
  struct mrs_alloc_desc *ret = RB_REMOVE(mrs_alloc_desc_head, &allocations, rem);
  if (ret == NULL) {
    mrs_debug_printf("remove_alloc_desc: element not found\n");
    return -1;
  }
  ret->allocated_region = NULL;
  ret->shadow_desc = NULL;
  alloc_desc_list_insert(&free_alloc_descs, ret);
  return 0;
}

static struct mrs_alloc_desc *lookup_alloc_desc(void *alloc) {
  struct mrs_alloc_desc lookup = {0};
  lookup.allocated_region = alloc;
  struct mrs_alloc_desc *ret = RB_FIND(mrs_alloc_desc_head, &allocations, &lookup);
  return ret;
}

/* initialization */

__attribute__((constructor))
static inline void init() {
#ifdef CONCURRENT
  // hack to initialize mutexes without calling malloc
#define initialize_lock(name) \
  _pthread_mutex_init_calloc_cb(&name, name ## _storage)

initialize_lock(debug_lock);
initialize_lock(shadow_spaces_lock);
initialize_lock(free_shadow_descs_lock);
initialize_lock(allocations_lock);
initialize_lock(free_alloc_descs_lock);
initialize_lock(quarantine_lock);
#endif /* CONCURRENT */

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

  for (int i = 0; i < NUM_SHADOW_DESCS; i++) {
    shadow_desc_list_insert(&free_shadow_descs, &shadow_descs[i]);
  }
  for (int i = 0; i < NUM_ALLOC_DESCS; i++) {
    alloc_desc_list_insert(&free_alloc_descs, &alloc_descs[i]);
  }

  mrs_debug_printf("init: complete\n");
}

/* mrs functions */

void *mrs_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  mrs_debug_printf("mrs_mmap: called with addr %p len 0x%zx prot 0x%x flags 0x%x fd %d offset 0x%zx\n", addr, len, prot, flags, fd, offset);

  void *mb = real_mmap(addr, len, prot, flags, fd, offset);
  if (mb ==  MAP_FAILED) {
    mrs_debug_printf("mrs_mmap: error in mmap errno %d\n", errno);
    return MAP_FAILED;
  }

  void *sh;
  if (caprevoke_shadow(CAPREVOKE_SHADOW_NOVMMAP, mb, &sh)) {
    mrs_debug_printf("mrs_mmap: error in caprevoke_shadow errno %d\n", errno);
    return MAP_FAILED;
  }

  mrs_lock(&shadow_spaces_lock);
  if (insert_shadow_desc(mb, sh)) {
    mrs_debug_printf("mrs_mmap: recording newly mapped region\n");
    mrs_unlock(&shadow_spaces_lock);
    return MAP_FAILED;
  }
  mrs_unlock(&shadow_spaces_lock);

  /*mrs_debug_printf("mrs_mmap: mmap returned %p caprevoke_shadow returned %p\n", mb, sh);*/
  return mb;
}

// TODO munmap madvise etc

void *mrs_malloc(size_t size) {

  /*mrs_debug_printf("mrs_malloc: enter\n");*/

  void *alloc = real_malloc(size);

  mrs_lock(&shadow_spaces_lock);
  void *sh = lookup_shadow_desc(alloc);
  if (sh == NULL) {
    mrs_unlock(&shadow_spaces_lock);
    mrs_debug_printf("\nmrs_malloc: looking up shadow space failed\n");
    real_free(alloc);
    return NULL;
  }

  mrs_lock(&allocations_lock);
  if (insert_alloc_desc(alloc, sh)) {
    mrs_unlock(&allocations_lock);
    mrs_unlock(&shadow_spaces_lock);
    mrs_debug_printf("\nmrs_malloc: inserting alloc descriptor failed\n");
    real_free(alloc);
    return NULL;
  }
  mrs_unlock(&allocations_lock);
  mrs_unlock(&shadow_spaces_lock);

  mrs_debug_printf("mrs_malloc: called size 0x%zx address %p\n", size, alloc);

  return alloc;
}

void *mrs_flush_quarantine(void *local_quarantine) {
  struct mrs_alloc_desc *iter = (struct mrs_alloc_desc *)local_quarantine;
  while (iter != NULL) {
    // TODO need lock for shadow space one since we access it. may want to do counts,
    // or if we never give back shadow space just store that cap in the allocation descriptor.
    // TODO use raw version when available
    mrs_lock(&shadow_spaces_lock); //TODO this design doesn't make sense perf-wise. keep a local copy of shadow cap, only do the lock in sanitize mode
                                  // when the alloc is actually removed and freed. Same thing for clearing below.
    caprev_shadow_nomap_set(iter->shadow_desc->shadow, iter->allocated_region, iter->allocated_region);
    mrs_unlock(&shadow_spaces_lock);
    iter = iter->next;
  }

  // TODO fix
  struct caprevoke_stats crst;
  uint64_t oepoch;
  caprevoke(CAPREVOKE_JUST_THE_TIME, 0, &crst);
  oepoch = crst.epoch;
  caprevoke(CAPREVOKE_LAST_PASS, oepoch, &crst);

  struct mrs_alloc_desc *prev;
  iter = (struct mrs_alloc_desc *)local_quarantine;
  while (iter != NULL) {
    mrs_lock(&shadow_spaces_lock);
    caprev_shadow_nomap_clear(iter->shadow_desc->shadow, iter->allocated_region);
    mrs_unlock(&shadow_spaces_lock);
    // XXX once revoker runs the tag will be cleared
    real_free(iter->allocated_region);
    // TODO in sanitize mode decrement the mmaped page's count.
    prev = iter;
    iter = iter->next;
  }

  // quarantine to free list
  mrs_lock(&free_alloc_descs_lock);
  prev->next = free_alloc_descs;
  free_alloc_descs = (struct mrs_alloc_desc *)local_quarantine;
  mrs_unlock(&free_alloc_descs_lock);

  return NULL;
}

/* TODO if a full page is freed, we may want to do munmap or mprotect (or
 * special MPROT_QUARANTINE later). we may also want to coalesce in quarantine
 * and measure the quarantine size by number of physical pages occupied .*/
/* TODO atexit how many things are not freed? */
void mrs_free(void *ptr) {

  mrs_debug_printf("mrs_free: called address %p\n", ptr);

  if (ptr == NULL) {
    return;
  }

  mrs_lock(&allocations_lock);
  struct mrs_alloc_desc *alloc_desc = lookup_alloc_desc(ptr);

  if (alloc_desc == NULL) {
    mrs_debug_printf("mrs_free: freed base address not allocated\n");
    mrs_unlock(&allocations_lock);
    exit(7); // XXX
  }

#ifdef SANITIZE
  if (cheri_getlen(ptr)!= cheri_getlen(alloc_desc->allocated_region)) {
    mrs_debug_printf("mrs_free: freed base address size mismatch cap len 0x%zx alloc size 0x%zx\n", cheri_getlen(ptr), cheri_getlen(alloc_desc->allocated_region));
    mrs_unlock(&allocations_lock);
    exit(7); // XXX
  }
#endif /* SANITIZE */

  RB_REMOVE(mrs_alloc_desc_head, &allocations, alloc_desc); // TODO error check?
  mrs_unlock(&allocations_lock);

  mrs_lock(&quarantine_lock);
  alloc_desc_list_insert(&quarantine, alloc_desc);
  quarantine_size += cheri_getlen(alloc_desc->allocated_region);

  if (quarantine_size >= QUARANTINE_HIGHWATER) {
    mrs_debug_printf("mrs_free: passed quarantine highwater of %lu, revoking\n", QUARANTINE_HIGHWATER);

    struct mrs_alloc_desc *full_quarantine = quarantine;
    quarantine = NULL;
    quarantine_size = 0;
    mrs_unlock(&quarantine_lock);

#if defined(CONCURRENT) && defined(OFFLOAD_QUARANTINE)
    mrs_debug_printf("mrs_free: offloading quarantine\n");
    pthread_t thd;
    pthread_create(&thd, NULL, mrs_flush_quarantine, full_quarantine);
    pthread_detach(thd);
#else /* CONCURRENT && OFFLOAD_QUARANTINE */
    mrs_flush_quarantine(full_quarantine);
#endif /* !(CONCURRENT && OFFLOAD_QUARANTINE) */
  } else {
    mrs_unlock(&quarantine_lock);
  }
}
