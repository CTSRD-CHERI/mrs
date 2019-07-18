#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <cheri/cheric.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/tree.h>
#include <sys/caprevoke.h>
#include <caprevoke.h>

#include "mrs.h"

// use mrs on a cheri-enabled system to make a legacy memory allocator that has
// been ported to purecap (1) immune to use-after-reallocation vulnerabilities
// (2) immune to vulnerabilities related to double free, incorrect (arbitrary)
// free, and exposure of allocator metadata. the allocator will already be
// spatially safe by virtue of running purecap.

// TODO multicore

// TODO support either building mrs as (1) a standalone shared library for
// LD_PRELOAD use that exports malloc, free and mmap symbols and uses dlsym to
// get the real ones (easiest to use but means all mmaps, even those not by the
// allocator, will be instrumented) or (2) linked with a memory allocator as a
// shared library for LD_PRELOAD that exports malloc and free symbols whose
// underlying implementations are supplied by the linked memory allocator, and
// where that underlying allocator is modified to use the mrs mmap function.

// mrs can be built as a standalone shared library for use with LD_PRELOAD over
// an existing allocator (#define STANDALONE) - in this case it exports malloc, free, and mmap
// symbols, and it gets the "correct" or underlying ones from dlsym. mrs can
// also be linked into an existing cherified malloc implmenetaion (#define
// MALLOC_PREFIX example), in which case it exports only the malloc and free
// symbols. the malloc implementation should be modified to use mrs_mmap
// instead of mmap, and its malloc and free functions should be prefixed with
// the name of the malloc. mrs will then use those prefixed functions (and the
// real mmap) as the "correct" ones.

void *malloc(size_t size) {
  return mrs_malloc(size);
}
void free(void *ptr) {
  return mrs_free(ptr);
}
#ifdef STANDALONE
void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  return mrs_mmap(addr, len, prot, flags, fd, offset);
}
#endif
// TODO 
void *je_malloc(size_t size);
void je_free(void *ptr);

#define DEBUG 1

// TODO fprintf might use malloc/free/mmap
#define mrs_debug_printf(fmt, ...) \
  do {if (DEBUG) fprintf(stderr, ("mrs: " fmt), ##__VA_ARGS__); } while (0)

#define cheri_testsubset(x, y) __builtin_cheri_subset_test((x), (y))

struct mrs_params {
  struct mrs_shadow_desc *shadow_spaces;
  RB_HEAD(mrs_alloc_desc_head, mrs_alloc_desc) allocations;
  bool initialized;
  void* (*real_mmap) (void*, size_t, int, int, int, off_t);
  void* (*real_malloc) (size_t);
  void (*real_free) (void*);
};

static struct mrs_params params = {0};

static inline void init_params() {
  if (!params.initialized) {
#if defined(STANDALONE)
    // XXX dlsym might cause a malloc/free/mmap
    params.real_malloc = dlsym(RTLD_NEXT, "malloc");
    params.real_free = dlsym(RTLD_NEXT, "free");
    params.real_mmap = dlsym(RTLD_NEXT, "mmap");
#elif defined(MALLOC_PREFIX)
#define concat_resolved(a, b) a ## b
#define concat(a, b) concat_resolved(a,b) // need a function without ## so args will be resolved
    params.real_malloc = concat(MALLOC_PREFIX, _malloc);
    params.real_free = concat(MALLOC_PREFIX, _free);
    params.real_mmap = mmap;
#else
#error must build mrs with either STANDALONE or MALLOC_PREFIX defined
#endif
    params.initialized = true;
  }
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
  return RB_FIND(mrs_alloc_desc_head, &params.allocations, &lookup);
}

// ------------------- END ALLOCATED REGIONS

void *mrs_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  mrs_debug_printf("mrs_mmap: called with addr %p len 0x%zx prot 0x%x flags 0x%x fd %d offset 0x%zx\n", addr, len, prot, flags, fd, offset);

  init_params();

  void *mb = params.real_mmap(addr, len, prot, flags, fd, offset);
  if (mb ==  MAP_FAILED) {
    mrs_debug_printf("mrs_mmap: error in mmap errno %d\n", errno);
    return MAP_FAILED;
  }

  void *sh;
  if (caprevoke_shadow(CAPREVOKE_SHADOW_NOVMMAP, mb, &sh)) {
    mrs_debug_printf("mrs_mmap: error in caprevoke_shadow errno %d\n", errno);
    return MAP_FAILED;
  }

  if (insert_shadow_desc(mb, sh)) {
    mrs_debug_printf("mrs_mmap: recording newly mapped region\n");
    return MAP_FAILED;
  }

  mrs_debug_printf("mrs_mmap: mmap returned %p caprevoke_shadow returned %p\n", mb, sh);

  return mb;
}

// TODO munmap madvise etc

void *mrs_malloc(size_t size) {

  init_params();

  void *alloc = params.real_malloc(size);

  /* TODO
   *
   * - sanitize/validate capabilities passed to consumer (check permissions incl. VMMAP, check bounds are not too large)
   * - only need to handle padding/alignment if the underlying allocator is not purecap (not currently supported)
   *
   */

  void *sh = lookup_shadow_desc(alloc);
  if (sh == NULL) {
    mrs_debug_printf("mrs_malloc: looking up shadow space failed\n");
    params.real_free(alloc);
    return NULL;
  }

  if (insert_alloc_desc(alloc, sh)) {
    mrs_debug_printf("mrs_malloc: inserting alloc descriptor failed\n");
    params.real_free(alloc);
    return NULL;
  }

  mrs_debug_printf("mrs_malloc: called size 0x%zx address %p\n", cheri_getlen(alloc), alloc);

  return alloc;
}

void mrs_free(void *ptr) {
  mrs_debug_printf("mrs_free: called address %p\n", ptr);

  if (ptr == NULL) {
    return;
  }

  init_params();

  struct mrs_alloc_desc *alloc_desc = lookup_alloc_desc(ptr);

  if (alloc_desc == NULL) {
    mrs_debug_printf("mrs_free: freed base address not allocated\n");
    exit(7);
  }

  if (cheri_getlen(ptr)!= cheri_getlen(alloc_desc->alloc)) {
    mrs_debug_printf("mrs_free: freed base address size mismatch cap len 0x%zx alloc size 0x%zx\n", cheri_getlen(ptr), cheri_getlen(alloc_desc->alloc));
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

  struct caprevoke_stats crst;
  uint64_t oepoch;
  caprev_shadow_nomap_set(alloc_desc->shadow_desc->shadow, ptr);

  caprevoke(CAPREVOKE_JUST_THE_TIME, 0, &crst);
  oepoch = crst.epoch;
  caprevoke(CAPREVOKE_LAST_PASS, oepoch, &crst);

  caprev_shadow_nomap_clear(alloc_desc->shadow_desc->shadow, ptr);

  // XXX once revoker runs ptr's tag will be cleared
  params.real_free(ptr);
  RB_REMOVE(mrs_alloc_desc_head, &params.allocations, alloc_desc);
}

// TODO realloc calloc posix_memalign etc
