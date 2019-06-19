#include <cheri/cheric.h>
#include <sys/caprevoke.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/tree.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>

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

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  return mrs_mmap(addr, len, prot, flags, fd, offset);
}
void *malloc(size_t size) {
  return mrs_malloc(size);
}
void free(void *ptr) {
  return mrs_free(ptr);
}

static int insert_sh_desc();

#define DEBUG 1

// TODO fprintf might use malloc/mmap/free/etc
#define mrs_debug_printf(fmt, ...) \
  do {if (DEBUG) fprintf(stderr, ("mrs: " fmt), ##__VA_ARGS__); } while (0)


struct mrs_params {
  struct mrs_sh_desc *shadow_spaces;
  RB_HEAD(mrs_alloc_desc_head, mrs_alloc_desc) allocations;
  void* (*real_mmap) (void*, size_t, int, int, int, off_t);
  void* (*real_malloc) (size_t);
  void (*real_free) (void*);
};

static struct mrs_params params = {0};

// ---------------------------------- MMAP -> SHADOW SPACE MAPPING
// TODO support removal and free list of descriptors, use better data
// structures; this wants a red-black tree with coalescing (on insertion) and
// splitting (on removal), but how can we do this nicely with capabilities?

// TODO what if sub-mmapped-size regions are munmapped

// TODO use testsubset with mmap capability?
struct mrs_sh_desc {
  struct mrs_sh_desc *next;
  vaddr_t mmap_base;
  size_t mmap_size;
  void *sh;
  // TODO count number of corresponding allocs
};

static const int NUM_SH_DESCS = 1000;
static int sh_desc_index = 0;
static struct mrs_sh_desc sh_descs[NUM_SH_DESCS];

static int insert_sh_desc(vaddr_t base, size_t size, void *sh) {
  if (sh_desc_index == NUM_SH_DESCS) {
    printf("insert_sh_desc: maximum number of sh_descs exceeded\n");
    return -1;
  }

  struct mrs_sh_desc *ins = &sh_descs[sh_desc_index];
  sh_desc_index++;

  ins->next = NULL;
  ins->mmap_base = base;
  ins->mmap_size = size;
  ins->sh = sh;

  if (params.shadow_spaces == NULL) {
    params.shadow_spaces = ins;
  } else {
    struct mrs_sh_desc *iter = params.shadow_spaces;
    if (ins->mmap_base < iter->mmap_base) {
      ins->next = iter;
      params.shadow_spaces = ins;
    } else while ((iter->next != NULL) && (ins->mmap_base > iter->next->mmap_base)) {
      iter = iter->next;
    }
    ins->next = iter->next;
    iter->next = ins;
  }

  return 0;
}

static void *lookup_sh_desc(vaddr_t alloc_base, size_t alloc_size) {
  struct mrs_sh_desc *iter = params.shadow_spaces;
  while (iter != NULL) {
    // TODO what if an allocation spans multiple mmaped regions?
    if (((iter->mmap_base + iter->mmap_size) >= (alloc_base + alloc_size)) && (iter->mmap_base <= alloc_base)) {
      return iter;
    }
    iter = iter->next;
  }
  return NULL;
}

// ---------------------------------- END MMAP -> SHADOW SPACE MAPPING

// ------------------- ALLOCATED REGIONS
// TODO support free list of descriptors

// TODO use testsubset with malloc capability?
struct mrs_alloc_desc {
  RB_ENTRY(mrs_alloc_desc) linkage;
  void *alloc;
  vaddr_t alloc_base; // redundancy so we can RB_FIND without a capability
  size_t alloc_size;
  struct mrs_sh_desc *sh_desc;
};

static vaddr_t mrs_alloc_desc_cmp(struct mrs_alloc_desc *e1, struct mrs_alloc_desc *e2) {
  return e1->alloc_base - e2->alloc_base;
}

RB_PROTOTYPE(mrs_alloc_desc_head, mrs_alloc_desc, linkage, mrs_alloc_desc_cmp);
RB_GENERATE(mrs_alloc_desc_head, mrs_alloc_desc, linkage, mrs_alloc_desc_cmp);

static const int NUM_ALLOC_DESCS = 1000;
static int alloc_desc_index = 0;
static struct mrs_alloc_desc alloc_descs[NUM_ALLOC_DESCS];

static struct mrs_alloc_desc *insert_alloc_desc(void *alloc, struct mrs_sh_desc *sh_desc) {
  if (alloc_desc_index == NUM_ALLOC_DESCS) {
    printf("insert_alloc_desc: maximum number of alloc_descs exceeded\n");
    return NULL; // TODO null is a legitimate return value for RB_INSERT
  }

  struct mrs_alloc_desc *ins = &alloc_descs[alloc_desc_index];
  alloc_desc_index++;
  ins->alloc = alloc;
  ins->alloc_base = cheri_getbase(alloc);
  ins->alloc_size = cheri_getlen(alloc);
  ins->sh_desc = sh_desc;

  return RB_INSERT(mrs_alloc_desc_head, &params.allocations, ins);
}

static struct mrs_alloc_desc *lookup_alloc_desc(vaddr_t base) {
  struct mrs_alloc_desc lookup = {{0}}; //TODO
  lookup.alloc_base = base;
  return RB_FIND(mrs_alloc_desc_head, &params.allocations, &lookup);
}

// ------------------- END ALLOCATED REGIONS

void *mrs_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
  mrs_debug_printf("mrs_mmap: called with addr %p len 0x%zx prot 0x%x flags 0x%x fd %d offset 0x%zx\n", addr, len, prot, flags, fd, offset);

  if (params.real_mmap == NULL) {
    // TODO dlsym might use mmap
    params.real_mmap = dlsym(RTLD_NEXT, "mmap");
  }

  void *mb = params.real_mmap(addr, len, prot, flags, fd, offset);
  if (mb ==  MAP_FAILED) {
    mrs_debug_printf("mrs_mmap: error in mmap errno %d\n", errno);
    return MAP_FAILED;
  }
  mrs_debug_printf("mrs_mmap: mmap returned %p\n", mb);

  void *sh;
  if (caprevoke_shadow(CAPREVOKE_SHADOW_NOVMMAP, mb, &sh)) {
    mrs_debug_printf("mrs_mmap: error in caprevoke_shadow errno %d\n", errno);
    return MAP_FAILED;
  }
  mrs_debug_printf("mrs_mmap: caprevoke_shadow returned 0x%zx\n", cheri_getaddress(sh));

  if (insert_sh_desc(cheri_getbase(mb), cheri_getlen(mb), sh)) {
    mrs_debug_printf("mrs_mmap: recording newly mapped region\n");
    return MAP_FAILED;
  }

  return mb;
}

// TODO munmap madvise etc

void *mrs_malloc(size_t size) {

  if (params.real_malloc == NULL) {
    // TODO dlsym might use malloc
    params.real_malloc = dlsym(RTLD_NEXT, "malloc");
  }

  void *alloc = params.real_malloc(size);

  /* TODO
   *
   * - sanitize/validate capabilities passed to consumer (check permissions incl. VMMAP, check bounds are not too large)
   * - only need to handle padding/alignment if the underlying allocator is not purecap (not currently supported)
   *
   */

  void *sh = lookup_sh_desc(cheri_getbase(alloc), cheri_getlen(alloc));
  if (sh == NULL) {
    mrs_debug_printf("mrs_malloc: looking up shadow space failed\n");
    // TODO make sure this has been loaded params.real_free(alloc);
    return NULL;
  }

  insert_alloc_desc(alloc, sh);

  mrs_debug_printf("mrs_malloc: called size 0x%zx address %p\n", cheri_getlen(alloc), alloc);

  return alloc;

}

void mrs_free(void *ptr) {
  mrs_debug_printf("mrs_free: called address %p\n", ptr);

  if (ptr == NULL) {
    return;
  }

  if (params.real_free == NULL) {
    // TODO dlsym might use free
    params.real_free = dlsym(RTLD_NEXT, "free");
  }

  struct mrs_alloc_desc *alloc = lookup_alloc_desc(cheri_getbase(ptr));

  if (alloc == NULL) {
    mrs_debug_printf("mrs_free: freed base address not allocated\n");
    exit(7);
  }

  if (cheri_getlen(ptr)!= alloc->alloc_size) {
    mrs_debug_printf("mrs_free: freed base address size mismatch cap len 0x%zx alloc size 0x%zx\n", cheri_getlen(ptr), alloc->alloc_size);
    exit(7);
  }

  /* TODO
   *
   * - add it to the quarantine list, use data structures to set appropriate shadow bitmap
   * - free descriptor
   * - if quarantine full, run revoker and free memory
   *
   */

  params.real_free(ptr);
  RB_REMOVE(mrs_alloc_desc_head, &params.allocations, alloc);
}

// TODO realloc calloc posix_memalign etc
