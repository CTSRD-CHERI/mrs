#include <cheri/cheric.h>
#include <sys/caprevoke.h>
#include <sys/types.h>
#include <sys/mman.h>
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
  void* (*real_mmap) (void*, size_t, int, int, int, off_t);
  void* (*real_malloc) (size_t);
  void (*real_free) (void*);
};

static struct mrs_params params = {0};

// ---------------------------------- ALLOC ADDR -> SHADOW SPACE MAPPING
// TODO support removal, use better data structure

struct mrs_sh_desc {
  struct mrs_sh_desc *next;
  vaddr_t base;
  size_t size;
  void *sh;
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
  ins->base = base;
  ins->size = size;
  ins->sh = sh;

  if (params.shadow_spaces == NULL) {
    params.shadow_spaces = ins;
  } else {
    struct mrs_sh_desc *iter = params.shadow_spaces;
    if (ins->base < iter->base) {
      ins->next = iter;
      params.shadow_spaces = ins;
    } else while (iter->next != NULL && ins->base > iter->next->base) {
      iter = iter->next;
    }
    ins->next = iter->next;
    iter->next = ins;
  }

  return 0;
}

// TODO lookup_sh_desc - think about the right structure for all metadata

// ---------------------------------- END ALLOC ADDR -> SHADOW SPACE MAPPING

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
  mrs_debug_printf("mrs_malloc: called\n");

  if (params.real_malloc == NULL) {
    // TODO dlsym might use malloc
    params.real_malloc = dlsym(RTLD_NEXT, "malloc");
  }

  return params.real_malloc(size);

  /* TODO
   *
   * - record allocations
   * - sanitize/validate capabilities passed to consumer (check permissions incl. VMMAP, check bounds are not too large)
   * - only need to handle padding/alignment if the underlying allocator is not purecap (not currently supported)
   *
   */
}

void mrs_free(void *ptr) {
  mrs_debug_printf("mrs_free: called\n");

  if (params.real_free == NULL) {
    // TODO dlsym might use free
    params.real_free = dlsym(RTLD_NEXT, "free");
  }

  params.real_free(ptr);

  /* TODO
   *
   * - validate that the passed-in pointer was actually allocated
   * - add it to the quarantine list, use data structures to set appropriate shadow bitmap
   * - if quarantine full, run revoker and free memory
   *
   */
}

// TODO realloc calloc posix_memalign etc
