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

static void *mrs_malloc(size_t);
static void mrs_free(void *);
#ifdef OFFLOAD_QUARANTINE
static void mrs_free_offload(void *);
#endif /* OFFLOAD_QUARANTINE */
static void *mrs_calloc(size_t, size_t);
static void *mrs_realloc(void *, size_t);
static int mrs_posix_memalign(void **, size_t, size_t);
static void *mrs_aligned_alloc(size_t, size_t);

void *malloc(size_t size) {
	return mrs_malloc(size);
}
void free(void *ptr) {
#ifndef OFFLOAD_QUARANTINE
	return mrs_free(ptr);
#else /* !OFFLOAD_QUARANTINE */
	return mrs_free_offload(ptr);
#endif
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

size_t malloc_allocation_size(void *) __attribute__((weak));

/* globals */

/* alignment requirement for allocations so they can be painted in the caprevoke bitmap */
static const size_t CAPREVOKE_BITMAP_ALIGNMENT = sizeof(void *); /* XXX VM_CAPREVOKE_GSZ_MEM_NOMAP from machine/vmparam.h */
static const size_t DESCRIPTOR_SLAB_ENTRIES = 10000;
static const size_t MIN_REVOKE_HEAP_SIZE = 8 * 1024 * 1024;

volatile const struct caprevoke_info *cri;
static size_t page_size;
static void *entire_shadow;

struct mrs_allocation_info {
	void *freed_ptr;
	size_t underlying_size;
};

struct mrs_descriptor_slab {
	int num_descriptors;
	struct mrs_descriptor_slab *next;
	struct mrs_allocation_info slab[DESCRIPTOR_SLAB_ENTRIES];
};

struct mrs_quarantine {
	size_t size;
	size_t max_size;
	struct mrs_descriptor_slab *list;
};

#ifndef OFFLOAD_QUARANTINE
static struct mrs_descriptor_slab *free_descriptor_slabs;
#else /* !OFFLOAD_QUARANTINE */
/* XXX ABA and other issues ... should switch to atomics library */
static struct mrs_descriptor_slab * _Atomic free_descriptor_slabs;
#endif /* OFFLOAD_QUARANTINE */

static size_t allocated_size; /* amount of memory that the allocator views as allocated (includes quarantine) */
static size_t max_allocated_size;

static struct mrs_quarantine quarantine;
#ifdef OFFLOAD_QUARANTINE
static struct mrs_quarantine offload_quarantine;
#endif /* OFFLOAD_QUARANTINE */

static void *mrs_calloc_bootstrap(size_t number, size_t size);

static void *(*real_malloc) (size_t);
static void (*real_free) (void *);
static void *(*real_calloc) (size_t, size_t) = mrs_calloc_bootstrap; /* replaced on init */
static void *(*real_realloc) (void *, size_t);
static int (*real_posix_memalign) (void **, size_t, size_t);
static void *(*real_aligned_alloc) (size_t, size_t);

/* locks */

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

/* quarantine offload support */
#ifdef OFFLOAD_QUARANTINE
static void *mrs_offload_thread(void *);
create_lock(offload_quarantine_lock);
/* no hack for these because condition variables are not used in allocation routines */
pthread_cond_t offload_quarantine_empty = PTHREAD_COND_INITIALIZER;
pthread_cond_t offload_quarantine_ready = PTHREAD_COND_INITIALIZER;
#endif /* OFFLOAD_QUARANTINE */

/* printf support */

create_lock(printf_lock);
void _putchar(char character) {
	write(2, &character, sizeof(char));
}

#define mrs_printf(fmt, ...) \
	do {mrs_lock(&printf_lock);printf(("mrs: " fmt), ##__VA_ARGS__);mrs_unlock(&printf_lock);} while (0)

#define mrs_printcap(name, cap) \
	mrs_printf("capability %s: v:%u s:%u p:%08lx b:%016lx l:%016lx, o:%lx t:%ld\n", (name), cheri_gettag((cap)), cheri_getsealed((cap)), cheri_getperm((cap)), cheri_getbase((cap)), cheri_getlen((cap)), cheri_getoffset((cap)), cheri_gettype((cap)))

/* debugging */

#ifdef DEBUG
#define mrs_debug_printf(fmt, ...) mrs_printf(fmt, ##__VA_ARGS__)
#define mrs_debug_printcap(name, cap) mrs_printcap(name, cap)
#else /* DEBUG */
#define mrs_debug_printf(fmt, ...)
#define mrs_debug_printcap(name, cap)
#endif /* !DEBUG */

/* utilities */

static struct mrs_descriptor_slab *alloc_descriptor_slab() {
	if (free_descriptor_slabs == NULL) {
		mrs_debug_printf("alloc_descriptor_slab: mapping new memory\n");
		struct mrs_descriptor_slab *ret = (struct mrs_descriptor_slab *)mmap(NULL, sizeof(struct mrs_descriptor_slab), PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
		return (ret == MAP_FAILED) ? NULL : ret;
	} else {
		mrs_debug_printf("alloc_descriptor_slab: reusing memory\n");
		struct mrs_descriptor_slab *ret = free_descriptor_slabs;

#ifdef OFFLOAD_QUARANTINE
		while (!atomic_compare_exchange_weak(&free_descriptor_slabs, &ret, ret->next));
#else /* OFFLOAD_QUARANTINE */
		free_descriptor_slabs = free_descriptor_slabs->next;
#endif /* !OFFLOAD_QUARANTINE */

		ret->num_descriptors = 0;
		return ret;
	}
}

/*
 * TODO knob for underlying allocation
 * we assume that the consumer of this shim can issue arbitrary malicious
 * malloc/free calls. by using the length of the capability returned from
 * malloc to increment allocated size and the capability given back by the user
 * to increment the quarantine size (only if that capability's base is actually
 * the base of an allocation, as confirmed by usable_malloc_size), we guarantee
 * that for each freed allocation, allocated_size will have been incremented by
 * at least as much as quarantine_size gets incremented. this is important
 * because quarantine_size gets subtracted from allocated_size. if the above
 * guarantee did not hold, an attacker could make allocated_size go negative
 * and prevent sweeps from taking place (this still does not allow heap aliasing).
 *
 * we could alternatively call malloc_usable_size during allocation and free to
 * make sure the same number is being added to allocated_size and
 * quarantine_size, but this adds a slight additional cost to allocation.
 * perhaps worth it.
 *
 * in the current code it is still possible for an attacker to inflate
 * quarantine_size by repeatedly freeing the same legitimately allocated
 * pointer. one solution to this is to paint the bitmap as each allocation is
 * freed, and only report the painting as a success if the region of the bitmap
 * is not already painted. this might slightly increase the cost of painting
 * and lessen the benefit of the offload thread. another possible solution is
 * to detect when allocated_size goes negative and take some appropriate
 * action, but more thought is needed there.
 */
static inline void increment_allocated_size(void *allocated) {
	allocated_size += cheri_getlen(allocated);
	if (allocated_size > max_allocated_size) {
		max_allocated_size = allocated_size;
	}
}

/* just insert a freed allocation into a quarantine, no validation, increase quarantine size by length of allocation capability */
static inline void quarantine_insert(struct mrs_quarantine *quarantine, void *ptr, size_t alloc_size) {

	if (quarantine->list == NULL || quarantine->list->num_descriptors == DESCRIPTOR_SLAB_ENTRIES) {
		struct mrs_descriptor_slab *ins = alloc_descriptor_slab();
		if (ins == NULL) {
			mrs_printf("quarantine_insert: couldn't allocate new descriptor slab\n");
			exit(7);
		}
		ins->next = quarantine->list;
		quarantine->list = ins;
	}

	quarantine->list->slab[quarantine->list->num_descriptors].freed_ptr = ptr;
	quarantine->list->slab[quarantine->list->num_descriptors].underlying_size = alloc_size;

	quarantine->list->num_descriptors++;

	quarantine->size += cheri_getlen(ptr); // TODO knob for incrementing quarantine size by underlying allocation (need to do this on the allocation side too)
	if (quarantine->size > quarantine->max_size) {
		quarantine->max_size = quarantine->size;
	}
}

/*
 * given a pointer freed by the application, validate it by (1) checking that
 * the pointer has an underlying allocation (was actually allocated by the
 * allocator) and (2) using the bitmap painting function to make sure this
 * pointer is valid and hasn't already been freed or revoked.
 *
 * returns the size of the underlying allocation if validation was successful,
 * 0 otherwise.
 *
 * supports ablation study knobs, returning 0 in case of a short circuit.
 *
 */
static inline size_t validate_freed_pointer(void *ptr) {

	/*
	 * untagged check before malloc_allocation_size() catches NULL and other invalid
	 * caps that may cause a rude implementation of malloc_allocation_size() to crash.
	 */
	if (!cheri_gettag(ptr)) {
		mrs_debug_printf("validate_freed_pointer: untagged capability\n");
		return 0;
	}

	size_t alloc_size = malloc_allocation_size(ptr);
	if (alloc_size == 0) {
		mrs_debug_printf("validate_freed_pointer: not allocated by underlying allocator\n");
		return 0;
	}

#ifdef JUST_BOOKKEEPING
	real_free(ptr);
	return 0;
#endif /* JUST_BOOKKEEPING */

	/*
	 * here we use the bitmap to synchronize and make sure that our guarantee is
	 * upheld in multithreaded environments. we paint the bitmap to signal to the
	 * kernel what needs to be revoked, but we also gate the operation of bitmap
	 * painting, so that we can only successfully paint the bitmap for some freed
	 * allocation (and let that allocation pass onto the quarantine list) if it
	 * is legitimately allocated on the heap, not revoked, and not previously
	 * queued for revocation, at the time of painting.
	 *
	 * essentially at this point we don't want something to end up on the
	 * quarantine list twice. if that were to happen, we wouldn't be upholding
	 * the principle that prevents heap aliasing.
	 *
	 * we can't allow a capability to pass painting and end up on the quarantine
	 * list if its region of the bitmap is already painted. if that were to
	 * happen, the two quarantine list entries corresponding to that region would
	 * be freed non-atomically, such that we could observe one being freed, the
	 * allocator reallocating the region, then the other being freed <! ERROR !>
	 *
	 * we also can't allow a previously revoked capability to pass painting and
	 * end up on the quarantine list. if that were to happen, we could observe:
	 *
	 * ptr mrs_freed -> painted in bitmap -> added to quarantine -> revoked ->
	 * cleared in bitmap -> /THREAD SWITCH/ revoked ptr mrs_freed -> painted in
	 * bitmap -> revoked again -> cleared in bitmap -> freed back to allocator ->
	 * reused /THREAD SWITCH BACK/ -> freed back to allocator <! ERROR !>
	 *
	 * similarly for untagged capabilities, because then a malicious user could
	 * just construct a capability that takes the place of revoked ptr (i.e. same
	 * address) above.
	 *
	 * we block these behaviors with a bitmap painting function that takes in a
	 * user pointer and the full length of the allocation. it will only succeed
	 * if, atomically at the time of painting, (1) the bitmap region is not
	 * painted (2) the user pointer is tagged (3) the user pointer is not
	 * revoked. if the painting function fails, we short-circuit and do not add
	 * allocation to quarantine.
	 *
	 * we can clear the bitmap after revocation and before freeing back to the
	 * allocator, which "opens" the gate for revocation of that region to occur
	 * again. it's fine for clearing not to be atomic with freeing back to the
	 * allocator, though, because between revocation and the allocator
	 * reallocating the region, the user does not have any valid capabilities to
	 * the region by definition.
	 */

#if !defined(JUST_QUARANTINE)
	/* doesn't matter whether alloc_size isn't a 16-byte multiple because all allocations will be 16-byte aligned */
	if (caprev_shadow_nomap_set_len(entire_shadow, cheri_getbase(ptr), __builtin_align_up(alloc_size, CAPREVOKE_BITMAP_ALIGNMENT), ptr)) {
		mrs_debug_printf("validate_freed_pointer: setting bitmap failed\n");
		return 0;
	}
#endif /* !JUST_QUARANTINE */

	return alloc_size;
}

static inline bool quarantine_should_flush(struct mrs_quarantine *quarantine) {
#if defined(QUARANTINE_HIGHWATER)

	return (quarantine->size >= QUARANTINE_HIGHWATER);

#else /* QUARANTINE_HIGHWATER */

#if !defined(QUARANTINE_RATIO)
#  define QUARANTINE_RATIO 4
#endif /* !QUARANTINE_RATIO */

	return ((allocated_size >= MIN_REVOKE_HEAP_SIZE) && ((quarantine->size * QUARANTINE_RATIO) >= allocated_size));

#endif /* !QUARANTINE_HIGHWATER */
}

/*
 * perform revocation then iterate through the quarantine and free entries with
 * non-zero underlying size (offload thread sets unvalidated caps to have zero
 * size).
 *
 * supports ablation study knobs.
 */
static inline void quarantine_flush(struct mrs_quarantine *quarantine) {
#if !defined(JUST_QUARANTINE) && !defined(JUST_PAINT_BITMAP)
	atomic_thread_fence(memory_order_acq_rel); /* don't read epoch until all bitmap painting is done */
	caprevoke_epoch start_epoch = cri->epoch_enqueue;
	struct caprevoke_stats crst;
#ifdef CONCURRENT_REVOCATION_PASS
	const int MRS_CAPREVOKE_FLAGS = (CAPREVOKE_LAST_PASS | CAPREVOKE_EARLY_SYNC);
#else /* CONCURRENT_REVOCATION_PASS */
	const int MRS_CAPREVOKE_FLAGS = (CAPREVOKE_LAST_PASS | CAPREVOKE_LAST_NO_EARLY);
#endif /* !CONCURRENT_REVOCATION_PASS */
	while (!caprevoke_epoch_clears(cri->epoch_dequeue, start_epoch)) {
		caprevoke(MRS_CAPREVOKE_FLAGS, start_epoch, &crst);
	}
#endif /* !JUST_QUARANTINE && !JUST_PAINT_BITMAP */

	struct mrs_descriptor_slab *prev = NULL;
	for (struct mrs_descriptor_slab *iter = quarantine->list; iter != NULL; iter = iter->next) {
		for (int i = 0; i < iter->num_descriptors; i++) {
			/* in the offload case, only clear the bitmap for validated descriptors (underlying_size != 0) */
#ifdef OFFLOAD_QUARANTINE
			if (iter->slab[i].underlying_size != 0) {
#endif /* OFFLOAD_QUARANTINE */

#if !defined(JUST_QUARANTINE)
				/* doesn't matter if underlying_size isn't a 16-byte multiple because all allocations will be 16-byte aligned */
				caprev_shadow_nomap_clear_len(entire_shadow, cheri_getbase(iter->slab[i].freed_ptr), __builtin_align_up(iter->slab[i].underlying_size, CAPREVOKE_BITMAP_ALIGNMENT));
				atomic_thread_fence(memory_order_release); /* don't construct a pointer to a previously revoked region until the bitmap is cleared. */
#endif /* !JUST_QUARANTINE */
				/* this will be a revoked capability, which the allocator must accept */
				real_free(iter->slab[i].freed_ptr);

#ifdef OFFLOAD_QUARANTINE
			}
#endif /* OFFLOAD_QUARANTINE */
		}
		prev = iter;
	}

	/* free the quarantined descriptors */
	prev->next = free_descriptor_slabs;
#ifdef OFFLOAD_QUARANTINE
	while (!atomic_compare_exchange_weak(&free_descriptor_slabs, &prev->next, quarantine->list));
#else /* OFFLOAD_QUARANTINE */
	free_descriptor_slabs = quarantine->list;
#endif /* !OFFLOAD_QUARANTINE */

	quarantine->list = NULL;
	allocated_size -= quarantine->size;
	quarantine->size = 0;
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

	initialize_lock(printf_lock);

#ifdef OFFLOAD_QUARANTINE
	initialize_lock(offload_quarantine_lock);

	pthread_t thd;
	if (pthread_create(&thd, NULL, mrs_offload_thread, NULL)) {
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
#ifdef OFFLOAD_QUARANTINE
	mrs_printf("fini: heap size %zu, max heap size %zu, quarantine size %zu, max quarantine size %zu\n", allocated_size, max_allocated_size, offload_quarantine.size, offload_quarantine.max_size);
#else /* OFFLOAD_QUARANTINE */
	mrs_printf("fini: heap size %zu, max heap size %zu, quarantine size %zu, max quarantine size %zu\n", allocated_size, max_allocated_size, quarantine.size, quarantine.max_size);
#endif /* !OFFLOAD_QUARANTINE */
}
#endif /* PRINT_STATS */

/* mrs functions */

static void *mrs_malloc(size_t size) {
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

	/*
	 * clearing allocations could be done after revocation on free (and thus be
	 * offloaded), but others report that zeroing the memory and bringing it into
	 * the cache just before allocation results in a performance improvement on
	 * some platforms, even if not on ours. TODO ask David about heuristics for
	 * this
	 *
	 * for revocation, clearing in the free function (but after revocation) may
	 * slightly reduce the cost of sweeping in later passes by reducing the
	 * number of capabilities in memory.
	 *
	 * we may also get a performance improvement by checking whether the
	 * allocations are 16-byte, 32-byte, multiples of 8-byte, etc. and replacing
	 * the memset with inline stores.
	 */
#ifdef CLEAR_ALLOCATIONS
	memset(allocated_region, 0, cheri_getlen(allocated_region));
#endif /* CLEAR_ALLOCATIONS */

	increment_allocated_size(allocated_region);

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

	/* this causes problems if our library is initizlied before the thread library */
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

	increment_allocated_size(allocated_region);

	/* this causes problems if our library is initizlied before the thread library */
	/*mrs_debug_printf("mrs_calloc: exit called %d size 0x%zx address %p\n", number, size, allocated_region);*/

	return allocated_region;
}

static int mrs_posix_memalign(void **ptr, size_t alignment, size_t size) {
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

	increment_allocated_size(*ptr);

	return ret;
}

static void *mrs_aligned_alloc(size_t alignment, size_t size) {
#ifdef JUST_INTERPOSE
	return real_aligned_alloc(alignment, size);
#endif /* JUST_INTERPOSE */

	mrs_debug_printf("mrs_aligned_alloc: called alignment %zu size %zu\n", alignment, size);

	if (alignment < CAPREVOKE_BITMAP_ALIGNMENT) {
		alignment = CAPREVOKE_BITMAP_ALIGNMENT;
	}

	void *allocated_region = real_aligned_alloc(alignment, size);
	if (allocated_region == NULL) {
	 return allocated_region;
	}

	increment_allocated_size(allocated_region);

	return allocated_region;
}

/*
 * replace realloc with a malloc and free to avoid dangling pointers in case of
 * in-place realloc that shrinks the buffer. if ptr is not a real allocation,
 * its buffer will still get copied into a new allocation.
 */
static void *mrs_realloc(void *ptr, size_t size) {

#ifdef JUST_INTERPOSE
	return real_realloc(ptr, size);
#endif /* JUST_INTERPOSE */

	size_t old_size = cheri_getlen(ptr);
	mrs_debug_printf("mrs_realloc: called ptr %p ptr size %zu new size %zu\n", ptr, old_size, size);

	if (size == 0) {
		free(ptr);
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
	free(ptr);
	return new_alloc;
}

static void mrs_free(void *ptr) {
#ifdef JUST_INTERPOSE
	return real_free(ptr);
#endif /* JUST_INTERPOSE */

	mrs_debug_printf("mrs_free: called address %p\n", ptr);

	size_t alloc_size = validate_freed_pointer(ptr);
	if (alloc_size == 0) {
		mrs_debug_printf("mrs_free: validation failed\n");
		return;
	}

	// TODO refactor and also include in the offload case
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

	quarantine_insert(&quarantine, ptr, alloc_size);

	if (quarantine_should_flush(&quarantine)) {
		mrs_printf("mrs_free: passed quarantine threshold, revoking: allocated size %zu quarantine size %zu\n", allocated_size, quarantine.size);
		quarantine_flush(&quarantine);
	}
}

#ifdef OFFLOAD_QUARANTINE
/*
 * we trigger a revocation pass when the unvalidated quarantine hits the
 * highwater mark because if we waited until the validated queue passed the
 * highwater mark, the allocated size might increase (allocations made) between
 * the unvalidated queue and validated queue filling such that the high water
 * mark is no longer hit. this function just fills up the unvalidated
 * quarantine and passes it off when it's full. with offload enabled,
 * the "quarantine" global is unvalidated and passed off to the
 * "offload_quarantine" global then processed in place (list entries that fail
 * validation are not processed).
 */
static void mrs_free_offload(void *ptr) {
	mrs_debug_printf("mrs_free_offload: called address %p\n", ptr);

	/* use alloc_size of 0 to indicate unvalidated descriptor */
quarantine_insert(&quarantine, ptr, 0);

if (quarantine_should_flush(&quarantine)) {
		mrs_printf("mrs_free_offload: passed quarantine threshold, revoking: allocated size %zu quarantine size %zu\n", allocated_size, quarantine.size);
		mrs_lock(&offload_quarantine_lock);
		while (offload_quarantine.list != NULL) {
			mrs_debug_printf("mrs_free_offload: waiting for offload_quarantine to drain\n");
			if (pthread_cond_wait(&offload_quarantine_empty, &offload_quarantine_lock)) {
				mrs_printf("pthread error\n");
				exit(7);
			}
		}
		mrs_debug_printf("mrs_free_offload: offload_quarantine drained\n");

		offload_quarantine.list = quarantine.list;
		offload_quarantine.size = quarantine.size;
		quarantine.list = NULL;
		quarantine.size = 0;

		mrs_unlock(&offload_quarantine_lock);
		if (pthread_cond_signal(&offload_quarantine_ready)) {
			mrs_printf("pthread error\n");
			exit(7);
		}
	}
}

static void *mrs_offload_thread(void *arg) {
	mrs_lock(&offload_quarantine_lock);
	for (;;) {
		while (offload_quarantine.list == NULL) {
			mrs_debug_printf("mrs_offload_thread: waiting for offload_quarantine to be ready\n");
			if (pthread_cond_wait(&offload_quarantine_ready, &offload_quarantine_lock)) {
				mrs_printf("pthread error\n");
				exit(7);
			}
		}
		mrs_debug_printf("mrs_offload_thread: offload_quarantine ready\n");

		/* iterate through the quarantine validating the freed pointers. alloc_size of 0 means invalid. */
		for (struct mrs_descriptor_slab *iter = offload_quarantine.list; iter != NULL; iter = iter->next) {
			for (int i = 0; i < iter->num_descriptors; i++) {
				iter->slab[i].underlying_size = validate_freed_pointer(iter->slab[i].freed_ptr);

				/* if the pointer was invalid, don't include it in the size calculation */
				if (iter->slab[i].underlying_size == 0) {
					// TODO can use underlying alloc size if knob is set
					offload_quarantine.size -= cheri_getlen(iter->slab[i].freed_ptr);
				}
			}
		}

		quarantine_flush(&offload_quarantine);

		if (pthread_cond_signal(&offload_quarantine_empty)) {
				mrs_printf("pthread error\n");
				exit(7);
		}
	}
}
#endif /* OFFLOAD_QUARANTINE */
