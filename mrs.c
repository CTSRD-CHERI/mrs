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
#include <inttypes.h>
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
 * PRINT_CAPREVOKE: print stats for each caprevoke
 * CLEAR_ON_ALLOC: zero allocated regions as they are allocated (for non-calloc allocation functions)
 * CLEAR_ON_FREE: zero allocated regions as they come out of quarantine
 * REVOKE_ON_FREE: perform revocation on free rather than during allocation routines
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
 * CONCURRENT_REVOCATION_PASSES: number of concurrent revocation pass before the stop-the-world pass
 *
 */

/* functions */

static void *mrs_malloc(size_t);
static void mrs_free(void *);
static void *mrs_calloc(size_t, size_t);
static void *mrs_realloc(void *, size_t);
static int mrs_posix_memalign(void **, size_t, size_t);
static void *mrs_aligned_alloc(size_t, size_t);

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

/*
 * defined by CHERIfied mallocs for use with mrs - given a capability returned
 * by the malloc that may have had its bounds shrunk, rederive and return a
 * capability with bounds corresponding to the original allocation.
 *
 * if the passed-in capability is tagged/permissioned and corresponds to some
 * allocation, give back a pointer with that same base whose length corresponds
 * to the underlying allocation size. otherwise return NULL.
 *
 * (for corespondence, check that its base matches the base of an allocation.
 * in practice, check that the offset is zero, which is necessary for the base
 * to match the base of any allocation, and then it is fine to compare the
 * address of the passed-in thing (which is the base) to whatever is necessary.
 * note that the length of the passed-in capability doesn't matter as long as
 * the allocator uses the underlying size for rederivation or revocation.
 *
 * this function will give back a pointer with VMMAP permissions, so mrs can
 * clear its memory and free it back post revocation. with mrs we assume the
 * attacker can't access this function, and in the post-mrs world it is
 * unnecessary.
 *
 * NB that as long as an allocator's allocations are naturally aligned
 * according to their size, as is the case for most slab/bibop allocators, it
 * is possible to check this condition by verifying that the passed-in
 * base/address is contained in the heap and is aligned to the size of
 * allocations in that heap region (power of 2 size or otherwise). it may be
 * necessary to do something verly slightly more complicated, like checking
 * offset from the end of a slab in snmalloc. in traditional free list
 * allocators, allocation metadata can be used to verify that the passed-in
 * pointer is legit.
 *
 * (writeup needs more detail about exactly what alloctors
 * will give back and expect in terms of base offset etc.)
 *
 * in an allocator that is not using mrs, similar logic should be used to
 * validate and/or rederive pointers and take actions accordingly on the free
 * path and any other function that accepts application pointers. a pointer
 * passed to free must correspond appropriately as described above. if it
 * doesn't then no action can be taken or you can abort.
 *
 * malloc_usable_size() and any other function taking in pointers similarly
 * needs validation.
 *
 * NB it is possible to do revocation safely with mrs only using a version of
 * malloc_usable_size() modified to give the size of the underlying allocation -
 * but this was done so that clearing on free could be evaluated easily and
 * so that allocators wouldn't have to accept revoked caps.
 */
void *malloc_underlying_allocation(void *) __attribute__((weak));

/* globals */

/* alignment requirement for allocations so they can be painted in the caprevoke bitmap */
static const size_t CAPREVOKE_BITMAP_ALIGNMENT = sizeof(void *); /* XXX VM_CAPREVOKE_GSZ_MEM_NOMAP from machine/vmparam.h */
static const size_t DESCRIPTOR_SLAB_ENTRIES = 10000;
static const size_t MIN_REVOKE_HEAP_SIZE = 8 * 1024 * 1024;

volatile const struct caprevoke_info *cri;
static size_t page_size;
static void *entire_shadow;

struct mrs_descriptor_slab_entry {
	void *ptr;
	size_t size;
};

struct mrs_descriptor_slab {
	int num_descriptors;
	struct mrs_descriptor_slab *next;
	struct mrs_descriptor_slab_entry slab[DESCRIPTOR_SLAB_ENTRIES];
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

/* XXX allocated_size has races in the offload case that are probably harmless */
static size_t allocated_size; /* amount of memory that the allocator views as allocated (includes quarantine) */
static size_t max_allocated_size;

static struct mrs_quarantine application_quarantine; /* quarantine for the application thread */
#ifdef OFFLOAD_QUARANTINE
static struct mrs_quarantine offload_quarantine; /* quarantine for the offload thread */
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
 * we assume that the consumer of this shim can issue arbitrary malicious
 * malloc/free calls. to track the total allocated size effectively, we
 * accumulate the length of capabilities as they are returned by mrs_malloc.
 * for the quarantine size, tracking is different in the offload and
 * non-offload cases. in the non-offload case, capabilities passed in to
 * mrs_free are validated and replaced with a rederived capability to the
 * entire allocation (obtained by calling the underlying allocator's
 * malloc_underlying_allocation() function) before being added to quarantine,
 * so we accumulate the length of capabilities in quarantine post-validation.
 * the result is that for each allocation, the same number is added to the
 * allocated size total and the quarantine size total. when the quarantine is
 * flushed, the allocated size is reduced by the quarantine size and the
 * quarantine size is reset to zero.
 *
 * in the offload case, the application thread fills a quarantine with
 * unvalidated capabilities passed in to mrs_free() (which may be untagged,
 * duplicates, have shrunk bounds, etc.). the lengths of these capabilities are
 * accumulated into the quarantine size, which is an approximation and only
 * used to trigger offload processing. in the offload thread, a separate
 * accumulation is performed using only validated capabilities, and that is used
 * to reduce the allocated size after flushing.
 *
 * sometimes malloc implementations are recursive in which case we leak some
 * space. this was observed in snmalloc for allocations of size 0x20.
 */
static inline void increment_allocated_size(void *allocated) {
	allocated_size += cheri_getlen(allocated);
	if (allocated_size > max_allocated_size) {
		max_allocated_size = allocated_size;
	}
}

static inline void clear_region(void *mem, size_t len) {
	static const size_t ZERO_THRESHOLD = 64;

	/* for small regions that are qword-multiple-sized, use writes to avoid
	 * memset call. alignment should be good in normal cases */
	if ((len <= ZERO_THRESHOLD) && (len % sizeof(uint64_t) == 0)) {
		for (size_t i = 0; i < (len / sizeof(uint64_t)); i++) {
			/* volatile needed to avoid memset call compiler "optimization" */
			((volatile uint64_t *)mem)[i] = 0;
		}
	} else {
		memset(mem, 0, len);
	}
}

/*
 * just insert a freed allocation into a quarantine, no validation, increase
 * quarantine size by the length of the allocation's capability
 */
static inline void quarantine_insert(struct mrs_quarantine *quarantine, void *ptr, size_t size) {

	if (quarantine->list == NULL || quarantine->list->num_descriptors == DESCRIPTOR_SLAB_ENTRIES) {
		struct mrs_descriptor_slab *ins = alloc_descriptor_slab();
		if (ins == NULL) {
			mrs_printf("quarantine_insert: couldn't allocate new descriptor slab\n");
			exit(7);
		}
		ins->next = quarantine->list;
		quarantine->list = ins;
	}

	quarantine->list->slab[quarantine->list->num_descriptors].ptr = ptr;
	quarantine->list->slab[quarantine->list->num_descriptors].size = size;

	quarantine->list->num_descriptors++;

	quarantine->size += size;
	if (quarantine->size > quarantine->max_size) {
		quarantine->max_size = quarantine->size;
	}

	if (quarantine->size > allocated_size) {
		mrs_printf("fatal error: quarantine size %zu exceeded allocated_size %zu "
		    "inserting the following cap\n", quarantine->size, allocated_size);
		mrs_printcap("inserted", ptr);
		exit(7);
	}
}

/*
 * given a pointer freed by the application, validate it by (1) checking that
 * the pointer has an underlying allocation (was actually allocated by the
 * allocator) and (2) using the bitmap painting function to make sure this
 * pointer is valid and hasn't already been freed or revoked.
 *
 * returns a capability to the underlying allocation if validation was successful,
 * NULL otherwise.
 *
 * supports ablation study knobs, returning NULL in case of a short circuit.
 *
 */
static inline void *validate_freed_pointer(void *ptr) {

	/*
	 * untagged check before malloc_underlying_allocation() catches NULL and other invalid
	 * caps that may cause a rude implementation of malloc_underlying_allocation() to crash.
	 */
	/*if (!cheri_gettag(ptr)) {*/
		/*mrs_debug_printf("validate_freed_pointer: untagged capability\n");*/
		/*return NULL;*/
	/*}*/

	void *underlying_allocation = malloc_underlying_allocation(ptr);
	if (underlying_allocation == NULL) {
		mrs_debug_printf("validate_freed_pointer: not allocated by underlying allocator\n");
		return NULL;
	}
	/*mrs_debug_printcap("freed underlying allocation", underlying_allocation);*/

#ifdef JUST_BOOKKEEPING
	real_free(ptr);
	return NULL;
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
	/*
	 * doesn't matter whether or not the len of underlying_allocation is
	 * actually a 16-byte multiple because all allocations will be 16-byte
	 * aligned
	 */
	if (caprev_shadow_nomap_set_len(entire_shadow, cheri_getbase(ptr), __builtin_align_up(cheri_getlen(underlying_allocation), CAPREVOKE_BITMAP_ALIGNMENT), ptr)) {
		mrs_debug_printf("validate_freed_pointer: setting bitmap failed\n");
		return NULL;
	}
#endif /* !JUST_QUARANTINE */

	return underlying_allocation;
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

#ifdef PRINT_CAPREVOKE
static inline uint64_t
caprevoke_get_cyc(void)
{
	uint64_t res;

	__asm__ __volatile__ (
		".set push\n.set noreorder\nrdhwr %0, $2\n.set pop"
	      : "=r"(res));

	return res;
}

static inline void
print_caprevoke_stats(char *what, struct caprevoke_stats *crst, uint64_t cycles)
{
	mrs_printf("mrs caprevoke %s:"
		" efin=%" PRIu64

		" psrt=%" PRIu32
		" psro=%" PRIu32
		" psrw=%" PRIu32

		" pfro=%" PRIu32
		" pfrw=%" PRIu32

		" pskf=%" PRIu32
		" psks=%" PRIu32

		" cfnd=%" PRIu32
		" cfrv=%" PRIu32

		" cnuk=%" PRIu32

		" lscn=%" PRIu32

		" pcyc=%" PRIu64
		" tcyc=%" PRIu64
		"\n",
		what,
		crst->epoch_fini,

		crst->pages_retried,
		crst->pages_scan_ro,
		crst->pages_scan_rw,

		crst->pages_faulted_ro,
		crst->pages_faulted_rw,

		crst->pages_skip_fast,
		crst->pages_skip,

		crst->caps_found,
		crst->caps_found_revoked,

		crst->caps_cleared,

		crst->lines_scan,

		crst->page_scan_cycles,
		cycles
	);
}
#endif

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

	while (!caprevoke_epoch_clears(cri->epoch_dequeue, start_epoch)) {
# ifdef PRINT_CAPREVOKE
		uint64_t cyc_init, cyc_fini;

#  if CONCURRENT_REVOCATION_PASSES > 0
		/* Run all concurrent passes as their own syscalls so we can report accurately */
		for (int i = 0; i < CONCURRENT_REVOCATION_PASSES; i++) {
			cyc_init = caprevoke_get_cyc();
			caprevoke(CAPREVOKE_EARLY_SYNC, start_epoch, &crst);
			cyc_fini = caprevoke_get_cyc();
			print_caprevoke_stats("concurrent", &crst, cyc_fini - cyc_init);
		}
		cyc_init = caprevoke_get_cyc();
		caprevoke(CAPREVOKE_LAST_PASS | CAPREVOKE_LAST_NO_EARLY, start_epoch, &crst);
		cyc_fini = caprevoke_get_cyc();
		print_caprevoke_stats("final", &crst, cyc_fini - cyc_init);
#  else /* CONCURRENT_REVOCATION_PASSES */
		cyc_init = caprevoke_get_cyc();
		caprevoke(CAPREVOKE_LAST_PASS | CAPREVOKE_LAST_NO_EARLY, start_epoch, &crst);
		cyc_fini = caprevoke_get_cyc();
		print_caprevoke_stats("single", &crst, cyc_fini - cyc_init);
#  endif /* !CONCURRENT_REVOCATION_PASSES */

# else /* PRINT_CAPREVOKE */

#  if CONCURRENT_REVOCATION_PASSES > 0
		/* Bundle the last concurrent pass with the last pass */
		for (int i = 0; i < CONCURRENT_REVOCATION_PASSES - 1; i++) {
			caprevoke(CAPREVOKE_EARLY_SYNC, start_epoch, &crst);
		}
		caprevoke(CAPREVOKE_LAST_PASS | CAPREVOKE_EARLY_SYNC, start_epoch, &crst);
#  else
		caprevoke(CAPREVOKE_LAST_PASS | CAPREVOKE_LAST_NO_EARLY, start_epoch, &crst);
#  endif

# endif /* !PRINT_CAPREVOKE */

	}
#endif /* !JUST_QUARANTINE && !JUST_PAINT_BITMAP */

	struct mrs_descriptor_slab *prev = NULL;
	for (struct mrs_descriptor_slab *iter = quarantine->list; iter != NULL; iter = iter->next) {
		for (int i = 0; i < iter->num_descriptors; i++) {
			/* in the offload case, only clear the bitmap for validated descriptors (cap != NULL) */
#ifdef OFFLOAD_QUARANTINE
			if (iter->slab[i].ptr != NULL) {
#endif /* OFFLOAD_QUARANTINE */

#if !defined(JUST_QUARANTINE)
				/* doesn't matter if underlying_size isn't a 16-byte multiple because all allocations will be 16-byte aligned */
				caprev_shadow_nomap_clear_len(entire_shadow, cheri_getbase(iter->slab[i].ptr), __builtin_align_up(cheri_getlen(iter->slab[i].ptr), CAPREVOKE_BITMAP_ALIGNMENT));
				atomic_thread_fence(memory_order_release); /* don't construct a pointer to a previously revoked region until the bitmap is cleared. */
#endif /* !JUST_QUARANTINE */

#ifdef CLEAR_ON_FREE
				clear_region(iter->slab[i].ptr, cheri_getlen(iter->slab[i].ptr));
#endif /* CLEAR_ON_FREE */

				/* we have a VMMAP-bearing cap from malloc_underlying_allocation */
				real_free(iter->slab[i].ptr);

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
	mrs_debug_printf("quarantine_flush: flushed, allocated_size %zu quarantine->size %zu\n", allocated_size, quarantine->size);
}

/*
 * check whether we should flush based on the quarantine policy and perform the
 * flush if so.  takes into account whether offload is enabled or not.
 *
 * in the wrapper, we perform these checks at the beginning of allocation
 * routines (so that the allocation routines might use the revoked memory in
 * the non-offload edge case where this could happen) rather than during an
 * mmap call - it might be better to perform this check just as the allocator
 * runs out of memory and before it calls mmap, but this is not possible from
 * the wrapper.
 */
static inline void check_and_perform_flush() {
#ifdef OFFLOAD_QUARANTINE

	// TODO perhaps allow the application to continue when we are past the high
	// water mark instead of blocking for the offload thread to finish flushing

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
if (quarantine_should_flush(&application_quarantine)) {
		mrs_printf("check_and_perform_flush (offload): passed application_quarantine threshold, offloading: allocated size %zu quarantine size %zu\n", allocated_size, application_quarantine.size);
#ifdef PRINT_CAPREVOKE
		mrs_printf("check_and_perform flush: cycle count before waiting on offload %" PRIu64 "\n", caprevoke_get_cyc());
#endif /* PRINT_CAPREVOKE */
		mrs_lock(&offload_quarantine_lock);
		while (offload_quarantine.list != NULL) {
#ifdef PRINT_CAPREVOKE
			mrs_printf("check_and_perform_flush (offload): waiting for offload_quarantine to drain\n");
#endif /* PRINT_CAPREVOKE */
			if (pthread_cond_wait(&offload_quarantine_empty, &offload_quarantine_lock)) {
				mrs_printf("pthread error\n");
				exit(7);
			}
		}
#ifdef PRINT_CAPREVOKE
		mrs_printf("check_and_perform_flush (offload): offload_quarantine drained\n");
		mrs_printf("check_and_perform flush: cycle count after waiting on offload %" PRIu64 "\n", caprevoke_get_cyc());
#endif /* PRINT_CAPREVOKE */

		offload_quarantine.list = application_quarantine.list;
		offload_quarantine.size = application_quarantine.size;
		application_quarantine.list = NULL;
		application_quarantine.size = 0;

		mrs_unlock(&offload_quarantine_lock);
		if (pthread_cond_signal(&offload_quarantine_ready)) {
			mrs_printf("pthread error\n");
			exit(7);
		}
	}

#else /* OFFLOAD_QUARANTINE */

	if (quarantine_should_flush(&application_quarantine)) {
		mrs_printf("check_and_perform_flush (no offload): passed application_quarantine threshold, revoking: allocated size %zu quarantine size %zu\n", allocated_size, application_quarantine.size);
		quarantine_flush(&application_quarantine);
	}

#endif /* !OFFLOAD_QUARANTINE */
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

	mrs_printf(VERSION_STRING);
}

#ifdef PRINT_STATS
__attribute__((destructor))
static void fini(void) {
#ifdef OFFLOAD_QUARANTINE
	mrs_printf("fini: heap size %zu, max heap size %zu, offload quarantine size %zu, max offload quarantine size %zu\n", allocated_size, max_allocated_size, offload_quarantine.size, offload_quarantine.max_size);
#else /* OFFLOAD_QUARANTINE */
	mrs_printf("fini: heap size %zu, max heap size %zu, quarantine size %zu, max quarantine size %zu\n", allocated_size, max_allocated_size, application_quarantine.size, application_quarantine.max_size);
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

#ifndef REVOKE_ON_FREE
	check_and_perform_flush();
#endif /* !REVOKE_ON_FREE */

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

#ifdef CLEAR_ON_ALLOC
	clear_region(allocated_region, cheri_getlen(allocated_region));
#endif /* CLEAR_ON_ALLOC */

	increment_allocated_size(allocated_region);

	/*mrs_debug_printf("mrs_malloc: called size 0x%zx\n", size);*/
	/*mrs_debug_printcap("allocation", allocated_region);*/

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

#ifndef REVOKE_ON_FREE
	check_and_perform_flush();
#endif /* !REVOKE_ON_FREE */

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

#ifndef REVOKE_ON_FREE
	check_and_perform_flush();
#endif /* !REVOKE_ON_FREE */

	if (alignment < CAPREVOKE_BITMAP_ALIGNMENT) {
		alignment = CAPREVOKE_BITMAP_ALIGNMENT;
	}

	int ret = real_posix_memalign(ptr, alignment, size);
	if (ret != 0) {
		return ret;
	}

#ifdef CLEAR_ON_ALLOC
	clear_region(*ptr, cheri_getlen(*ptr));
#endif /* CLEAR_ON_ALLOC */

	increment_allocated_size(*ptr);

	return ret;
}

static void *mrs_aligned_alloc(size_t alignment, size_t size) {
#ifdef JUST_INTERPOSE
	return real_aligned_alloc(alignment, size);
#endif /* JUST_INTERPOSE */

	mrs_debug_printf("mrs_aligned_alloc: called alignment %zu size %zu\n", alignment, size);

#ifndef REVOKE_ON_FREE
	check_and_perform_flush();
#endif /* !REVOKE_ON_FREE */

	if (alignment < CAPREVOKE_BITMAP_ALIGNMENT) {
		alignment = CAPREVOKE_BITMAP_ALIGNMENT;
	}

	void *allocated_region = real_aligned_alloc(alignment, size);
	if (allocated_region == NULL) {
	 return allocated_region;
	}

#ifdef CLEAR_ON_ALLOC
	clear_region(allocated_region, cheri_getlen(allocated_region));
#endif /* CLEAR_ON_ALLOC */

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

static void mrs_free(void *ptr) {
#ifdef JUST_INTERPOSE
	return real_free(ptr);
#endif /* JUST_INTERPOSE */

	/*mrs_debug_printf("mrs_free: called address %p\n", ptr);*/

	void *ins = ptr;

	/*
	 * if not offloading, validate the passed-in cap here and replace it with the
	 * cap to its underlying allocation
	 */
#ifndef OFFLOAD_QUARANTINE
	ins = validate_freed_pointer(ptr);
	if (ins == NULL) {
		mrs_debug_printf("mrs_free: validation failed\n");
		return;
	}
#endif /* !OFFLOAD_QUARANTINE */

	// TODO revisit coalescing/bypass
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

	/* use passed-in length because, if validated it is guaranteed to be less than the allocated length */
	quarantine_insert(&application_quarantine, ins, cheri_getlen(ptr));

#ifdef REVOKE_ON_FREE
	check_and_perform_flush();
#endif /* REVOKE_ON_FREE */
}

#ifdef OFFLOAD_QUARANTINE
static void *mrs_offload_thread(void *arg) {
	mrs_lock(&offload_quarantine_lock);
	for (;;) {
		while (offload_quarantine.list == NULL) {
#ifdef PRINT_CAPREVOKE
			mrs_printf("mrs_offload_thread: waiting for offload_quarantine to be ready\n");
#endif /* PRINT_CAPREVOKE */
			if (pthread_cond_wait(&offload_quarantine_ready, &offload_quarantine_lock)) {
				mrs_printf("pthread error\n");
				exit(7);
			}
		}
#ifdef PRINT_CAPREVOKE
		mrs_debug_printf("mrs_offload_thread: offload_quarantine ready\n");
#endif /* PRINT_CAPREVOKE */

		/* re-calculate the quarantine's size using only valid descriptors. */
		offload_quarantine.size = 0;
		/* iterate through the quarantine validating the freed pointers. */
		for (struct mrs_descriptor_slab *iter = offload_quarantine.list; iter != NULL; iter = iter->next) {
			for (int i = 0; i < iter->num_descriptors; i++) {
				iter->slab[i].ptr = validate_freed_pointer(iter->slab[i].ptr);

				if (iter->slab[i].ptr != NULL) {
					offload_quarantine.size += iter->slab[i].size;
				}
			}
		}

		mrs_debug_printf("mrs_offload_thread: flushing validated quarantine size %zu\n", offload_quarantine.size);

		quarantine_flush(&offload_quarantine);

#ifdef PRINT_CAPREVOKE
		mrs_printf("mrs_offload_thread: application quarantine's (unvalidated) size "
		    "when offloaded quarantine flush complete: %zu\n",
		    application_quarantine.size);
#endif /* PRINT_CAPREVOKE */

		if (pthread_cond_signal(&offload_quarantine_empty)) {
				mrs_printf("pthread error\n");
				exit(7);
		}
	}
}
#endif /* OFFLOAD_QUARANTINE */
