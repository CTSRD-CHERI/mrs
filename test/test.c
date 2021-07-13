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
#undef NDEBUG
#define _DEBUG

#include <sys/types.h>

#include <cheri/cheric.h>
#include <cheri/revoke.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc_np.h>

void assert_not_revoked(void *cap) {
	assert(!cheri_revoke_is_revoked(cap));
}

void assert_revoked(void *cap) {
	assert(cheri_revoke_is_revoked(cap));
}

/* expects revocation to happen immediately (no quarantine, no offload) */
void uaf_basic_sub16() {
	void * volatile buffer = malloc(1);
	assert_not_revoked(buffer);
	free(buffer);
	assert_revoked(buffer);
}

/* expects revocation to happen immediately (no quarantine, no offload) */
void uaf_basic_16() {
	void * volatile buffer = malloc(16);
	assert_not_revoked(buffer);
	free(buffer);
	assert_revoked(buffer);
}

/* should trigger debug statements */
void free_pages() {
	void * volatile buffer = malloc(0x1000);
	free(buffer);
	buffer = malloc(0x2000);
	free(buffer);
}

/* expects revocation not to happen (doesn't fill quarantine) */
void uaf_low_water() {
	void * volatile buffer = malloc(1);
	assert_not_revoked(buffer);
	free(buffer);
	assert_not_revoked(buffer);
}

/* expects revocation to happen (fills quarantine of size 1024, no offload) */
void uaf_high_water() {
	void * volatile buffer1 = malloc(1);
	assert_not_revoked(buffer1);
	free(buffer1);
	assert_not_revoked(buffer1);
	void * volatile buffer2 = malloc(1024);
	assert_not_revoked(buffer2);
	free(buffer2);
	assert_revoked(buffer2);
}

/* expects revocation to be offloaded (fills quarantine of size 1024, waits for it to work) */
void uaf_high_water_offload() {
	void * volatile buffer1 = malloc(1);
	assert_not_revoked(buffer1);
	free(buffer1);
	assert_not_revoked(buffer1);
	void * volatile buffer2 = malloc(1024);
	assert_not_revoked(buffer2);
	free(buffer2);
	sleep(1);
	assert_revoked(buffer2);
}

/* basic stress test with many mallocs and frees */
void basic_stress_test(int num_allocs) {
	void * volatile * volatile allocs = malloc(sizeof(void *) * num_allocs);
	int i = 0;
	while (i < num_allocs) {
		allocs[i] = malloc(1024);
		i++;
	}
	while (i > 0) {
		free(allocs[i - 1]);
		i--;
	}
	free((void *)allocs);
}

void reuse_test() {
	for (int i = 0; i < 1024; i++) {
		void * volatile ptr = malloc(16);
		free(ptr);
	}
}

void malloc_usable_size_test() {
	char *myptr = (char *)malloc(16);
	size_t usable_size = malloc_usable_size(myptr);
	assert(usable_size >= 16);
	myptr += 1;
	usable_size = malloc_usable_size(myptr);
	assert(usable_size == 0);
}

__attribute__((weak))
void *malloc_underlying_allocation(void *);

void malloc_underlying_allocation_test() {
	char *orig = (char *)malloc(16);
	printf("original %#p\n", orig);

	char *underlying = malloc_underlying_allocation(orig);
	printf("0 underlying %#p original %#p\n", underlying, orig);

	char *restricted = cheri_setbounds(orig, 4);
	underlying = malloc_underlying_allocation(restricted);
	printf("1 underlying %#p restricted %#p\n", underlying, restricted);

	restricted += 1;
	underlying = malloc_underlying_allocation(restricted);
	printf("2 underlying %#p restricted %#p\n", underlying, restricted);

	restricted = cheri_setbounds(orig + 4, 4);
	underlying = malloc_underlying_allocation(restricted);
	printf("3 underlying %#p original %#p\n", underlying, orig);
}

/* with quarantine highwater 1 tests revoked free, with >16 tests double free. both test untagged free. */
void revoked_double_free_test() {
	void * volatile ptr = malloc(16);
	free(ptr);
	free(ptr);
	ptr = (void *)0x7;
	free(ptr);
}

/*
 * test how underlying mallocs respond to malformed inputs to free -
 * if the allocator doesn't crash, and next alloc isn't the address
 * that was just freed, you need to inspect the allocator's internals to
 * determine whether the free succeeded or not.
 */

void malformed_free_untagged() {
	char *myptr = (char *)malloc(32);
	myptr = cheri_cleartag(myptr);
	printf("freeing %#p\n", myptr);
	free(myptr);
	myptr = (char *)malloc(32);
	printf("next alloc %#p\n", myptr);
}

void malformed_free_perms() {
	char *myptr = (char *)malloc(32);
	myptr = cheri_andperm(myptr, 0);
	printf("freeing %#p\n", myptr);
	free(myptr);
	myptr = (char *)malloc(32);
	printf("next alloc %#p\n", myptr);
}

void malformed_free_addr_badalign() {
	char *myptr = (char *)malloc(32);
	myptr += 4;
	printf("freeing %#p\n", myptr);
	free(myptr);
	myptr = (char *)malloc(32);
	printf("next alloc %#p\n", myptr);
}

void malformed_free_addr_goodalign() {
	char *myptr = (char *)malloc(32);
	myptr += 16;
	printf("freeing %#p\n", myptr);
	free(myptr);
	myptr = (char *)malloc(32);
	printf("next alloc %#p\n", myptr);
}

void malformed_free_base_addr_badalign() {
	char *myptr = (char *)malloc(32);
	myptr = cheri_setbounds(myptr + 4, 28);
	printf("freeing %#p\n", myptr);
	free(myptr);
	myptr = (char *)malloc(32);
	printf("next alloc %#p\n", myptr);
}

void malformed_free_base_addr_goodalign() {
	char *myptr = (char *)malloc(32);
	myptr = cheri_setbounds(myptr + 16, 16);
	printf("freeing %#p\n", myptr);
	free(myptr);
	myptr = (char *)malloc(32);
	printf("next alloc %#p\n", myptr);
}

/* shrunk bounds may cause a crash but are highly unlikely to result in safety
 * violations so we don't check them */

int main(int argc, char *argv[]) {
	printf("mrs test start\n");
	/*uaf_basic_sub16();*/
	/*uaf_basic_16();*/
	/*free_pages();*/
	/*uaf_printf();*/
	/*uaf_low_water();*/
	/*uaf_high_water();*/
	/*uaf_high_water_offload();*/
	/*basic_stress_test(1024 * 16);*/
	/*reuse_test();*/
	/*revoked_double_free_test();*/
	/*malloc_usable_size_test();*/
	/*malloc_underlying_allocation_test();*/

	/*malformed_free_untagged();*/
	/*malformed_free_perms();*/
	/*malformed_free_addr_badalign();*/
	/*malformed_free_addr_goodalign();*/
	/*malformed_free_base_addr_badalign();*/
	/*malformed_free_base_addr_goodalign();*/

	printf("mrs test end\n");
}
