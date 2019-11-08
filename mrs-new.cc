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

#include <new>

/*
 * these cover replaceable allocation functions and replaceable non-throwing
 * allocation functions through C++14:
 * https://en.cppreference.com/w/cpp/memory/new/operator_new
 */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnew-returns-null"

/* version (1) */
void * operator new(size_t size) {
	/* don't throw for size 0 allocations because this breaks applications -
	 * technically this returned pointer should be non-null but pointers returned
	 * with size 0 can't be dereferenced anyway */
	if (size == 0) {
		return NULL;
	}
	void *ret = malloc(size);
	if (ret == NULL) {
		throw std::bad_alloc();
	}
	return ret;
}

/* version (2) */
void * operator new[](size_t size) {
	/* don't throw for size 0 allocations because this breaks applications -
	 * technically this returned pointer should be non-null but pointers returned
	 * with size 0 can't be dereferenced anyway */
	if (size == 0) {
		return NULL;
	}
	void *ret = malloc(size);
	if (ret == NULL) {
		throw std::bad_alloc();
	}
	return ret;
}

#pragma clang diagnostic pop

/* version (5) */
void * operator new(size_t size, std::nothrow_t&) noexcept {
	return malloc(size);
}

/* version (6) */
void * operator new[](size_t size, std::nothrow_t&) noexcept {
	return malloc(size);
}

/*
 * these cover replaceable usual deallocation functions and replaceable
 * placement deallocation functions through C++14:
 * https://en.cppreference.com/w/cpp/memory/new/operator_delete
 */

/* version (1) */
void operator delete(void *p) noexcept {
	free(p);
}

/* version (2) */
void operator delete[](void *p) noexcept {
	free(p);
}

/* version (5) */
void operator delete(void *p, size_t size) noexcept {
	free(p);
}

/* version (6) */
void operator delete[](void *p, size_t size) noexcept {
	free(p);
}

/* version (9) */
void operator delete(void *p, std::nothrow_t&) noexcept {
	free(p);
}

/* version (10) */
void operator delete[](void *p, std::nothrow_t&) noexcept {
	free(p);
}
