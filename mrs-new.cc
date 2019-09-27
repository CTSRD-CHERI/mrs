#include <new>

extern "C" {
	void *mrs_malloc(size_t);
	void mrs_free(void *);
}

/*
 * these cover replaceable allocation functions and replaceable non-throwing
 * allocation functions through C++14:
 * https://en.cppreference.com/w/cpp/memory/new/operator_new
 */

/* version (1) */
void * operator new(size_t size) {
	/* don't throw for size 0 allocations - technically this returned pointer should be non-null */
	if (size == 0) {
		return NULL;
	}
	void *ret = mrs_malloc(size);
	if (ret == NULL) {
		throw std::bad_alloc();
	}
	return ret;
}

/* version (2) */
void * operator new[](size_t size) {
	/* don't throw for size 0 allocations - technically this returned pointer should be non-null */
	if (size == 0) {
		return NULL;
	}
	void *ret = mrs_malloc(size);
	if (ret == NULL) {
		throw std::bad_alloc();
	}
	return ret;
}

/* version (5) */
void * operator new(size_t size, std::nothrow_t&) noexcept {
	return mrs_malloc(size);
}

/* version (6) */
void * operator new[](size_t size, std::nothrow_t&) noexcept {
	return mrs_malloc(size);
}

/*
 * these cover replaceable usual deallocation functions and replaceable
 * placement deallocation functions through C++14:
 * https://en.cppreference.com/w/cpp/memory/new/operator_delete
 */

/* version (1) */
void operator delete(void *p) noexcept {
	mrs_free(p);
}

/* version (2) */
void operator delete[](void *p) noexcept {
	mrs_free(p);
}

/* version (5) */
void operator delete(void *p, size_t size) noexcept {
	mrs_free(p);
}

/* version (6) */
void operator delete[](void *p, size_t size) noexcept {
	mrs_free(p);
}

/* version (9) */
void operator delete(void *p, std::nothrow_t&) noexcept {
	mrs_free(p);
}

/* version (10) */
void operator delete[](void *p, std::nothrow_t&) noexcept {
	mrs_free(p);
}
