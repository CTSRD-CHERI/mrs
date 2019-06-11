void * mrs_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
void mrs_free(void *ptr);
void *mrs_malloc(size_t size);
