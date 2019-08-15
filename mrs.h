void *mrs_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);
int mrs_munmap(void *addr, size_t len);
int mrs_madvise(void *addr, size_t len, int behav);
int mrs_posix_madvise(void *addr, size_t len, int behav);
