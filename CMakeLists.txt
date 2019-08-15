cmake_minimum_required(VERSION 3.8)
project(mrs C CXX)

# options: choose output and config; offload quarantine, bypass quarantine, debug, etc

# build standalone
add_library(mrs SHARED mrs.c printf.c)
target_compile_definitions(mrs PRIVATE STANDALONE DEBUG)
target_link_libraries(mrs pthread cheri_caprevoke)

# build jemalloc
set(JEMALLOC_SRC jemalloc.c arena.c background_thread.c base.c bin.c
  bitmap.c ckh.c ctl.c div.c extent.c extent_dss.c extent_mmap.c hash.c
  hooks.c large.c log.c malloc_io.c mutex.c mutex_pool.c nstime.c
  pages.c prng.c prof.c rtree.c stats.c sz.c tcache.c ticker.c tsd.c
  witness.c)
list(TRANSFORM JEMALLOC_SRC PREPEND ./jemalloc/src/)
add_library(jemalloc SHARED mrs.c printf.c ${JEMALLOC_SRC})
target_include_directories(jemalloc PRIVATE . ./jemalloc/include)
target_compile_definitions(jemalloc PRIVATE JEMALLOC_NO_RENAME MALLOC_PREFIX=je DEBUG)
target_link_libraries(jemalloc pthread cheri_caprevoke)

# build test
add_executable(mrstest test/test.c)
