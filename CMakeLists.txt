cmake_minimum_required(VERSION 3.12.4)
project(mrs C CXX)

# the default behavior is to build libraries with a 25% heap-size quarantine
# that will be revoked when it is at least 2MB in size.

option(DEBUG "enable debug output" OFF)
option(PRINT_STATS "print statistics in library destructor" OFF)
option(OFFLOAD_QUARANTINE "process the quarantine in a separate worker thread" OFF)
option(BYPASS_QUARANTINE "MADV_FREE freed page-size allocations" OFF)
option(CLEAR_ALLOCATIONS "zero out allocations made by malloc" OFF)
option(SANITIZE "behave more like a sanitizer" OFF)

option(JUST_INTERPOSE "just call the real functions" OFF)
option(JUST_BOOKKEEPING "just update data structures then call the real functions" OFF)
option(JUST_QUARANTINE "just do bookkeeping and quarantining (no bitmap painting or revocation)" OFF)
option(JUST_PAINT_BITMAP"do bookkeeping, quarantining, and bitmap painting but no revocation" OFF)

if(DEBUG)
  message("defining DEBUG")
  add_compile_definitions(DEBUG)
endif()
if(PRINT_STATS)
  message("defining PRINT_STATS")
  add_compile_definitions(PRINT_STATS)
endif()
if(OFFLOAD_QUARANTINE)
  message("defining OFFLOAD_QUARANTINE")
  add_compile_definitions(OFFLOAD_QUARANTINE)
endif()
if(BYPASS_QUARANTINE)
  message("defining BYPASS_QUARANTINE")
  add_compile_definitions(BYPASS_QUARANTINE)
endif()
if(CLEAR_ALLOCATIONS)
  message("defining CLEAR_ALLOCATIONS")
  add_compile_definitions(CLEAR_ALLOCATIONS)
endif()
if(SANITIZE)
  message("defining SANITIZE")
  add_compile_definitions(SANITIZE)
endif()

if(JUST_INTERPOSE)
  message("defining JUST_INTERPOSE")
  add_compile_definitions(JUST_INTERPOSE)
endif()
if(JUST_BOOKKEEPING)
  message("defining JUST_BOOKKEEPING")
  add_compile_definitions(JUST_BOOKKEEPING)
endif()
if(JUST_QUARANTINE)
  message("defining JUST_QUARANTINE")
  add_compile_definitions(JUST_QUARANTINE)
endif()
if(JUST_PAINT_BITMAP)
  message("defining JUST_PAINT_BITMAP")
  add_compile_definitions(JUST_PAINT_BITMAP)
endif()

set(QUARANTINE_RATIO "" CACHE STRING "limit the quarantine size to 1/QUARANTINE_RATIO times the size of the heap")
set(QUARANTINE_HIGHWATER "" CACHE STRING "limit the quarantine size to QUARANTINE_HIGHWATER bytes (supersedes QUARANTINE_RATIO)")

if(NOT QUARANTINE_RATIO STREQUAL "")
  message("defining QUARANTINE_RATIO=${QUARANTINE_RATIO}")
  add_compile_definitions(QUARANTINE_RATIO=${QUARANTINE_RATIO})
endif()
if(NOT QUARANTINE_HIGHWATER STREQUAL "")
  message("defining QUARANTINE_HIGHWATER=${QUARANTINE_HIGHWATER}")
  add_compile_definitions(QUARANTINE_HIGHWATER=${QUARANTINE_HIGHWATER})
endif()

# build standalone
add_library(mrs SHARED mrs.c printf.c)
target_compile_definitions(mrs PRIVATE STANDALONE)
target_link_libraries(mrs pthread cheri_caprevoke)

# build jemalloc
set(JEMALLOC_SRC jemalloc.c arena.c background_thread.c base.c bin.c
  bitmap.c ckh.c ctl.c div.c extent.c extent_dss.c extent_mmap.c hash.c
  hooks.c large.c log.c malloc_io.c mutex.c mutex_pool.c nstime.c
  pages.c prng.c prof.c rtree.c stats.c sz.c tcache.c ticker.c tsd.c
  witness.c)
list(TRANSFORM JEMALLOC_SRC PREPEND ./jemalloc/src/)

add_library(jemalloc SHARED ${JEMALLOC_SRC})
target_include_directories(jemalloc PRIVATE . ./jemalloc/include)

add_library(jemalloc-mrs SHARED mrs.c printf.c ${JEMALLOC_SRC})
target_include_directories(jemalloc-mrs PRIVATE . ./jemalloc/include)
target_compile_definitions(jemalloc-mrs PRIVATE JEMALLOC_NO_RENAME MALLOC_PREFIX=je)
target_link_libraries(jemalloc-mrs pthread cheri_caprevoke)

# build test
add_executable(mrstest test/test.c)
