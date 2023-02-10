cmake_minimum_required(VERSION 3.12.4)
project(mrs C CXX)

#################
# BUILD TARGETS #
#################

# build mrs
add_library(mrs SHARED mrs.c mrs.cc)
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

# build test
add_executable(mrstest test/test.c)

#######################
# COMPILE DEFINITIONS #
#######################

# the default behavior is to build libraries with a 25% heap-size quarantine
# that will be revoked when it is at least 2MB in size.

option(DEBUG "enable debug output" OFF)
option(PRINT_STATS "print statistics in library destructor" OFF)
option(PRINT_CAPREVOKE "print statistics per revocation" OFF)
option(OFFLOAD_QUARANTINE "process the quarantine in a separate worker thread" OFF)
option(MRS_PINNED_CPUSET "notch out CPU 2 for offload thread" OFF)
option(BYPASS_QUARANTINE "MADV_FREE freed page-size allocations" OFF)
option(CLEAR_ON_ALLOC "zero allocated regions as they are allocated (for non-calloc allocation functions)" OFF)
option(CLEAR_ON_FREE "zero allocated regions as they are freed" OFF)
option(CLEAR_ON_RETURN "zero allocated regions as they come out of quarantine" OFF)
option(REVOKE_ON_FREE "perform revocation on free rather than during allocation routines" OFF)
option(LOAD_SIDE_REVOCATION "use Reloaded" OFF)

option(JUST_INTERPOSE "just call the real functions" OFF)
option(JUST_BOOKKEEPING "just update data structures then call the real functions" OFF)
option(JUST_QUARANTINE "just do bookkeeping and quarantining (no bitmap painting or revocation)" OFF)
option(JUST_PAINT_BITMAP "do bookkeeping, quarantining, and bitmap painting but no revocation" OFF)

option(SNMALLOC_FLUSH "assume the existence of snmalloc_flush_message_queue()" OFF)
option(SNMALLOC_PRINT_STATS "assume the existence of snmalloc_print_stats()" OFF)

set(VERSION_STRING "\"version")

if(DEBUG)
	message("defining DEBUG")
	target_compile_definitions(mrs PRIVATE DEBUG)
	set(VERSION_STRING "${VERSION_STRING} DEBUG")
endif()
if(PRINT_STATS)
	message("defining PRINT_STATS")
	target_compile_definitions(mrs PRIVATE PRINT_STATS)
	set(VERSION_STRING "${VERSION_STRING} PRINT_STATS")
endif()
if(PRINT_CAPREVOKE)
	message("defining PRINT_CAPREVOKE")
	target_compile_definitions(mrs PRIVATE PRINT_CAPREVOKE)
	set(VERSION_STRING "${VERSION_STRING} PRINT_CAPREVOKE")
endif()
if(OFFLOAD_QUARANTINE)
	message("defining OFFLOAD_QUARANTINE")
	target_compile_definitions(mrs PRIVATE OFFLOAD_QUARANTINE)
	set(VERSION_STRING "${VERSION_STRING} OFFLOAD_QUARANTINE")
endif()
if(MRS_PINNED_CPUSET)
	message("defining MRS_PINNED_CPUSET")
	target_compile_definitions(mrs PRIVATE MRS_PINNED_CPUSET)
	set(VERSION_STRING "${VERSION_STRING} MRS_PINNED_CPUSET")
endif()
if(BYPASS_QUARANTINE)
	message("defining BYPASS_QUARANTINE")
	target_compile_definitions(mrs PRIVATE BYPASS_QUARANTINE)
	set(VERSION_STRING "${VERSION_STRING} BYPASS_QUARANTINE")
endif()
if(CLEAR_ON_ALLOC)
	message("defining CLEAR_ON_ALLOC")
	target_compile_definitions(mrs PRIVATE CLEAR_ON_ALLOC)
	set(VERSION_STRING "${VERSION_STRING} CLEAR_ON_ALLOC")
endif()
if(CLEAR_ON_FREE)
	message("defining CLEAR_ON_FREE")
	target_compile_definitions(mrs PRIVATE CLEAR_ON_FREE)
	set(VERSION_STRING "${VERSION_STRING} CLEAR_ON_FREE")
endif()
if(CLEAR_ON_RETURN)
	message("defining CLEAR_ON_RETURN")
	target_compile_definitions(mrs PRIVATE CLEAR_ON_RETURN)
	set(VERSION_STRING "${VERSION_STRING} CLEAR_ON_RETURN")
endif()
if(REVOKE_ON_FREE)
	message("defining REVOKE_ON_FREE")
	target_compile_definitions(mrs PRIVATE REVOKE_ON_FREE)
	set(VERSION_STRING "${VERSION_STRING} REVOKE_ON_FREE")
endif()
if(SNMALLOC_PRINT_STATS)
	message("defining SNMALLOC_PRINT_STATS")
	target_compile_definitions(mrs PRIVATE SNMALLOC_PRINT_STATS)
	set(VERSION_STRING "${VERSION_STRING} SNMALLOC_PRINT_STATS")
endif()
if(SNMALLOC_FLUSH)
	message("defining SNMALLOC_FLUSH")
	target_compile_definitions(mrs PRIVATE SNMALLOC_FLUSH)
	set(VERSION_STRING "${VERSION_STRING} SNMALLOC_FLUSH")
endif()


if(JUST_INTERPOSE)
	message("defining JUST_INTERPOSE")
	target_compile_definitions(mrs PRIVATE JUST_INTERPOSE)
	set(VERSION_STRING "${VERSION_STRING} JUST_INTERPOSE")
endif()
if(JUST_BOOKKEEPING)
	message("defining JUST_BOOKKEEPING")
	target_compile_definitions(mrs PRIVATE JUST_BOOKKEEPING)
	set(VERSION_STRING "${VERSION_STRING} JUST_BOOKKEEPING")
endif()
if(JUST_QUARANTINE)
	message("defining JUST_QUARANTINE")
	target_compile_definitions(mrs PRIVATE JUST_QUARANTINE)
	set(VERSION_STRING "${VERSION_STRING} JUST_QUARANTINE")
endif()
if(JUST_PAINT_BITMAP)
	message("defining JUST_PAINT_BITMAP")
	target_compile_definitions(mrs PRIVATE JUST_PAINT_BITMAP)
	set(VERSION_STRING "${VERSION_STRING} JUST_PAINT_BITMAP")
endif()
if(LOAD_SIDE_REVOCATION)
	message("defining LOAD_SIDE_REVOCATION")
	target_compile_definitions(mrs PRIVATE LOAD_SIDE_REVOCATION)
	set(VERSION_STRING "${VERSION_STRING} LOAD_SIDE_REVOCATION")
endif()

set(CONCURRENT_REVOCATION_PASSES "0" CACHE STRING "Number of concurrent revocation passes before the stop-the-world pass")
set(QUARANTINE_RATIO "" CACHE STRING "limit the quarantine size to 1/QUARANTINE_RATIO times the size of the heap")
set(QUARANTINE_HIGHWATER "" CACHE STRING "limit the quarantine size to QUARANTINE_HIGHWATER bytes (supersedes QUARANTINE_RATIO)")

if(NOT QUARANTINE_RATIO STREQUAL "")
	message("defining QUARANTINE_RATIO=${QUARANTINE_RATIO}")
	target_compile_definitions(mrs PRIVATE QUARANTINE_RATIO=${QUARANTINE_RATIO})
	set(VERSION_STRING "${VERSION_STRING} QUARANTINE_RATIO=${QUARANTINE_RATIO}")
endif()
if(NOT QUARANTINE_HIGHWATER STREQUAL "")
	message("defining QUARANTINE_HIGHWATER=${QUARANTINE_HIGHWATER}")
	target_compile_definitions(mrs PRIVATE QUARANTINE_HIGHWATER=${QUARANTINE_HIGHWATER})
	set(VERSION_STRING "${VERSION_STRING} QUARANTINE_HIGHWATER=${QUARANTINE_HIGHWATER}")
endif()
if(NOT CONCURRENT_REVOCATION_PASSES STREQUAL "0")
	message("defining CONCURRENT_REVOCATION_PASSES=${CONCURRENT_REVOCATION_PASSES}")
	target_compile_definitions(mrs PRIVATE CONCURRENT_REVOCATION_PASSES=${CONCURRENT_REVOCATION_PASSES})
	set(VERSION_STRING "${VERSION_STRING} CONCURRENT_REVOCATION_PASSES=${CONCURRENT_REVOCATION_PASSES}")
endif()

if(NOT DEFINED GIT_SHA1_OVERRIDE)
  find_package(Git)
  execute_process(COMMAND
    "${GIT_EXECUTABLE}" describe --match=NeVeRmAtCh --always --abbrev=40 --dirty
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    OUTPUT_VARIABLE GIT_SHA1
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  set(VERSION_STRING "${VERSION_STRING} ${GIT_SHA1}\\n\"")
else()
  set(VERSION_STRING "${VERSION_STRING} ${GIT_SHA1_OVERRIDE}\\n\"")
endif()

target_compile_definitions(mrs PRIVATE VERSION_STRING=${VERSION_STRING})
