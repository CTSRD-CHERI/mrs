cmake_minimum_required(VERSION 3.12.4)
project(mrs C CXX)

#################
# BUILD TARGETS #
#################

# build mrs
add_library(mrs SHARED mrs.c mrs-new.cc printf.c)
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
option(BYPASS_QUARANTINE "MADV_FREE freed page-size allocations" OFF)
option(CLEAR_ALLOCATIONS "zero out allocations made by malloc" OFF)
option(CONCURRENT_REVOCATION_PASS "enable a concurrent revocation pass before the stop-the-world pass" OFF)
option(REVOKE_ON_FREE "perform revocation on free rather than during allocation routines" OFF)

option(JUST_INTERPOSE "just call the real functions" OFF)
option(JUST_BOOKKEEPING "just update data structures then call the real functions" OFF)
option(JUST_QUARANTINE "just do bookkeeping and quarantining (no bitmap painting or revocation)" OFF)
option(JUST_PAINT_BITMAP "do bookkeeping, quarantining, and bitmap painting but no revocation" OFF)

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
if(BYPASS_QUARANTINE)
	message("defining BYPASS_QUARANTINE")
	target_compile_definitions(mrs PRIVATE BYPASS_QUARANTINE)
	set(VERSION_STRING "${VERSION_STRING} BYPASS_QUARANTINE")
endif()
if(CLEAR_ALLOCATIONS)
	message("defining CLEAR_ALLOCATIONS")
	target_compile_definitions(mrs PRIVATE CLEAR_ALLOCATIONS)
	set(VERSION_STRING "${VERSION_STRING} CLEAR_ALLOCATIONS")
endif()
if(CONCURRENT_REVOCATION_PASS)
	message("defining CONCURRENT_REVOCATION_PASS")
	target_compile_definitions(mrs PRIVATE CONCURRENT_REVOCATION_PASS)
	set(VERSION_STRING "${VERSION_STRING} CONCURRENT_REVOCATION_PASS")
endif()
if(REVOKE_ON_FREE)
	message("defining REVOKE_ON_FREE")
	target_compile_definitions(mrs PRIVATE REVOKE_ON_FREE)
	set(VERSION_STRING "${VERSION_STRING} REVOKE_ON_FREE")
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

find_package(Git)
execute_process(COMMAND
  "${GIT_EXECUTABLE}" describe --match=NeVeRmAtCh --always --abbrev=40 --dirty
  WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_SHA1
  OUTPUT_STRIP_TRAILING_WHITESPACE)
set(VERSION_STRING "${VERSION_STRING} ${GIT_SHA1}\\n\"")

target_compile_definitions(mrs PRIVATE VERSION_STRING=${VERSION_STRING})
