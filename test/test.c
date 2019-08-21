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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <cheri/cheric.h>

/* expects revocation to happen immediately (no quarantine, no offload) */
void uaf_basic_sub16() {
  void *buffer = malloc(1);
  assert(cheri_gettag(buffer));
  free(buffer);
  assert(!cheri_gettag(buffer));
}

/* expects revocation to happen immediately (no quarantine, no offload) */
void uaf_basic_16() {
  void *buffer = malloc(16);
  assert(cheri_gettag(buffer));
  free(buffer);
  assert(!cheri_gettag(buffer));
}

/* should trigger debug statements */
void free_pages() {
  void *buffer = malloc(0x1000);
  free(buffer);
  buffer = malloc(0x2000);
  free(buffer);
}

/* expects revocation not to happen (doesn't fill quarantine) */
void uaf_low_water() {
  void *buffer = malloc(1);
  assert(cheri_gettag(buffer));
  free(buffer);
  assert(cheri_gettag(buffer));
}

/* expects revocation to happen (fills quarantine of size 1024, no offload) */
void uaf_high_water() {
  void *buffer1 = malloc(1);
  assert(cheri_gettag(buffer1));
  free(buffer1);
  assert(cheri_gettag(buffer1));
  void *buffer2 = malloc(1024);
  assert(cheri_gettag(buffer2));
  free(buffer2);
  assert(!cheri_gettag(buffer2));
}

/* expects revocation to be offloaded (fills quarantine of size 1024, waits for it to work) */
void uaf_high_water_offload() {
  void *buffer1 = malloc(1);
  assert(cheri_gettag(buffer1));
  free(buffer1);
  assert(cheri_gettag(buffer1));
  void *buffer2 = malloc(1024);
  assert(cheri_gettag(buffer2));
  free(buffer2);
  assert(cheri_gettag(buffer2));
  sleep(1);
  assert(!cheri_gettag(buffer2));
}

/* basic stress test with many mallocs and frees */
void basic_stress_test(int num_allocs) {
  void **allocs = malloc(sizeof(void *) * num_allocs);
  int i = 0;
  while (i < num_allocs) {
    allocs[i] = malloc(1024);
    i++;
  }
  while (i > 0) {
    free(allocs[i - 1]);
    i--;
  }
  free(allocs);
}


int main(int argc, char *argv[]) {
  printf("mrs test start\n");
  /*uaf_basic_sub16();*/
  /*uaf_basic_16();*/
  /*free_pages();*/
  /*uaf_printf();*/
  /*uaf_low_water();*/
  /*uaf_high_water();*/
  /*uaf_high_water_offload();*/
  basic_stress_test(1024 * 16);
  printf("mrs test end\n");
}
