#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <cheri/cheric.h>

/* expects revocation to happen immediately (no quarantine, no offload) */
void uaf_basic_sub16() {
  char *buffer = (char *)malloc(1);
  assert(cheri_gettag(buffer));
  free(buffer);
  assert(!cheri_gettag(buffer));
}

/* expects revocation to happen immediately (no quarantine, no offload) */
void uaf_basic_16() {
  char *buffer = (char *)malloc(16);
  assert(cheri_gettag(buffer));
  free(buffer);
  assert(!cheri_gettag(buffer));
}

/* should trigger debug statements */
void free_pages() {
  char *buffer = (char *)malloc(0x1000);
  free(buffer);
  buffer = (char *)malloc(0x2000);
  free(buffer);
}

/* expects revocation not to happen (doesn't fill quarantine) */
void uaf_low_water() {
  char *buffer = (char *)malloc(1);
  assert(cheri_gettag(buffer));
  free(buffer);
  assert(cheri_gettag(buffer));
}

/* expects revocation to happen (fills quarantine of size 1024, no offload) */
void uaf_high_water() {
  char *buffer1 = (char *)malloc(1);
  assert(cheri_gettag(buffer1));
  free(buffer1);
  assert(cheri_gettag(buffer1));
  char *buffer2 = (char *)malloc(1024);
  assert(cheri_gettag(buffer2));
  free(buffer2);
  assert(!cheri_gettag(buffer2));
}

/* expects revocation to be offloaded (fills quarantine of size 1024, waits for it to work) */
void uaf_high_water_offload() {
  char *buffer1 = (char *)malloc(1);
  assert(cheri_gettag(buffer1));
  free(buffer1);
  assert(cheri_gettag(buffer1));
  char *buffer2 = (char *)malloc(1024);
  assert(cheri_gettag(buffer2));
  free(buffer2);
  assert(cheri_gettag(buffer2));
  sleep(1);
  assert(!cheri_gettag(buffer2));
}


int main(int argc, char *argv[]) {
  printf("mrs test start\n");
  uaf_basic_sub16();
  uaf_basic_16();
  free_pages();
  /*uaf_printf();*/
  /*uaf_low_water();*/
  /*uaf_high_water();*/
  /*uaf_high_water_offload();*/
  printf("mrs test end\n");
}
