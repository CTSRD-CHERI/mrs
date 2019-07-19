#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <cheri/cheric.h>

void uaf_low_water() {
  char *buffer = (char *)malloc(1);
  assert(cheri_gettag(buffer));
  free(buffer);
  assert(cheri_gettag(buffer));
}

void uaf_high_water() {
  char *buffer1 = (char *)malloc(1024);
  assert(cheri_gettag(buffer1));
  free(buffer1);
  assert(cheri_gettag(buffer1));
  char *buffer2 = (char *)malloc(1024);
  assert(cheri_gettag(buffer2));
  free(buffer2);
  assert(!cheri_gettag(buffer2));
}

int main(int argc, char *argv[]) {
  uaf_low_water();
  uaf_high_water();
  uaf_high_water();
}
