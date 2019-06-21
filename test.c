#include <stdlib.h>
#include <sys/types.h>
#include "mrs.h"

int main() {
  void *ptr = malloc(0xfa);
  free(ptr);

  return 0;
}
