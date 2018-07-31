#include "util.h"

void
eri_memset (void *p, char c, size_t s)
{
  size_t i;
  char *b = (char *) p;
  for (i = 0; i < s; ++i) b[i] = c;
}
