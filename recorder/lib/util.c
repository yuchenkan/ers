#include "util.h"

void
ers_memset (void *p, char c, size_t s)
{
  size_t i;
  char *b = (char *) p;
  for (i = 0; i < s; ++i) b[i] = c;
}

char
ers_strncmp (const char *s1, const char *s2, size_t n)
{
  size_t i;
  for (i = 0; i < n; ++i)
    {
      if (s1[i] < s2[i]) return -1;
      else if (s1[i] > s2[i]) return 1;
      if (s1[i] == '\0') break;
    }
  return 0;
}
