#ifndef ERI_ASSERT_H
#define ERI_ASSERT_H

#include <stddef.h>

#define eri_assert(exp) do { if (! (exp)) *((char *) 0) = 0; } while (0)

#define eri_min(a, b) \
  ({				\
    typeof (a) __a = a;		\
    typeof (b) __b = b;		\
    __a < __b ? __a : __b;	\
  })

#define eri_max(a, b) \
  ({				\
    typeof (a) __a = a;		\
    typeof (b) __b = b;		\
    __a > __b ? __a : __b;	\
  })

void eri_memset (void *p, char c, size_t s);

#endif
