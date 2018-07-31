#ifndef ERS_ASSERT_H
#define ERS_ASSERT_H

#include <stddef.h>

#define ers_assert(exp) do { if (! (exp)) *((char *) 0) = 0; } while (0)

#define ers_min(a, b) \
  ({				\
    typeof (a) __a = a;		\
    typeof (b) __b = b;		\
    __a < __b ? __a : __b;	\
  })

#define ers_max(a, b) \
  ({				\
    typeof (a) __a = a;		\
    typeof (b) __b = b;		\
    __a > __b ? __a : __b;	\
  })

void ers_memset (void *p, char c, size_t s);

#endif
