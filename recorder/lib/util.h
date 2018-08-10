#ifndef ERS_ASSERT_H
#define ERS_ASSERT_H

#include <stddef.h>

#define ERS_EXPAND(x) #x
#define ERS_STRINGIFY(x) ERS_EXPAND (x)

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
void ers_memcpy (void *d, const void *s, size_t n);
size_t ers_strlen (const char *s);
void ers_strcpy (char *d, const char *s);
#define ers_strncmp __builtin_strncmp

#endif
