#ifndef ERI_ASSERT_H
#define ERI_ASSERT_H

#include <stddef.h>

#define ERI_EXPAND(x) #x
#define ERI_STRINGIFY(x) ERI_EXPAND (x)

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
void eri_memcpy (void *d, const void *s, size_t n);
size_t eri_strlen (const char *s);
void eri_strcpy (char *d, const char *s);
#define eri_strncmp __builtin_strncmp

#endif
