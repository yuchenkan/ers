#ifndef ERI_ASSERT_H
#define ERI_ASSERT_H

#include <stddef.h>

#define eri_assert(exp) do { if (! (exp)) asm ("movq $0, %r15; movl $0, (%r15);"); } while (0)

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
char eri_strncmp (const char *s1, const char *s2, size_t n);
#define eri_strcmp __builtin_strcmp
const char *eri_strtok (const char *s, char d);
const char *eri_strntok (const char *s, char d, size_t n);
const char *eri_strstr (const char *s, const char *d);

#define eri_round_up_mask(x, mask) \
  ({						\
    typeof (x) __x = x;				\
    typeof (__x) __m = (typeof (__x)) (mask);	\
    (__x + __m) & ~__m;				\
  })
#define eri_round_up(x, u) eri_round_up_mask (x, (u) - 1)

#define eri_less_than(x, a, b) (*(a) < *(b))


#endif
