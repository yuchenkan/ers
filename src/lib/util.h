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

void eri_memset (void *s, char c, size_t n);
void eri_memcpy (void *d, const void *s, size_t n);
void eri_memmove (void *d, const void *s, size_t n);
char eri_memcmp (const void *s1, const void *s2, size_t n);
size_t eri_strlen (const char *s);
void eri_strcpy (char *d, const char *s);
void eri_strncat (char *d, const char *s, size_t n);
char eri_strcmp (const char *s1, const char *s2);
char eri_strncmp (const char *s1, const char *s2, size_t n);
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
#define eri_round_down(x, u) ((x) & ~((u) - 1))

#define eri_less_than(x, a, b) (*(a) < *(b))

#define eri_length_of(x) (sizeof (x) / sizeof (x)[0])

#define eri_size_of(x, r) (eri_round_up (sizeof (x), r))

#endif
