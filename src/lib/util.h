#ifndef ERI_LIB_UTIL_H
#define ERI_LIB_UTIL_H

#include "public/comm.h"

#define _ERI_PP_IF_0(...)
#define _ERI_PP_IF_1(...)	__VA_ARGS__
#define ERI_PP_IF(c, ...)	_ERS_PASTE (_ERI_PP_IF_, c) (__VA_ARGS__)

#define _ERI_PP_IIF_0(t, f)	f
#define _ERI_PP_IIF_1(t, f)	t
#define ERI_PP_IIF(c, t, f)	_ERS_PASTE (_ERI_PP_IIF_, c) (t, f)

#ifdef __ASSEMBLER__

#define ERI_ASSERT_FALSE \
  movq	$0, %r15;		\
  movq	$0, (%r15)

#else

#include <stdint.h>

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

#ifndef ERI_FUNC_ATTR
# define ERI_FUNC_ATTR
#endif

ERI_FUNC_ATTR void eri_memset (void *s, char c, uint64_t n);
ERI_FUNC_ATTR void eri_memcpy (void *d, const void *s, uint64_t n);
ERI_FUNC_ATTR void eri_memmove (void *d, const void *s, uint64_t n);
ERI_FUNC_ATTR int8_t eri_memcmp (const void *s1, const void *s2, uint64_t n);
ERI_FUNC_ATTR uint64_t eri_strlen (const char *s);
ERI_FUNC_ATTR void eri_strcpy (char *d, const char *s);
ERI_FUNC_ATTR void eri_strncat (char *d, const char *s, uint64_t n);
ERI_FUNC_ATTR int8_t eri_strcmp (const char *s1, const char *s2);
ERI_FUNC_ATTR int8_t eri_strncmp (const char *s1, const char *s2, uint64_t n);
ERI_FUNC_ATTR const char *eri_strtok (const char *s, char d);
ERI_FUNC_ATTR const char *eri_strntok (const char *s, char d, uint64_t n);
ERI_FUNC_ATTR const char *eri_strstr (const char *s, const char *d);
ERI_FUNC_ATTR const char *eri_strnstr (const char *s, const char *d, uint64_t n);

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

#endif
