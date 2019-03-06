#ifndef ERI_LIB_UTIL_H
#define ERI_LIB_UTIL_H

#include <public/common.h>

#define ERI_STR(...)		_ERS_STR (__VA_ARGS__)
#define ERI_PASTE(x, y)		_ERS_PASTE (x, y)
#define ERI_PASTE2(x, y, z)	ERI_PASTE (ERI_PASTE (x, y), z)

#define ERI_PP_IF(t, ...)	_ERS_PP_IF (t, ##__VA_ARGS__)

#define ERI_EMPTY
#define ERI_EVAL(...)		__VA_ARGS__

#define ERI_MOV_LM(label, dst, reg) \
  leaq	label(%rip), reg;						\
  movq	reg, dst

#define ERI_MOV_MM(src, dst, reg) \
  movq	src, reg;							\
  movq	reg, dst

#define _ERI_PP_IIF_0(t, ...)		__VA_ARGS__
#define _ERI_PP_IIF_1(t, ...)		t
#define ERI_PP_IIF(c, t, ...) \
  ERI_PASTE (_ERI_PP_IIF_, c) (t, ##__VA_ARGS__)

#if 0
#define ERI_OMIT(...)
#endif

#define ERI_SYMBOL(symbol) \
  .global symbol;							\
  .hidden symbol;							\
symbol:

#define ERI_FUNCTION(func) \
  .align 16;								\
  .global func;								\
  .hidden func;								\
  .type func, @function;						\
func:

#define ERI_STATIC_FUNCTION(func) \
  .align 16;								\
  .type func, @function;						\
func:

#define ERI_END_FUNCTION(func) \
  .size func, . - func

#define ERI_ASSERT_FALSE \
  movq	$0, %r15;							\
  movq	$0, (%r15)

#ifndef __ASSEMBLER__

#include <stdint.h>

#ifndef eri_assert
# define eri_assert(exp) \
  do { if (! (exp))							\
	 asm ("movq $0, %%r15; movl $0, (%%r15);" : : : "r15"); } while (0)
#endif

#define eri_assert_unreachable() \
  do { eri_assert (0); __builtin_unreachable (); } while (0)

#define eri_min(a, b) \
  ({									\
    typeof (a) __a = a;							\
    typeof (b) __b = b;							\
    __a < __b ? __a : __b;						\
  })

#define eri_max(a, b) \
  ({									\
    typeof (a) __a = a;							\
    typeof (b) __b = b;							\
    __a > __b ? __a : __b;						\
  })

void eri_memset (void *s, char c, uint64_t n);
void eri_memcpy (void *d, const void *s, uint64_t n);
void eri_memmove (void *d, const void *s, uint64_t n);
int8_t eri_memcmp (const void *s1, const void *s2, uint64_t n);
uint64_t eri_strlen (const char *s);
void eri_strcpy (char *d, const char *s);
void eri_strncat (char *d, const char *s, uint64_t n);
int8_t eri_strcmp (const char *s1, const char *s2);
int8_t eri_strncmp (const char *s1, const char *s2, uint64_t n);
const char *eri_strtok (const char *s, char d);
const char *eri_strntok (const char *s, char d, uint64_t n);
const char *eri_strstr (const char *s, const char *d);
const char *eri_strnstr (const char *s, const char *d, uint64_t n);

#define eri_round_up_mask(x, mask) \
  ({									\
    typeof (x) __x = x;							\
    typeof (__x) __m = (typeof (__x)) (mask);				\
    (__x + __m) & ~__m;							\
  })
#define eri_round_up(x, u) eri_round_up_mask (x, (u) - 1)
#define eri_round_down(x, u) ((x) & ~((u) - 1))

#define eri_length_of(x) (sizeof (x) / sizeof (x)[0])

#define eri_size_of(x, r) (eri_round_up (sizeof (x), r))

#endif

#endif
