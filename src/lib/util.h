#ifndef ERI_LIB_UTIL_H
#define ERI_LIB_UTIL_H

#include <public/util.h>

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

#define ERI_LEA_MM(src, dst, reg) \
  leaq	src, reg;							\
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

#define ERI_INT_MAX	2147483647
#define ERI_INT_MIN	(-ERI_INT_MAX - 1)

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
    typeof (a) _a = a;							\
    typeof (b) _b = b;							\
    _a < _b ? _a : _b;							\
  })

#define eri_max(a, b) \
  ({									\
    typeof (a) _a = a;							\
    typeof (b) _b = b;							\
    _a > _b ? _a : _b;							\
  })

#define eri_hash(x) \
  ({									\
    uint64_t _x = x;							\
    _x = (_x ^ (_x >> 30)) * 0xbf58476d1ce4e5b9;			\
    _x = (_x ^ (_x >> 27)) * 0x94d049bb133111eb;			\
    _x ^ (_x >> 31);							\
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
    typeof (x) _x = x;							\
    typeof (_x) _m = (typeof (_x)) (mask);				\
    (_x + _m) & ~_m;							\
  })
#define eri_round_up(x, u) eri_round_up_mask (x, (u) - 1)
#define eri_round_down(x, u) ((x) & ~((u) - 1))

#define eri_length_of(x) (sizeof (x) / sizeof (x)[0])
#define eri_size_of(x, r) (eri_round_up (sizeof (x), r))

#define eri_struct_of(v, t, f) \
  ((t *) ((uint64_t) v - __builtin_offsetof (t, f)))

#define eri_itop(i)	((void *) (uint64_t) (i))

void eri_assert_itoa (uint64_t i, char *a, uint8_t base);
uint64_t eri_assert_atoi (const char *a, uint8_t base);
#define eri_itoa_size(i)	(3 * sizeof (i) + 1)

#define eri_get_arg_str(arg, key, val) \
  ({ char *_arg = arg;							\
     char *_key = key;							\
     char **_val = val;							\
     uint8_t _g = eri_strncmp (_arg, _key, eri_strlen (_key)) == 0;	\
     if (_g) *_val = _arg + eri_strlen (_key);				\
     _g; })

#define eri_get_arg_int(arg, key, val, base) \
  ({ char *_arg = arg;							\
     char *_key = key;							\
     typeof (val) _val = val;						\
     uint8_t _base = base;						\
     uint8_t _g = eri_strncmp (_arg, _key, eri_strlen (_key)) == 0;	\
     if (_g) *_val = eri_assert_atoi (_arg + eri_strlen (_key), _base);	\
     _g; })

struct eri_range
{
  uint64_t start, end;
};

#define eri_within(range, val) \
  ({ struct eri_range *_range = range; uint64_t _val = val;		\
     _val >= _range->start && _val < _range->end; })
#define eri_cross(range, val, len) \
  ({ struct eri_range *_range = range;					\
     uint64_t _val = val; uint64_t _len = len;				\
     _val + _len > _range->start && _val < _range->end;	})

#endif

#endif
