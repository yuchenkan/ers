#ifndef ERI_LIB_UTIL_H
#define ERI_LIB_UTIL_H

#include <public/util.h>

#include <lib/compiler.h>

#define ERI_STR(...)		_ERS_STR (__VA_ARGS__)
#define ERI_PASTE(x, y)		_ERS_PASTE (x, y)
#define ERI_PASTE2(x, y, z)	ERI_PASTE (ERI_PASTE (x, y), z)

#define ERI_EMPTY
#define ERI_OMIT(...)

#define ERI_EVAL(...)		__VA_ARGS__
#define ERI_EVAL1(...)		__VA_ARGS__

#define ERI_MOV_LM(label, dst, reg) \
  leaq	label(%rip), reg;						\
  movq	reg, dst

#define ERI_MOV_MM(src, dst, reg) \
  movq	src, reg;							\
  movq	reg, dst

#define ERI_LEA_MM(src, dst, reg) \
  leaq	src, reg;							\
  movq	reg, dst

#define ERI_PP_IF(t, ...)	_ERS_PP_IF (t, ##__VA_ARGS__)

#define _ERI_PP_IIF_0(t, ...)		__VA_ARGS__
#define _ERI_PP_IIF_1(t, ...)		t
#define ERI_PP_IIF(c, t, ...) \
  ERI_PASTE (_ERI_PP_IIF_, c) (t, ##__VA_ARGS__)

#define _ERI_PP_NARGS_X(a, b, c, d, e, f, g, h, i, j, k, \
			l, m, n, o, p, q, r, s, ...) s
#define ERI_PP_NARGS(...) \
  _ERI_PP_NARGS_X (0, ##__VA_ARGS__, 17, 16, 15, 14, 13, 12, 11, 10, 9,	\
		   8, 7, 6, 5, 4, 3, 2, 1, 0)

#define ERI_PP_CONCAT(x, y)	(ERI_EVAL x, ERI_EVAL y)
#define ERI_PP_CONCAT1(x, y)	(ERI_EVAL1 x, ERI_EVAL1 y)

#define _ERI_PP_FOREACH_0(proc, args)
#define _ERI_PP_FOREACH_1(proc, args, a) \
  _ERI_PP_FOREACH_0 (proc, args)					\
  ERI_EVAL (proc ERI_PP_CONCAT ((0, a), args))
#define _ERI_PP_FOREACH_2(proc, args, a, b) \
  _ERI_PP_FOREACH_1 (proc, args, a)					\
  ERI_EVAL (proc ERI_PP_CONCAT ((1, b), args))
#define _ERI_PP_FOREACH_3(proc, args, a, b, c) \
  _ERI_PP_FOREACH_2 (proc, args, a, b)					\
  ERI_EVAL (proc ERI_PP_CONCAT ((2, c), args))
#define _ERI_PP_FOREACH_4(proc, args, a, b, c, d) \
  _ERI_PP_FOREACH_3 (proc, args, a, b, c)				\
  ERI_EVAL (proc ERI_PP_CONCAT ((3, d), args))
#define _ERI_PP_FOREACH_5(proc, args, a, b, c, d, e) \
  _ERI_PP_FOREACH_4 (proc, args, a, b, c, d)				\
  ERI_EVAL (proc ERI_PP_CONCAT ((4, e), args))
#define _ERI_PP_FOREACH_6(proc, args, a, b, c, d, e, f) \
  _ERI_PP_FOREACH_5 (proc, args, a, b, c, d, e)				\
  ERI_EVAL (proc ERI_PP_CONCAT ((5, f), args))
#define _ERI_PP_FOREACH_7(proc, args, a, b, c, d, e, f, g) \
  _ERI_PP_FOREACH_6 (proc, args, a, b, c, d, e, f)			\
  ERI_EVAL (proc ERI_PP_CONCAT ((6, g), args))
#define _ERI_PP_FOREACH_8(proc, args, a, b, c, d, e, f, g, h) \
  _ERI_PP_FOREACH_7 (proc, args, a, b, c, d, e, f, g)			\
  ERI_EVAL (proc ERI_PP_CONCAT ((7, h), args))
#define _ERI_PP_FOREACH_9(proc, args, a, b, c, d, e, f, g, h, i) \
  _ERI_PP_FOREACH_8 (proc, args, a, b, c, d, e, f, g, h)		\
  ERI_EVAL (proc ERI_PP_CONCAT ((8, i), args))
#define _ERI_PP_FOREACH_10(proc, args, a, b, c, d, e, f, g, h, i, j) \
  _ERI_PP_FOREACH_9 (proc, args, a, b, c, d, e, f, g, h, i)		\
  ERI_EVAL (proc ERI_PP_CONCAT ((9, j), args))
#define _ERI_PP_FOREACH_11(proc, args, a, b, c, d, e, f, g, h, i, j, k) \
  _ERI_PP_FOREACH_10 (proc, args, a, b, c, d, e, f, g, h, i, j)		\
  ERI_EVAL (proc ERI_PP_CONCAT ((10, k), args))
#define _ERI_PP_FOREACH_12(proc, args, a, b, c, d, e, f, g, h, i, j, k, \
			   l) \
  _ERI_PP_FOREACH_11 (proc, args, a, b, c, d, e, f, g, h, i, j, k)	\
  ERI_EVAL (proc ERI_PP_CONCAT ((11, l), args))
#define _ERI_PP_FOREACH_13(proc, args, a, b, c, d, e, f, g, h, i, j, k, \
			   l, m) \
  _ERI_PP_FOREACH_12 (proc, args, a, b, c, d, e, f, g, h, i, j, k, l)	\
  ERI_EVAL (proc ERI_PP_CONCAT ((12, m), args))
#define _ERI_PP_FOREACH_14(proc, args, a, b, c, d, e, f, g, h, i, j, k, \
			   l, m, n) \
  _ERI_PP_FOREACH_13 (proc, args, a, b, c, d, e, f, g, h, i, j, k, l,	\
		      m)						\
  ERI_EVAL (proc ERI_PP_CONCAT ((13, n), args))
#define _ERI_PP_FOREACH_15(proc, args, a, b, c, d, e, f, g, h, i, j, k, \
			   l, m, n, o) \
  _ERI_PP_FOREACH_14 (proc, args, a, b, c, d, e, f, g, h, i, j, k, l,	\
		      m, n)						\
  ERI_EVAL (proc ERI_PP_CONCAT ((14, o), args))
#define _ERI_PP_FOREACH_16(proc, args, a, b, c, d, e, f, g, h, i, j, k, \
			  l, m, n, o, p) \
  _ERI_PP_FOREACH_15 (proc, args, a, b, c, d, e, f, g, h, i, j, k, l,	\
		      m, n, o)						\
  ERI_EVAL (proc ERI_PP_CONCAT ((15, p), args))

#define ERI_PP_FOREACH(proc, args, ...) \
  ERI_PASTE (_ERI_PP_FOREACH_, ERI_PP_NARGS (__VA_ARGS__)) (		\
					proc, args, ##__VA_ARGS__)

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

#define eri_xassert(exp, log, ...) \
  do { if (! (exp))							\
	 {								\
	   log (ERI_STR (exp) "\n", ##__VA_ARGS__);			\
	   asm ("ud2");							\
	 } } while (0)

#ifndef eri_assert
# define eri_assert(exp) \
  do {									\
    if (! (exp)) {							\
      register const char *_file asm ("r14") = __FILE__;		\
      register uint64_t _line asm ("r15") = __LINE__;			\
      asm ("ud2" : : "r" (_file), "r" (_line) : "memory");		\
    }									\
  } while (0)

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

#define eri_swap(a, b) \
  do {									\
    typeof (a) _a = a;							\
    typeof (*_a) _t = *_a;						\
    typeof (_a) _b = b;							\
    *_a = *_b;								\
    *_b = _t;								\
  } while (0)

#define eri_abs(a) \
  ({									\
    typeof (a) _a = a;							\
    _a >= 0 ? _a : -_a;							\
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
  ({ const struct eri_range *_range = range; uint64_t _val = val;	\
     _val >= _range->start && _val < _range->end; })
#define eri_across(range, val, len) \
  ({ const struct eri_range *_range = range;				\
     uint64_t _val = val; uint64_t _len = len;				\
     _val + _len > _range->start && _val < _range->end;	})

struct eri_pair
{
  uint64_t first, second;
};

#define eri_hash(x) \
  ({									\
    uint64_t _x = x;							\
    _x = (_x ^ (_x >> 30)) * 0xbf58476d1ce4e5b9;			\
    _x = (_x ^ (_x >> 27)) * 0x94d049bb133111eb;			\
    _x ^ (_x >> 31);							\
  })

#define eri_hashs1(h, ...) \
  ({									\
    uint64_t _a[] = { __VA_ARGS__ };					\
    uint64_t _h = h;							\
    uint32_t _i;							\
    for (_i = 0; _i < eri_length_of (_a); ++_i)				\
      _h = eri_hash (_h + _a[_i]);					\
    _h;									\
  })

#define eri_hashs(...)	eri_hashs1 (eri_hash (0), ##__VA_ARGS__)

struct _eri_memory_size
{
  uint64_t size;
  void **p;
};

static eri_unused void *
_eri_memory_layout (void *base, struct _eri_memory_size *sizes, uint64_t n)
{
  uint8_t *p = base;
  uint64_t i;
  for (i = 0; i < n; ++i)
    {
      if (sizes[i].p) *sizes[i].p = p;
      p += sizes[i].size;
    }
  return p;
}

#define __ERI_MEMORY_SIZE(s, p)		{ s, (void **) (p) },
#define _ERI_MEMORY_SIZE(i, sp, a)	__ERI_MEMORY_SIZE sp

#define eri_memory_layout(base, ...) \
  ({									\
    struct _eri_memory_size _sizes[] = {				\
      ERI_PP_FOREACH (_ERI_MEMORY_SIZE, (_), ##__VA_ARGS__)		\
    };									\
    _eri_memory_layout (base, _sizes, eri_length_of (_sizes));		\
  })

#endif

#endif
