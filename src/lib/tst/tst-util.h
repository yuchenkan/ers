#ifndef TST_LIB_TST_UTIL_H
#define TST_LIB_TST_UTIL_H

#include "lib/util.h"

#ifdef __ASSEMBLER__

#define TST_WEAK_GLOBAL_HIDDEN(symbol) \
  .weak symbol;								\
  ERI_GLOBAL_HIDDEN (symbol)

#else

#include <stdint.h>

#include "lib/printf.h"

#ifdef TST_VERBOSE
# define tst_printf(...)	eri_assert_printf (__VA_ARGS__)
#else
# define tst_printf(...)
#endif

struct tst_rand
{
  uint64_t val;
};

void tst_rand_seed (struct tst_rand *rand, uint64_t seed);
uint64_t tst_rand_next (struct tst_rand *rand);
void tst_rand_fill (struct tst_rand *rand, void *buf, uint64_t size);

#define TST_YIELD(n) \
  do {									\
    typeof (n) _i;							\
    typeof (n) _n = n;							\
    for (_i = 0; _i < _n; ++_i) ERI_ASSERT_SYSCALL (sched_yield);	\
  } while (0)

int32_t tst_create_thread (uint8_t *stack, int32_t *ctid,
			   void (*fn) (void *), void *data);

#define TST_RFLAGS_STATUS_MASK	0xd5

#endif

#endif
