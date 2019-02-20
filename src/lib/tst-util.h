#ifndef TST_LIB_TST_UTIL_H
#define TST_LIB_TST_UTIL_H

#include <stdint.h>

#include <lib/syscall.h>

struct tst_rand
{
  uint64_t val;
};

void tst_rand_seed (struct tst_rand *rand, uint64_t seed);
uint64_t tst_rand_next (struct tst_rand *rand);

#define tst_rand(rand, min, max) \
  ({									\
    typeof (min) _min = min; 						\
    _min + tst_rand_next (rand) % ((max) - _min);			\
  })

void tst_rand_fill (struct tst_rand *rand, void *buf, uint64_t size);

#define tst_yield(n) \
  do {									\
    typeof (n) _i;							\
    typeof (n) _n = n;							\
    for (_i = 0; _i < _n; ++_i) eri_assert_syscall (sched_yield);	\
  } while (0)

#endif
