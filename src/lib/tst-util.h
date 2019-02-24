#ifndef TST_LIB_TST_UTIL_H
#define TST_LIB_TST_UTIL_H

#include <stdint.h>

#include <lib/syscall.h>
#include <lib/printf.h>

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

#define tst_rand_init(rand) \
  do {									\
    uint64_t _seed = eri_assert_syscall (gettid);			\
    eri_assert_gprintf ("seed = %lu\n", _seed);				\
    tst_rand_seed (rand, _seed);					\
  } while (0)

void tst_rand_fill (struct tst_rand *rand, void *buf, uint64_t size);

#endif
