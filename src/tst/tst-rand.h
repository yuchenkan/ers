#ifndef TST_TST_TST_RAND_H
#define TST_TST_TST_RAND_H

#include <stdint.h>

#include <lib/printf.h>
#include <tst/tst-syscall.h>

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

#define tst_rand_init(rand, seed) \
  do {									\
    uint64_t _seed = seed;						\
    _seed = _seed ? : tst_assert_syscall (gettid);			\
    eri_fprintf (ERI_STDERR, "seed = %lu\n", _seed);			\
    tst_rand_seed (rand, _seed);					\
  } while (0)

void tst_rand_fill (struct tst_rand *rand, void *buf, uint64_t size);

#endif
