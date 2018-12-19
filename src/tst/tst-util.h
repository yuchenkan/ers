#ifndef TST_TST_UTIL_H
#define TST_TST_UTIL_H

#include <stdint.h>

struct tst_rand
{
  uint64_t val;
};

void tst_rand_seed (struct tst_rand *rand, uint64_t seed);
uint64_t tst_rand_next (struct tst_rand *rand);
void tst_rand_fill (struct tst_rand *rand, void *buf, uint64_t size);

#define TST_RFLAGS_STATUS_MASK	0xd5

#endif
