#ifndef TST_LIB_TST_UTIL_H
#define TST_LIB_TST_UTIL_H

#include "lib/util.h"

#ifdef __ASSEMBLER__

#define TST_WEAK_GLOBAL_HIDDEN(symbol) \
  .weak symbol;								\
  ERI_GLOBAL_HIDDEN (symbol)

#else

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

#endif
