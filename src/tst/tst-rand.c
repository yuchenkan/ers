#include <lib/util.h>
#include <tst/tst-rand.h>

uint64_t
tst_rand_next (struct tst_rand *rand)
{
  rand->val ^= rand->val << 13;
  rand->val ^= rand->val >> 7;
  rand->val ^= rand->val << 17;
  return rand->val;
}

void
tst_rand_seed (struct tst_rand *rand, uint64_t seed)
{
  rand->val = seed * seed * seed * seed;
  tst_rand_next (rand);
}

void
tst_rand_fill (struct tst_rand *rand, void *buf, uint64_t size)
{
  uint64_t i;
  for (i = 0; i < size / sizeof i; ++i)
    *(uint64_t *) ((uint8_t *) buf + i * sizeof i) = tst_rand_next (rand);
  if (size % sizeof i)
    {
      uint64_t v = tst_rand_next (rand);
      eri_memcpy ((uint8_t *) buf + i * 8, &v, size % sizeof i);
    }
}
