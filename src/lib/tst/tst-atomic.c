#include <stdint.h>

#include <lib/util.h>
#include <lib/atomic.h>

int
main (void)
{
  uint8_t u8;
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;

  eri_atomic_store (&u8, 1, 1);
  eri_atomic_store (&u16, 1, 1);
  eri_atomic_store (&u32, 1, 1);
  eri_atomic_store (&u64, 1, 1);

  eri_assert (eri_atomic_load (&u8, 1) == 1);
  eri_assert (eri_atomic_load (&u16, 1) == 1);
  eri_assert (eri_atomic_load (&u32, 1) == 1);
  eri_assert (eri_atomic_load (&u64, 1) == 1);

  u8 = 1;
  u16 = 1;
  u32 = 1;
  u64 = 1;

  eri_atomic_inc (&u8, 1);
  eri_atomic_inc (&u16, 1);
  eri_atomic_inc (&u32, 1);
  eri_atomic_inc (&u64, 1);

  eri_assert (u8 == 2);
  eri_assert (u16 == 2);
  eri_assert (u32 == 2);
  eri_assert (u64 == 2);

  u8 = 3;
  u16 = 3;
  u32 = 3;
  u64 = 3;

  eri_atomic_dec (&u8, 1);
  eri_atomic_dec (&u16, 1);
  eri_atomic_dec (&u32, 1);
  eri_atomic_dec (&u64, 1);

  eri_assert (u8 == 2);
  eri_assert (u16 == 2);
  eri_assert (u32 == 2);
  eri_assert (u64 == 2);

  u8 = -1;
  u16 = -1;
  u32 = -1;
  u64 = -1;

  eri_assert (eri_atomic_inc_fetch (&u8, 1) == 0);
  eri_assert (eri_atomic_inc_fetch (&u16, 1) == 0);
  eri_assert (eri_atomic_inc_fetch (&u32, 1) == 0);
  eri_assert (eri_atomic_inc_fetch (&u64, 1) == 0);

  eri_assert (eri_atomic_inc_fetch (&u8, 1) == 1);
  eri_assert (eri_atomic_inc_fetch (&u16, 1) == 1);
  eri_assert (eri_atomic_inc_fetch (&u32, 1) == 1);
  eri_assert (eri_atomic_inc_fetch (&u64, 1) == 1);

  u8 = 3;
  u16 = 3;
  u32 = 3;
  u64 = 3;

  eri_assert (eri_atomic_dec_fetch (&u8, 1) == 2);
  eri_assert (eri_atomic_dec_fetch (&u16, 1) == 2);
  eri_assert (eri_atomic_dec_fetch (&u32, 1) == 2);
  eri_assert (eri_atomic_dec_fetch (&u64, 1) == 2);

  eri_assert (eri_atomic_dec_fetch (&u8, 1) == 1);
  eri_assert (eri_atomic_dec_fetch (&u16, 1) == 1);
  eri_assert (eri_atomic_dec_fetch (&u32, 1) == 1);
  eri_assert (eri_atomic_dec_fetch (&u64, 1) == 1);

  u8 = -5;
  u16 = -5;
  u32 = -5;
  u64 = -5;

  eri_atomic_and (&u8, 9, 1);
  eri_atomic_and (&u16, 9, 1);
  eri_atomic_and (&u32, 9, 1);
  eri_atomic_and (&u64, 9, 1);

  eri_assert (u8 == 9);
  eri_assert (u16 == 9);
  eri_assert (u32 == 9);
  eri_assert (u64 == 9);

  int64_t s64 = -1;
  eri_atomic_and (&s64, 0xffffffff, 1);
  eri_assert (s64 == 0xffffffff);
  s64 = -1;
  eri_atomic_and (&s64, 0x100000000, 1);
  eri_assert (s64 == 0x100000000);
  s64 = -1;
  eri_atomic_and (&s64, -1, 1);
  eri_assert (s64 == -1);

  u16 = 2;
  u32 = 2;
  u64 = 2;

  eri_assert (! eri_atomic_bit_test_set (&u16, 0, 1));
  eri_assert (! eri_atomic_bit_test_set (&u32, 0, 1));
  eri_assert (! eri_atomic_bit_test_set (&u64, 0, 1));
  eri_assert (u16 == 3);
  eri_assert (u32 == 3);
  eri_assert (u64 == 3);

  u16 = 2;
  u32 = 2;
  u64 = 2;

  eri_assert (eri_atomic_bit_test_set (&u16, 1, 1));
  eri_assert (eri_atomic_bit_test_set (&u32, 1, 1));
  eri_assert (eri_atomic_bit_test_set (&u64, 1, 1));
  eri_assert (u16 == 2);
  eri_assert (u32 == 2);
  eri_assert (u64 == 2);

  u8 = 2;
  u16 = 2;
  u32 = 2;
  u64 = 2;

  eri_assert (eri_atomic_exchange (&u8, 1, 1) == 2);
  eri_assert (eri_atomic_exchange (&u16, 1, 1) == 2);
  eri_assert (eri_atomic_exchange (&u32, 1, 1) == 2);
  eri_assert (eri_atomic_exchange (&u64, 1, 1) == 2);
  eri_assert (u8 == 1);
  eri_assert (u16 == 1);
  eri_assert (u32 == 1);
  eri_assert (u64 == 1);

  u8 = 2;
  u16 = 2;
  u32 = 2;
  u64 = 2;

  eri_assert (eri_atomic_compare_exchange (&u8, 1, 3, 1) != 1);
  eri_assert (eri_atomic_compare_exchange (&u16, 1, 3, 1) != 1);
  eri_assert (eri_atomic_compare_exchange (&u32, 1, 3, 1) != 1);
  eri_assert (eri_atomic_compare_exchange (&u64, 1, 3, 1) != 1);
  eri_assert (u8 == 2);
  eri_assert (u16 == 2);
  eri_assert (u32 == 2);
  eri_assert (u64 == 2);

  u8 = 1;
  u16 = 1;
  u32 = 1;
  u64 = 1;

  eri_assert (eri_atomic_compare_exchange (&u8, 1, 3, 1) == 1);
  eri_assert (eri_atomic_compare_exchange (&u16, 1, 3, 1) == 1);
  eri_assert (eri_atomic_compare_exchange (&u32, 1, 3, 1) == 1);
  eri_assert (eri_atomic_compare_exchange (&u64, 1, 3, 1) == 1);
  eri_assert (u8 == 3);
  eri_assert (u16 == 3);
  eri_assert (u32 == 3);
  eri_assert (u64 == 3);

  return 0;
}
