#include <lib/util.h>

#define tst_itoa(i, b, e) \
  do {									\
    typeof (i) _i = i;							\
    uint8_t _b = b;							\
    char _a[eri_itoa_len (_i)];						\
    eri_assert_itoa (_i, _a, _b);					\
    eri_assert (eri_strcmp (_a, e) == 0);				\
    eri_assert (eri_assert_atoi (_a, _b) == _i);			\
  } while (0)

int
main (void)
{
  tst_itoa (0, 10, "0");
  tst_itoa (0, 16, "0");
  tst_itoa (1, 10, "1");
  tst_itoa (1, 16, "1");
  tst_itoa (10, 10, "10");
  tst_itoa (10, 16, "a");
  tst_itoa (16, 10, "16");
  tst_itoa (16, 16, "10");
  tst_itoa (123, 10, "123");
  tst_itoa (123, 16, "7b");
  return 0;
}
