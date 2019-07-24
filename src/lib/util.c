#include <lib/util.h>

void
eri_assert_itoa (uint64_t i, char *a, uint8_t base)
{
  eri_assert (base == 16 || base == 10);

  if (i == 0)
    {
      a[0] = '0';
      a[1] = '\0';
      return;
    }

  uint64_t v = i;
  uint8_t c;
  for (c = 0; v; v /= base) ++c;

  static const char digits[] = "0123456789abcdef";

  a[c--] = '\0';
  do
    a[c--] = digits[i % base];
  while (i /= base);
}

uint64_t
eri_assert_atoi (const char *a, uint8_t base)
{
  eri_assert (base == 16 || base == 10);
  uint64_t i = 0;
  for (; *a; ++a)
    {
      uint8_t v = 0;
      if (*a >= '0' && *a <= '9') v = *a - '0';
      else if (*a >= 'a' && *a <= 'f')
	{
	  eri_assert (base == 16);
	  v = *a - 'a' + 10;
	}
      else eri_assert_unreachable ();
      i = i * base + v;
    }
  return i;
}
