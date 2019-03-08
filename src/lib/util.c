#include <lib/util.h>

void
eri_memset (void *s, char c, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n; ++i) ((char *) s)[i] = c;
}

void
eri_memcpy (void *d, const void *s, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n; ++i) ((char *) d)[i] = ((const char *) s)[i];
}

void
eri_memmove (void *d, const void *s, uint64_t n)
{
  char *cd = (char *) d;
  const char *cs = (const char *) s;
  uint64_t i;
  if (cd == cs) return;
  else if (cd + n <= cs || cs + n <= cd)
    eri_memcpy (d, s, n);
  else if (cd + n > cs)
    for (i = 0; i < n; ++i) cd[i] = cs[i];
  else
    for (i = n - 1; i >= 0; --i) cd[i] = cs[i];
}

int8_t
eri_memcmp (const void *s1, const void *s2, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n; ++i)
    if (((const uint8_t *) s1)[i] < ((const uint8_t *) s2)[i]) return -1;
    else if (((const uint8_t *) s1)[i] > ((const uint8_t *) s2)[i]) return 1;
  return 0;
}

uint64_t
eri_strlen (const char *s)
{
  uint64_t i;
  for (i = 0; s[i]; ++i) continue;
  return i;
}

void
eri_strcpy (char *d, const char *s)
{
  while (*s) *d++ = *s++;
  *d = '\0';
}

void
eri_strncat (char *d, const char *s, uint64_t n)
{
  d = d + eri_strlen (d);
  uint64_t i;
  for (i = 0; i < n && *s; ++i) *d++ = *s++;
  *d = '\0';
}

int8_t
eri_strcmp (const char *s1, const char *s2)
{
  uint64_t i;
  for (i = 0; ; ++i)
    {
      if (s1[i] < s2[i]) return -1;
      else if (s1[i] > s2[i]) return 1;
      if (s1[i] == '\0') return 0;
    }
}

int8_t
eri_strncmp (const char *s1, const char *s2, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n; ++i)
    {
      if (s1[i] < s2[i]) return -1;
      else if (s1[i] > s2[i]) return 1;
      if (s1[i] == '\0') break;
    }
  return 0;
}

const char *
eri_strtok (const char *s, char d)
{
  while (*s && *s != d) ++s;
  return *s ? s : 0;
}

const char *
eri_strntok (const char *s, char d, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n && s[i] != d; ++i)
    continue;
  return i < n ? s + i : 0;
}

const char *
eri_strstr (const char *s, const char *d)
{
  return eri_strnstr (s, d, eri_strlen (s));
}

const char *
eri_strnstr (const char *s, const char *d, uint64_t n)
{
  uint64_t dl = eri_strlen (d);
  uint64_t i;
  for (i = 0; i <= n - dl; ++i)
    if (eri_strncmp (s + i, d, dl) == 0)
      return s + i;
  return 0;
}

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
eri_assert_atoi (char *a, uint8_t base)
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
      else eri_assert (0);
      i = i * base + v;
    }
  return i;
}
