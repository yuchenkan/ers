#include "lib/util.h"

ERI_FUNC_ATTR void
eri_memset (void *s, char c, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n; ++i) ((char *) s)[i] = c;
}

ERI_FUNC_ATTR void
eri_memcpy (void *d, const void *s, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n; ++i) ((char *) d)[i] = ((const char *) s)[i];
}

ERI_FUNC_ATTR void
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

ERI_FUNC_ATTR int8_t
eri_memcmp (const void *s1, const void *s2, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n; ++i)
    if (((const uint8_t *) s1)[i] < ((const uint8_t *) s2)[i]) return -1;
    else if (((const uint8_t *) s1)[i] > ((const uint8_t *) s2)[i]) return 1;
  return 0;
}

ERI_FUNC_ATTR uint64_t
eri_strlen (const char *s)
{
  uint64_t i;
  for (i = 0; s[i]; ++i) continue;
  return i;
}

ERI_FUNC_ATTR void
eri_strcpy (char *d, const char *s)
{
  while (*s) *d++ = *s++;
  *d = '\0';
}

ERI_FUNC_ATTR void
eri_strncat (char *d, const char *s, uint64_t n)
{
  d = d + eri_strlen (d);
  uint64_t i;
  for (i = 0; i < n && *s; ++i) *d++ = *s++;
  *d = '\0';
}

ERI_FUNC_ATTR int8_t
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

ERI_FUNC_ATTR int8_t
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

ERI_FUNC_ATTR const char *
eri_strtok (const char *s, char d)
{
  while (*s && *s != d) ++s;
  return *s ? s : 0;
}

ERI_FUNC_ATTR const char *
eri_strntok (const char *s, char d, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n && s[i] != d; ++i)
    continue;
  return i < n ? s + i : 0;
}

ERI_FUNC_ATTR const char *
eri_strstr (const char *s, const char *d)
{
  return eri_strnstr (s, d, eri_strlen (s));
}

ERI_FUNC_ATTR const char *
eri_strnstr (const char *s, const char *d, uint64_t n)
{
  uint64_t dl = eri_strlen (d);
  uint64_t i;
  for (i = 0; i <= n - dl; ++i)
    if (eri_strncmp (s + i, d, dl) == 0)
      return s + i;
  return 0;
}
