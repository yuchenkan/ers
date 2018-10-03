#include "util.h"

void
eri_memset (void *s, char c, size_t n)
{
  size_t i;
  for (i = 0; i < n; ++i) ((char *) s)[i] = c;
}

void
eri_memcpy (void *d, const void *s, size_t n)
{
  size_t i;
  for (i = 0; i < n; ++i) ((char *) d)[i] = ((const char *) s)[i];
}

void
eri_memmove (void *d, const void *s, size_t n)
{
  char *cd = (char *) d;
  const char *cs = (const char *) s;
  size_t i;
  if (cd == cs) return;
  else if (cd + n <= cs || cs + n <= cd)
    eri_memcpy (d, s, n);
  else if (cd + n > cs)
    for (i = 0; i < n; ++i) cd[i] = cs[i];
  else
    for (i = n - 1; i >= 0; --i) cd[i] = cs[i];
}

char
eri_memcmp (const void *s1, const void *s2, size_t n)
{
  size_t i;
  for (i = 0; i < n; ++i)
    if (((const char *) s1)[i] < ((const char *) s2)[i]) return -1;
    else if (((const char *) s1)[i] > ((const char *) s2)[i]) return 1;
  return 0;
}

size_t
eri_strlen (const char *s)
{
  size_t i;
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
eri_strncat (char *d, const char *s, size_t n)
{
  d = d + eri_strlen (d);
  size_t i;
  for (i = 0; i < n && *s; ++i) *d++ = *s++;
  *d = '\0';
}

char
eri_strcmp (const char *s1, const char *s2)
{
  int i;
  for (i = 0; ; ++i)
    {
      if (s1[i] < s2[i]) return -1;
      else if (s1[i] > s2[i]) return 1;
      if (s1[i] == '\0') return 0;
    }
}

char
eri_strncmp (const char *s1, const char *s2, size_t n)
{
  size_t i;
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
eri_strntok (const char *s, char d, size_t n)
{
  size_t i;
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
eri_strnstr (const char *s, const char *d, size_t n)
{
  size_t dl = eri_strlen (d);
  size_t i;
  for (i = 0; i <= n - dl; ++i)
    if (eri_strncmp (s + i, d, dl) == 0)
      return s + i;
  return 0;
}
