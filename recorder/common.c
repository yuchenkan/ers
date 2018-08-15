#include "common.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/printf.h"

void
eri_dump_maps (void)
{
  int maps;
  char buf[256];

  eri_assert (eri_fopen ("/proc/self/maps", 1, &maps) == 0);
  while (1)
    {
      size_t l;
      eri_assert (eri_fread (maps, buf, sizeof buf - 1, &l) == 0);
      buf[l] = '\0';
      eri_assert (eri_printf ("%s", buf) == 0);
      if (l != sizeof buf - 1) break;
    }
  eri_assert (eri_fclose (maps) == 0);
}

static void
process_map_entry (char *buf, struct eri_map_entry *ent)
{
  /* eri_assert (eri_printf ("%s\n", buf) == 0); */

  ent->start = ent->end = 0;
  ent->perms = 0;
  ent->path = 0;

  size_t i = 0;
  while (buf[i] && buf[i] != '-')
    ent->start = (ent->start << 4) + eri_ctoi (buf[i++]);
  eri_assert (buf[i++] == '-');
  while (buf[i] && buf[i] != ' ')
    ent->end = (ent->end << 4) + eri_ctoi (buf[i++]);
  eri_assert (buf[i++] == ' ');
  eri_assert (buf[i] && buf[i + 1] && buf[i + 2] && buf[i + 3]);
  ent->perms = (buf[i] != '-')
	       | ((buf[i + 1] != '-') << 1)
	       | ((buf[i + 2] != '-') << 2)
	       | ((buf[i + 3] != 'p') << 3);
  eri_assert (buf[i + 4] && buf[i + 5]);
  i += 5;
  const char *d = eri_strtok (buf + i, ' ');
  eri_assert (d);
  d = eri_strtok (d + 1, ' ');
  eri_assert (d);
  d = eri_strtok (d + 1, ' ');
  eri_assert (d);
  while (*d && *d == ' ') ++d;
  eri_assert (*d);
  if (*d != '\n') ent->path = d;
  d = eri_strtok (d, '\n');
  eri_assert (d);
  *(char *) d = '\0';
  d = eri_strstr (++d, "VmFlags: ");
  eri_assert (d);
  for (d = d + eri_strlen ("VmFlags: "); *d && *d != '\n'; d += 3)
    {
      eri_assert (d[0] && d[1] && d[2]);
      if (d[0] == 'g' && d[1] == 'd')
	{
	  ent->perms |= 16;
	  break;
        }
    }
  eri_assert (*d);
}

void
eri_process_maps (void (*proc) (const struct eri_map_entry *, void *),
		  void *data)
{
  int maps;
  char buf[256];
  eri_assert (eri_fopen ("/proc/self/smaps", 1, &maps) == 0);

  size_t last = 0;
  size_t count = 0;
  size_t ln = 0;
  while (1)
    {
      char reset = 0;

      size_t l;
      eri_assert (eri_fread (maps, buf, sizeof buf, &l) == 0);
      const char *d = buf;
      while ((d = eri_strntok (d, '\n', l - (d - buf))))
	{
	  ++d;
	  if (++ln == 16)
	    {
	      size_t nl = sizeof buf * count + (d - buf);

	      char *e = __builtin_alloca (nl - last);
	      eri_assert (eri_fseek (maps, last, ERI_SEEK_SET) == 0);
	      eri_assert (eri_fread (maps, e, nl - last, 0) == 0);
	      e[nl - last] = '\0';

	      struct eri_map_entry ent;
	      process_map_entry (e, &ent);
	      proc (&ent, data);

	      reset = 1;
	      last = sizeof buf * count + (d - buf);
	      ln = 0;
	    }
	}

      if (l != sizeof buf)
	{
	  eri_assert (last == sizeof buf * count + l);
	  break;
	}

      ++count;
      if (reset)
	eri_assert (eri_fseek (maps, count * sizeof buf, ERI_SEEK_SET) == 0);
    }
  eri_assert (eri_fclose (maps) == 0);
}

static void
phex (char *p, unsigned long v)
{
  short i, s = 1;
  while (s < 8 && v & ~(((unsigned long) 1 << (s * 8)) - 1)) ++s;
  for (i = s * 2 - 1; i >= 0; --i)
    {
      p[i] = eri_itoc (v % 16);
      v /= 16;
    }
  eri_assert (v == 0);
  p[s * 2] = '\0';
}

int
eri_open_path (const char *path, const char *name, int flags,
	       unsigned long id)
{
  size_t npath = eri_strlen (path);
  int nname = eri_strlen (name);

  size_t s = npath + 1 + nname + 1; /* path/name\0 */
  if (flags & ERI_OPEN_WITHID) s += 2 * sizeof id; /* path/name$id\0 */
  char *p = __builtin_alloca (s);

  eri_strcpy (p, path);

  size_t c = npath;
  if (npath == 0 || p[npath - 1] != '/') p[c++] = '/';

  eri_strcpy (p + c, name);
  c += nname;

  if (flags & ERI_OPEN_WITHID) phex (p + c, id);
  else p[c] = '\0';

  eri_assert (eri_printf ("%s\n", p) == 0);

  int fd;
  eri_assert (eri_fopen (p, flags & ERI_OPEN_REPLAY, &fd) == 0);
  return fd;
}

void
eri_save_mark (int fd, char mk)
{
  eri_assert (eri_fwrite (fd, &mk, sizeof mk) == 0);
}

char
eri_load_mark (int fd)
{
  size_t s;
  char mk;
  eri_assert (eri_fread (fd, &mk, sizeof mk, &s) == 0);
  return s == 0 ? ERI_MARK_NONE : mk;
}

void
eri_save_init_map (int init, unsigned long start, unsigned long end, char flags)
{
  eri_assert (eri_fwrite (init, (const char *) &start, sizeof start) == 0);
  eri_assert (eri_fwrite (init, (const char *) &end, sizeof end) == 0);
  eri_assert (eri_fwrite (init, &flags, sizeof flags) == 0);
}

void
eri_save_init_map_data (int init, const char *buf, size_t size)
{
  eri_assert (eri_fwrite (init, buf, size) == 0);
}

void
eri_load_init_map (int init, unsigned long *start, unsigned long *end, char *flags)
{
  eri_assert (eri_fread (init, (char *) start, sizeof *start, 0) == 0);
  eri_assert (eri_fread (init, (char *) end, sizeof *end, 0) == 0);
  eri_assert (eri_fread (init, flags, sizeof *flags, 0) == 0);
}

void
eri_load_init_map_data (int init, char *buf, size_t size)
{
  eri_assert (eri_fread (init, buf, size, 0) == 0);
}

void
eri_skip_init_map_data (int init, size_t size)
{
  eri_assert (eri_fseek (init, size, ERI_SEEK_CUR) == 0);
}

void
eri_save_init_context (int init, const struct eri_context *ctx)
{
  eri_assert (eri_fwrite (init, ctx->env, sizeof ctx->env) == 0);
}

void
eri_load_init_context (int init, struct eri_context *ctx)
{
  eri_assert (eri_fread (init, ctx->env, sizeof ctx->env, 0) == 0);
}
