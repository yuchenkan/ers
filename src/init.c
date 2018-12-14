#include "rtld.h"

struct proc_init_map_data
{
  eri_file_t init;
  uint64_t buf;

  /* The stack currently on, save it at the last point.  */
  int64_t stack_start, stack_end;
};

static void
proc_init_map_entry (const struct eri_map_entry *ent, void *data)
{
  if (ent->path
      && (eri_strcmp (ent->path, "[vvar]") == 0
	  || eri_strcmp (ent->path, "[vsyscall]") == 0))
    return;

  uint64_t start = ent->start;
  uint64_t end = ent->end;

  struct proc_init_map_data *d = data;
#if 0
  struct ers_map *m;
  for (m = d->maps; m; m = m->next)
    if (start >= m->start && start < m->end)
      return;
#endif

  uint8_t perms = ent->perms;
  eri_assert_fprintf (ERI_STDERR, "%lx-%lx %x\n", start, end, perms);

  if (perms & ERI_MAP_ENTRY_SHARED)
    eri_assert_fprintf (ERI_STDERR, "warning: non private map\n");

  uint8_t flags = perms & (ERI_MAP_ENTRY_RWX | ERI_MAP_ENTRY_GROWSDOWN);
  if (start == d->buf) flags |= ERI_INIT_MAP_ZERO;

  if (start <= (uint64_t) &start && end > (uint64_t) &start)
    {
      d->stack_start = start;
      d->stack_end = end;
      eri_assert (flags & ERI_INIT_MAP_GROWSDOWN);
    }

  eri_save_mark (d->init, ERI_MARK_INIT_MAP);
  eri_save_init_map (d->init, start, end, flags);
  if (flags & ERI_INIT_MAP_READ
      && ! (flags & ERI_INIT_MAP_ZERO)
      && d->stack_start != start)
    eri_save_init_map_data (d->init, start, end - start);
}

static uint8_t __attribute__ ((noinline))
init_context (eri_file_t init, uint64_t start, uint64_t end)
{
  struct eri_context ctx;
  asm ("" : : : "memory");
  eri_save_mark (init, ERI_MARK_INIT_STACK);
  eri_save_init_map_data (init, (const void *) start, end - start);
  uint8_t mode = set_context (&ctx);
  if (mode == LIVE)
    {
      eri_save_init_context (init, &ctx);
      eri_assert (eri_fclose (init) == 0);
    }
  else
    {
      eri_assert_fprintf (ERI_STDERR, "replay!!!\n");
      eri_dump_maps (ERI_STDERR);
      ERI_ASSERT_SYSCALL (munmap, ctx.unmap_start, ctx.unmap_size);
    }
  return mode;
}

void
eri_init (struct eri_rtld *rtld)
{
  const char *config = "ers_config";
  uint64_t page_size = 4096;

  const char *path = "ers_data";
  uint64_t buf_size = 256 * 1024 * 1024;
  uint64_t stack_size = 2 * 1024 * 1024;
  uint64_t file_buf_size = 64 * 1024;

  void **arg = rtld->arg;

  uint64_t argc = *(uint64_t *) arg;
  char **envp;
  for (envp = (char **) arg + 1 + argc + 1; *envp; ++envp)
    /* TODO: nested recording */
    if (eri_strncmp (*envp, "ERS_CONFIG=", eri_strlen ("ERS_CONFIG=")) == 0)
      path = *envp + eri_strlen ("ERS_CONFIG=");

  struct eri_auxv *auxv = (struct eri_auxv *) (envp + 1);
  struct eri_auxv *a;
  for (a = auxv; a->type != AT_NULL; ++a)
    if (a->type == ERI_AT_PAGESZ) page_size = a->val;

  /* TODO: load config */

  static struct eri_common common;

  common.config = config;
  common.page_size = page_size;

  common.path = path;
  common.buf_size = buf_size;
  common.stack_size = stack_size;
  common.file_buf_size = file_buf_size;

  common.buf = (uint64_t) ERI_ASSERT_SYSCALL_RES (
		mmap, 0, buf_size + 2 * page_size, 0,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, - 1, 0) + page_size;

  eri_file_buf_t init_buf[1024];
  eri_file_t init = eri_open_path (path, "init", 0, 0,
				   init_buf, sizeof init_buf);
  struct proc_init_map_data pd = { init, common.buf + page_size };
  eri_process_maps (proc_init_map_entry, &pd);

  eri_assert (pd.stack_start);
  uint8_t mode = eri_init_context (init, pd.stack_start, pd.stack_end);

  if (mode == ERI_LIVE) eri_live_init (&common, rtld);
}
