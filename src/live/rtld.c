#include <lib/elf.h>
#include <lib/util.c>
#include <lib/syscall.c>
#include <lib/printf.c>

#include <common/rtld.c>

#include <live/rtld.h>

static uint64_t
map_base (struct eri_seg *segs, uint16_t nsegs,
	  uint64_t page_size, struct eri_live_rtld_args *rtld_args)
{
  uint64_t buf_size = rtld_args->buf_size;

  uint64_t segs_start = eri_round_down (segs[0].vaddr, page_size);
  uint64_t segs_alloc_end = segs[nsegs - 1].vaddr + segs[nsegs - 1].memsz;
  uint64_t segs_end = eri_round_up (segs_alloc_end, page_size);

  rtld_args->map_start = eri_assert_syscall (mmap, segs_start - page_size,
		segs_end - segs_start + buf_size + page_size, 0,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);

  /* one guard page */
  uint64_t base = rtld_args->map_start + page_size - segs_start;

  rtld_args->base = base;
  rtld_args->buf = base + segs_end;
  rtld_args->map_end = rtld_args->buf + buf_size;

  return base;
}

eri_noreturn void
rtld (void **args, uint64_t rdx)
{
  extern uint8_t eri_binary_end[];
  struct eri_live_rtld_args rtld_args = {
    rdx, (uint64_t) args, (uint64_t) eri_binary_end
  };
  eri_sigset_t set;
  eri_sig_fill_set (&set);
  eri_assert_sys_sigprocmask (&set, &rtld_args.sig_mask);

  const char *live = "/work/ers/live";
  uint64_t buf_size = 1024 * 1024 * 1024;
  uint64_t page_size = 4096;

  rtld_args.envp = eri_get_envp_from_args (args);
  char **envp;
  for (envp = rtld_args.envp; *envp; ++envp)
    (void) (eri_get_arg_str (*envp, "ERS_LIVE=", (void *) &live)
    || eri_get_arg_int (*envp, "ERS_BUF_SIZE=", &buf_size, 10));
  rtld_args.buf_size = buf_size;

  struct eri_auxv *auxv;
  for (rtld_args.auxv = auxv = (struct eri_auxv *)(envp + 1);
       auxv->type != ERI_AT_NULL; ++auxv)
    if (auxv->type == ERI_AT_PAGESZ) page_size = auxv->val;
  rtld_args.page_size = page_size;

  uint64_t res = eri_syscall (open, live, ERI_O_RDONLY);
  if (res == ERI_ENOENT)
    {
      eri_assert_fprintf (ERI_STDERR, "failed to load ERS_LIVE: %s\n", live);
      eri_assert_syscall (exit, 1);
    }
  eri_assert (eri_syscall_is_ok (res));
  int32_t fd = res;

  uint8_t buf[sizeof (uint16_t) + sizeof (uint64_t) * 2];
  eri_assert_syscall (lseek, fd, -sizeof buf, ERI_SEEK_END);
  eri_assert_sys_read (fd, buf, sizeof buf);
  uint16_t nsegs = *(uint16_t *) buf;
  uint64_t nrels = *(uint64_t *) (buf + sizeof nsegs);
  uint64_t entry = *(uint64_t *) (buf + sizeof nsegs + sizeof nrels);

  uint64_t rels_size = sizeof (struct eri_relative) * nrels;

  eri_assert (nsegs > 0);
  struct eri_seg segs[nsegs];
  eri_assert_syscall (lseek, fd,
		      -(sizeof segs + rels_size + sizeof buf), ERI_SEEK_END);
  eri_assert_sys_read (fd, segs, sizeof segs);

  uint64_t base = map_base (segs, nsegs, page_size, &rtld_args);
  eri_map_bin (fd, segs, nsegs, base, page_size);

  // eri_assert_fprintf (ERI_STDERR, "base = %lx\n", base);

  if (nrels)
    {
      struct eri_relative rels[4096];
      eri_assert_syscall (lseek, fd,
			  -(rels_size + sizeof buf), ERI_SEEK_END);

      uint64_t i;
      for (i = 0; i < nrels; i += eri_length_of (rels))
	{
	  uint64_t n = eri_min (eri_length_of (rels), nrels - i);
	  eri_assert_sys_read (fd, rels, sizeof rels[0] * n);
	  eri_map_reloc (rels, n, base);
	}
    }

  eri_assert_syscall (close, fd);

  ((void (*) (void *)) base + entry) (&rtld_args);
  eri_assert_unreachable ();
}
