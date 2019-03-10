#include <rtld.c>
#include <lib/elf.h>
#include <lib/util.c>
#include <lib/syscall.h>
#include <lib/syscall.c>
#include <lib/printf.c>

#include <live/rtld.h>

static uint64_t
map_base (struct eri_seg *segs, uint16_t nsegs,
	  uint64_t page_size, void *args)
{
  struct eri_live_rtld_args *rtld_args = args;
  uint64_t buf_size = rtld_args->buf_size;

  uint64_t map_start = eri_round_down (segs[0].vaddr, page_size);
  uint64_t alloc_end = segs[nsegs - 1].vaddr + segs[nsegs - 1].memsz;
  uint64_t map_end = eri_round_up (alloc_end, page_size);

  uint64_t base = eri_assert_syscall (mmap, map_start - page_size,
		map_end - map_start + buf_size + 3 * page_size, 0,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0)
	+ page_size - map_start;

  rtld_args->map_start = base + map_start - page_size;
  rtld_args->buf = base + map_end + page_size;
  rtld_args->map_end = rtld_args->buf + buf_size + page_size;
  return base;
}

eri_noreturn void rtld (void **args, uint64_t rdx);

eri_noreturn void
rtld (void **args, uint64_t rdx)
{
  extern uint8_t eri_binary_end[];
  struct eri_live_rtld_args rtld_args = {
    rdx, (uint64_t) args, (uint64_t) eri_binary_end
  };
  struct eri_sigset set;
  eri_sig_fill_set (&set);
  eri_assert_syscall (rt_sigprocmask, ERI_SIG_SETMASK, &set,
		      &rtld_args.sig_mask, ERI_SIG_SETSIZE);

  const char *live = "ers/live";
  uint64_t buf_size = 256 * 1024 * 1024;
  uint64_t page_size = 4096;

  rtld_args.envp = eri_get_envp_from_args (args);
  char **envp;
  for (envp = rtld_args.envp; *envp; ++envp)
    (void) (eri_get_arg_str (*envp, "ERS_LIVE=", (void *) &live)
    || eri_get_arg_int (*envp, "ERS_BUF_SIZE=", &buf_size, 10));
  rtld_args.buf_size = buf_size;

  struct eri_auxv *auxv;
  for (auxv = (struct eri_auxv *)(envp + 1);
       auxv->type != ERI_AT_NULL; ++auxv)
    if (auxv->type == ERI_AT_PAGESZ) page_size = auxv->val;
  rtld_args.auxv = auxv;
  rtld_args.page_size = page_size;

  uint64_t entry = eri_map_bin (live, page_size, map_base, &rtld_args);
  if (! entry)
    {
      eri_assert_printf ("failed to load ERS_LIVE: %s\n", live);
      eri_assert_syscall (exit, 1);
    }

  ((void (*) (void *)) entry) (&rtld_args);
  eri_assert_unreachable ();
}
