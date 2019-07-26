#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static eri_noreturn void
start (struct tst_live_clone_args *args)
{
  tst_yield (args->delay);
  if (args->fn) args->fn (args->args);
  tst_assert_sys_exit (0);
}

void
tst_assert_live_clone (struct tst_live_clone_args *args)
{
  args->alive = 1;
  struct eri_sys_clone_args clone_args = {
    ERI_CLONE_SUPPORTED_FLAGS, args->top, 0, &args->alive, 0,
    start, args
  };
  tst_assert_sys_clone (&clone_args);
}

static void
raise (struct tst_live_clone_raise_args *args)
{
  uint32_t back = 1, i;
  for (i = 0; i < args->count || args->count == 0; ++i)
    {
      tst_assert_syscall (tgkill, args->pid, args->tid, args->sig);
      tst_yield ((back *= 2) / 64);
    }
}

void
tst_assert_live_clone_raise (struct tst_live_clone_raise_args *args)
{
  if (! args->sig) args->sig = ERI_SIGINT;
  if (! args->pid) args->pid = tst_assert_syscall (getpid);
  if (! args->tid) args->tid = tst_assert_syscall (gettid);

  args->args.fn = (void *) raise;
  args->args.args = args;
  tst_assert_live_clone (&args->args);
}

static eri_noreturn void
exit_group (void *args)
{
  tst_assert_sys_exit_group (0);
}

void
tst_assert_live_clone_exit_group (struct tst_live_clone_args *args)
{
  args->fn = exit_group;
  tst_assert_live_clone (args);
}

void *
tst_assert_live_alloc_boundary (uint64_t size, uint64_t page_size)
{
  eri_assert (size < page_size);
  uint8_t *p = (void *) tst_assert_syscall (mmap, 0, 2 * page_size,
			ERI_PROT_READ | ERI_PROT_WRITE,
			ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  tst_assert_syscall (mprotect, p + page_size, page_size, 0);
  return p + page_size - size;
}

void
tst_assert_live_free_boundary (void *ptr, uint64_t page_size)
{
  tst_assert_syscall (munmap, eri_round_down ((uint64_t) ptr, page_size),
		      2 * page_size);
}
