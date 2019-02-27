#include <compiler.h>

#include <lib/tst-util.h>
#include <tst/tst-syscall.h>

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand);

  uint64_t mask = tst_rand_next (&rand) & TST_SIGSET_MASK;
  struct eri_sigset set;
  set.val[0] = mask;

  tst_assert_sys_sigprocmask (&set, 0);
  tst_assert_sys_sigprocmask (0, &set);
  eri_assert (set.val[0] == mask);

  tst_assert_sys_exit (0);
}
