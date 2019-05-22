#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  uint64_t mask = tst_rand_next (&rand) & TST_SIGSET_MASK;
  struct eri_sigset set;
  set.val[0] = mask;

  tst_assert_sys_sigprocmask (&set, 0);
  tst_assert_sys_sigprocmask (0, &set);
  eri_assert (set.val[0] == mask);

  set.val[0] = TST_SIGSET_MASK;
  tst_assert_sys_sigprocmask (&set, 0);

  struct eri_sigset set2;
  eri_sig_empty_set (&set2);
  eri_sig_add_set (&set2, ERI_SIGINT);
  eri_sig_add_set (&set2, ERI_SIGTERM);
  tst_assert_syscall (rt_sigprocmask, ERI_SIG_UNBLOCK,
		      &set2, 0, ERI_SIG_SETSIZE);

  eri_sig_del_set (&set, ERI_SIGINT);
  eri_sig_del_set (&set, ERI_SIGTERM);
  struct eri_sigset set3;
  tst_assert_sys_sigprocmask (0, &set3);
  eri_assert (set3.val[0] == set.val[0]);

  tst_assert_syscall (rt_sigprocmask, ERI_SIG_BLOCK,
		      &set2, 0, ERI_SIG_SETSIZE);
  tst_assert_sys_sigprocmask (0, &set3);
  eri_assert (set3.val[0] == TST_SIGSET_MASK);

  eri_debug ("inval 1\n");
  eri_assert (tst_syscall (rt_sigprocmask, -1,
			   0, 0, ERI_SIG_SETSIZE) == ERI_EINVAL);
  eri_debug ("inval 2\n");
  eri_assert (tst_syscall (rt_sigprocmask, ERI_SIG_SETMASK,
			   0, 0, 0) == ERI_EINVAL);
  eri_debug ("fault 1\n");
  eri_assert (tst_syscall (rt_sigprocmask, ERI_SIG_SETMASK,
			   0, 1, ERI_SIG_SETSIZE) == ERI_EFAULT);
  eri_debug ("fault 2\n");
  eri_assert (tst_syscall (rt_sigprocmask, ERI_SIG_SETMASK,
			   1, 0, ERI_SIG_SETSIZE) == ERI_EFAULT);

  tst_assert_sys_exit (0);
}
