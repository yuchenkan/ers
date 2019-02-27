#ifndef ERI_TST_TST_SYSCALL_H
#define ERI_TST_TST_SYSCALL_H

#include <public/impl.h>
#include <tst/tst-syscall-dedicated.h>

/* ~(SIGKILL_MASK | SIGSTOP_MASK) */
#define TST_SIGSET_MASK			0xfffffffffffbfeff

#define tst_assert_sys_raise(sig) \
  tst_assert_syscall (tgkill, tst_assert_syscall (getpid),		\
		      tst_assert_syscall (gettid), sig)

#endif
