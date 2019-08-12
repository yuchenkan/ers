#ifndef TST_TST_TST_SYSCALL_H
#define TST_TST_TST_SYSCALL_H

#include <public/public.h>
#include <tst/tst-syscall-specific.h>

#define tst_stack_top(stack)		((stack) + sizeof (stack) - 8)

static eri_unused void
tst_assert_sys_sigprocmask_all (void)
{
  eri_sigset_t mask;
  eri_sig_fill_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);
}

static eri_unused void
tst_assert_sys_sigprocmask_none (void)
{
  eri_sigset_t mask;
  eri_sig_empty_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);
}

#endif
