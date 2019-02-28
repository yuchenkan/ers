#ifndef ERI_TST_TST_SYSCALL_H
#define ERI_TST_TST_SYSCALL_H

#include <public/impl.h>
#include <tst/tst-syscall-dedicated.h>

/* ~(SIGKILL_MASK | SIGSTOP_MASK) */
#define TST_SIGSET_MASK			0xfffffffffffbfeff

#define tst_clone_top(stack)		((stack) + sizeof (stack) - 8)

#define tst_assert_sys_raise(sig) \
  tst_assert_syscall (tgkill, tst_assert_syscall (getpid),		\
		      tst_assert_syscall (gettid), sig)

#ifndef __ASSEMBLER__

struct tst_sys_clone_raise_args
{
  int32_t sig;
  uint8_t *top;
  uint32_t delay;
  int32_t pid, tid;
};

#define tst_sys_clone_raise_init_args(args, signal, stack, raise_delay) \
  do {									\
    struct tst_sys_clone_raise_args *_args = args;			\
    _args->sig = signal;						\
    _args->top = tst_clone_top (stack);					\
    _args->delay = raise_delay;						\
    _args->pid = tst_assert_syscall (getpid);				\
    _args->tid = tst_assert_syscall (gettid);				\
  } while (0)

void tst_assert_sys_clone_raise (struct tst_sys_clone_raise_args *args);

#endif

#endif
