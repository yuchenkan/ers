#ifndef ERI_TST_TST_SYSCALL_H
#define ERI_TST_TST_SYSCALL_H

#include <public.h>
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
  uint32_t count;
  int32_t alive;
};

#define tst_sys_clone_raise_init_args(args, rsig, stack, rdelay, rcount) \
  do {									\
    struct tst_sys_clone_raise_args *_args = args;			\
    _args->sig = rsig;							\
    _args->top = tst_clone_top (stack);					\
    _args->delay = rdelay;						\
    _args->pid = tst_assert_syscall (getpid);				\
    _args->tid = tst_assert_syscall (gettid);				\
    _args->count = rcount;						\
    _args->alive = 1;							\
  } while (0)

void tst_assert_sys_clone_raise (struct tst_sys_clone_raise_args *args);

struct tst_sys_clone_exit_group_args
{
  uint8_t *top;
  uint32_t delay;
};

#define tst_sys_clone_exit_group_init_args(args, stack, edelay) \
  do {									\
    struct tst_sys_clone_exit_group_args *_args = args;			\
    _args->top = tst_clone_top (stack);					\
    _args->delay = edelay;						\
  } while (0)

void tst_assert_sys_clone_exit_group (
			struct tst_sys_clone_exit_group_args *args);

#endif

#endif
