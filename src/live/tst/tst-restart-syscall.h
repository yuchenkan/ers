#ifndef TST_LIVE_TST_TST_RESTART_SYSCALL_H
#define TST_LIVE_TST_TST_RESTART_SYSCALL_H

#include <stdint.h>

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

#define TST_LIVE_RESTART_SYSCALL_DEFINE_TST(init, wait, wake, fini, \
					    seed, debug) \
static eri_aligned16 uint8_t _stack[3][1024 * 1024];			\
static struct tst_live_clone_args _wake_args;				\
static struct tst_live_clone_raise_args _raise_args[2];			\
									\
static uint8_t _hand;							\
									\
static void								\
_sig_handler (int32_t sig, struct eri_siginfo *info,			\
	      struct eri_ucontext *ctx)					\
{									\
  tst_atomic_inc (&_hand, 0);						\
  eri_info ("handled %u\n", sig);					\
}									\
									\
static void								\
_wake (void *args)							\
{									\
  wake;									\
}									\
									\
eri_noreturn void							\
tst_live_start (void)							\
{									\
  eri_global_enable_debug = debug;					\
									\
  eri_info ("start\n");							\
  struct tst_rand _rand;						\
  tst_rand_init (&_rand, seed);						\
									\
  struct eri_sigaction _act = {						\
    _sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_RESTART,	\
    tst_assert_sys_sigreturn						\
  };									\
  eri_sig_fill_set (&_act.mask);					\
  tst_assert_sys_sigaction (ERI_SIGRTMIN, &_act, 0);			\
  tst_assert_sys_sigaction (ERI_SIGRTMIN + 1, &_act, 0);		\
									\
  _raise_args[0].args.top = tst_stack_top (_stack[0]);			\
  _raise_args[0].args.delay = tst_rand (&_rand, 256, 512);		\
  _raise_args[0].sig = ERI_SIGRTMIN;					\
  _raise_args[0].count = 1;						\
  _raise_args[1].args.top = tst_stack_top (_stack[1]);			\
  _raise_args[1].args.delay = tst_rand (&_rand, 256, 512);		\
  _raise_args[1].sig = ERI_SIGRTMIN + 1;				\
  _raise_args[1].count = 1;						\
  _wake_args.top = tst_stack_top (_stack[2]);				\
  _wake_args.delay = tst_rand (&_rand, 256, 1024);			\
  _wake_args.fn = _wake;						\
									\
  init;									\
									\
  tst_assert_live_clone_raise (_raise_args);				\
  tst_assert_live_clone_raise (_raise_args + 1);			\
  tst_assert_live_clone (&_wake_args);					\
									\
  uint8_t _pre = tst_atomic_load (&_hand, 1);				\
									\
  wait;									\
									\
  uint8_t _post = tst_atomic_load (&_hand, 1);				\
									\
  tst_assert_sys_futex_wait (&_raise_args[0].args.alive, 1, 0);		\
  tst_assert_sys_futex_wait (&_raise_args[1].args.alive, 1, 0);		\
  tst_assert_sys_futex_wait (&_wake_args.alive, 1, 0);			\
									\
  eri_info ("pre = %u, post = %u\n", _pre, _post);			\
									\
  fini;									\
									\
  tst_assert_sys_exit (0);						\
}

#endif
