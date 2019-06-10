#ifndef TST_LIVE_TST_TST_SIG_RACE_H
#define TST_LIVE_TST_TST_SIG_RACE_H

#include <stdint.h>

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

#define TST_LIVE_SIG_RACE_DEFINE_TST(init, what, seed, debug) \
static eri_aligned16 uint8_t _stack[1024 * 1024];			\
static struct tst_live_clone_raise_args _raise_args;			\
									\
static void								\
_sig_handler (int32_t sig) { eri_debug ("\n"); }			\
									\
eri_noreturn void							\
tst_live_start (void)							\
{									\
  eri_global_enable_debug = debug;					\
									\
  struct tst_rand _rand;						\
  tst_rand_init (&_rand, seed);						\
									\
  struct eri_sigaction _act = { 					\
    _sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn		\
  };									\
  tst_assert_sys_sigaction (ERI_SIGINT, &_act, 0);			\
									\
  init;									\
									\
  _raise_args.args.top = tst_stack_top (_stack);			\
  tst_assert_live_clone_raise (&_raise_args);				\
  tst_yield (tst_rand (&_rand, 0, 6));					\
									\
  what;									\
									\
  tst_assert_sys_exit_group (0);					\
}

#endif
