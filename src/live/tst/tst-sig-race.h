#include <compiler.h>
#include <common.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

#define TST_LIVE_SIG_RACE_DEFINE_TST(init, what, debug) \
static eri_aligned16 uint8_t _stack[1024 * 1024];			\
static struct tst_sys_clone_raise_args _raise_args;			\
									\
static void								\
_sig_handler (int32_t sig) { eri_debug ("\n"); }			\
									\
eri_noreturn void tst_live_start (void);				\
									\
eri_noreturn void							\
tst_live_start (void)							\
{									\
  eri_global_enable_debug = debug;					\
									\
  struct tst_rand _rand;						\
  tst_rand_init (&_rand);						\
									\
  struct eri_sigaction _act = { 					\
    _sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn		\
  };									\
  tst_assert_sys_sigaction (ERI_SIGINT, &_act, 0);			\
									\
  init;									\
									\
  tst_sys_clone_raise_init_args (&_raise_args, 0, _stack, 0, 0);	\
  tst_assert_sys_clone_raise (&_raise_args);				\
  tst_yield (tst_rand (&_rand, 0, 6));					\
									\
  what;									\
									\
  tst_assert_sys_exit_group (0);					\
}
