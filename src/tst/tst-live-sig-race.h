#include <compiler.h>
#include <common.h>

#include <lib/tst-util.h>
#include <tst/tst-util.h>
#include <tst/tst-syscall.h>

#define TST_LIVE_SIG_RACE_DEFINE_TST(what, debug) \
static aligned16 uint8_t stack[1024 * 1024];				\
static struct tst_sys_clone_raise_args raise_args;			\
									\
static void								\
sig_handler (int32_t sig) { eri_debug ("\n"); }				\
									\
noreturn void tst_live_start (void);					\
									\
noreturn void								\
tst_live_start (void)							\
{									\
  eri_global_enable_debug = debug;					\
									\
  struct tst_rand rand;							\
  tst_rand_init (&rand);						\
									\
  struct eri_sigaction act = { 						\
    sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn		\
  };									\
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);			\
									\
  tst_sys_clone_raise_init_args (&raise_args, 0, stack, 0, 0);		\
  tst_assert_sys_clone_raise (&raise_args);				\
  tst_yield (tst_rand (&rand, 0, 6));					\
									\
  what;									\
}
