#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <tst/tst-atomic.h>
#include <live/tst/tst-syscall.h>

static eri_aligned16 uint8_t stack[1024 * 1024];
static struct tst_live_clone_raise_args raise_args;

static void
sig_handler (int32_t sig)
{
  eri_info ("sig\n");
}

static int32_t v, a = 0xf;

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  struct eri_sigaction act = {
    sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);

  uint32_t delay = tst_rand (&rand, 0, 64);
  raise_args.args.top = tst_stack_top (stack);
  raise_args.args.delay = tst_rand (&rand, 0, 64);
  raise_args.sig = ERI_SIGINT;
  raise_args.count = 1;

  tst_assert_live_clone_raise (&raise_args);
  tst_yield (delay);

  tst_atomic_store (&v, tst_atomic_load (&v, 0), 1);
  eri_assert (v == 0);
  tst_atomic_inc (&v, 1);
  eri_assert (v == 1);
  tst_atomic_dec (&v, 1);
  eri_assert (v == 0);
  tst_atomic_xchg (&v, &a, 1);
  eri_assert (v == 0xf);
  eri_assert (a == 0);
  a = 0xf;
  eri_assert (tst_atomic_cmpxchg (&v, &a, 0xff, 1));
  eri_assert (v == 0xff);
  eri_assert (a == 0xf);
  tst_atomic_and (&v, 0xf, 1);
  eri_assert (v == 0xf);
  tst_atomic_or (&v, 0xff, 1);
  eri_assert (v == 0xff);
  tst_atomic_xor (&v, 0xff, 1);
  eri_assert (v == 0);
  a = 0xff;
  tst_atomic_xadd (&v, &a, 1);
  eri_assert (v == 0xff);
  eri_assert (a == 0);

  tst_atomic_add (&v, 0xff00, 1);
  eri_assert (v == 0xffff);

  tst_atomic_sub (&v, 0xff00, 1);
  eri_assert (v == 0xff);

  uint64_t rflags = ERI_RFLAGS_CF;
  tst_atomic_sbb_x (&v, 0xff, &rflags, 1);
  eri_assert (v == -1);
  eri_assert (rflags & ERI_RFLAGS_CF);

  tst_atomic_adc_x (&v, 0xff, &rflags, 1);
  eri_assert (v == 0xff);
  eri_assert (rflags & ERI_RFLAGS_CF);

  tst_atomic_adc_x (&v, 0, &rflags, 1);
  eri_assert (v == 0x100);
  eri_assert (! (rflags & ERI_RFLAGS_CF));

  tst_atomic_neg (&v, 1);
  eri_assert (v == -0x100);

  v = ~0x100;
  tst_atomic_not (&v, 1);
  eri_assert (v == 0x100);

  rflags = 0;
  tst_atomic_btc_x (&v, 8, &rflags, 1);
  eri_assert (v == 0);
  eri_assert (rflags & ERI_RFLAGS_CF);

  rflags = 0;
  tst_atomic_bts_x (&v, 8, &rflags, 1);
  eri_assert (v == 0x100);
  eri_assert (! (rflags & ERI_RFLAGS_CF));

  rflags = 0;
  tst_atomic_btc_x (&v, 8, &rflags, 1);
  eri_assert (v == 0);
  eri_assert (rflags & ERI_RFLAGS_CF);

  tst_assert_sys_futex_wait (&raise_args.args.alive, 1, 0);
  tst_assert_sys_exit (0);
}
