#include <public/public.h>
#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-entry.h>

extern uint8_t ctrl_enter[];
asm ("ctrl_enter: loop	ctrl_leave; nop; nop; ctrl_leave:");

extern uint8_t expr_enter[];
extern uint8_t expr_leave[];
asm ("expr_enter: " ERI_STR (ERS_SYNC_ASYNC (0, loop	expr_leave))
     "; nop; nop; expr_leave:");

static struct tst_live_entry_mcontext ctrl_tctx;

static uint8_t
ctrl_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  ctrl_tctx = *tctx;
  return 0;
}

static uint8_t
expr_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  eri_debug ("expr = %lx\n", tctx);
  eri_assert (tctx->rip == (uint64_t) expr_leave);
  tst_assert_live_entry_mcontext_eq (&ctrl_tctx, tctx,
				     ~TST_LIVE_ENTRY_MCONTEXT_RIP_MASK);
  return 0;
}

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  eri_debug ("\n");
  struct tst_live_entry_mcontext tctx;
  tst_live_entry_rand_fill_mcontext (&rand, &tctx);

  tctx.rcx = 2;

  tctx.rip = (uint64_t) ctrl_enter;
  eri_debug ("ctrl %lx\n", tctx.rip);
  tst_live_entry (&tctx, ctrl_step, 0);

  tctx.rip = (uint64_t) expr_enter;
  eri_debug ("expr %lx\n", tctx.rip);
  tst_live_entry (&tctx, expr_step, 0);

  eri_debug ("done\n");
  tst_assert_sys_exit (0);
}
