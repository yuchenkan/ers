#include <compiler.h>
#include <common.h>

#include <public/impl.h>
#include <tst/tst-syscall.h>
#include <tst/tst-live-entry.h>

extern uint8_t ctrl_enter[];
extern uint8_t ctrl_leave[];
asm ("ctrl_enter: loop	ctrl_leave; nop; nop; ctrl_leave:");

extern uint8_t expr_enter[];
extern uint8_t expr_leave[];
asm ("expr_enter: " ERI_STR (_ERS_SYNC_ASYNC (0, loop	expr_leave))
     "; nop; nop; expr_leave:");

static uint8_t
ctrl_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  *(struct tst_live_entry_mcontext *) args = *tctx;
  return 0;
}

static uint8_t
expr_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  eri_assert (tctx->rip == (uint64_t) expr_leave);
  eri_debug ("ctrl = %lx, expr = %lx\n", args, tctx);
  tst_assert_live_entry_mcontext_eq (tctx, args,
			~TST_LIVE_ENTRY_MCONTEXT_RIP_MASK);
  return 0;
}

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand);

  eri_debug ("\n");
  struct tst_live_entry_mcontext tctx;
  tst_live_entry_rand_fill_mcontext (&rand, &tctx);

  struct tst_live_entry_mcontext ctrl_tctx;
  tctx.rcx = 2;

  tctx.rip = (uint64_t) ctrl_enter;
  eri_debug ("ctrl %lx\n", tctx.rip);
  tst_live_entry (&tctx, ctrl_step, &ctrl_tctx);

  tctx.rip = (uint64_t) expr_enter;
  eri_debug ("expr %lx\n", tctx.rip);
  tst_live_entry (&tctx, expr_step, &ctrl_tctx);

  eri_debug ("done\n");
  tst_assert_sys_exit (0);
}
