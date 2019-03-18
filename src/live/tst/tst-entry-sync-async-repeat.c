#include <compiler.h>
#include <common.h>

#include <public.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-entry.h>

extern uint8_t ctrl_enter[];
asm ("ctrl_enter: rep movsb");

extern uint8_t expr_enter[];
extern uint8_t expr_leave[];
asm ("expr_enter: " ERI_STR (ERS_SYNC_ASYNC (0, rep movsb))
     "; expr_leave:");

static uint8_t idx;
#define COUNT	16
static struct tst_live_entry_mcontext ctrl_tctxs[COUNT];

static uint8_t src[COUNT];
static uint8_t dst[COUNT];

static uint8_t
ctrl_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  ctrl_tctxs[idx++] = *tctx;
  return idx != COUNT;
}

static uint8_t
expr_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  eri_debug ("idx = %u, expr = %lx\n", idx, tctx);
  eri_assert (tctx->rip
	== (uint64_t) (idx != COUNT - 1 ? expr_enter : expr_leave));
  tst_assert_live_entry_mcontext_eq (ctrl_tctxs + idx, tctx,
				     ~TST_LIVE_ENTRY_MCONTEXT_RIP_MASK);
  uint8_t i;
  for (i = 0; i < COUNT; ++i)
    eri_assert (dst[i] == (i <= idx ? src[i] : 0));
  return ++idx != COUNT;
}

eri_noreturn void tst_live_start (void);

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  struct tst_live_entry_mcontext tctx;
  tst_live_entry_rand_fill_mcontext (&rand, &tctx);

  tst_rand_fill (&rand, src, sizeof src);

  tctx.rcx = COUNT;
  tctx.rsi = (uint64_t) src;
  tctx.rdi = (uint64_t) dst;

  tctx.rip = (uint64_t) ctrl_enter;
  eri_debug ("ctrl %lx\n", tctx.rip);
  tst_live_entry (&tctx, ctrl_step, 0);

  idx = 0;
  eri_memset (dst, 0, sizeof dst);

  tctx.rip = (uint64_t) expr_enter;
  eri_debug ("expr %lx\n", tctx.rip);
  tst_live_entry (&tctx, expr_step, 0);

  eri_debug ("done\n");
  tst_assert_sys_exit (0);
}
