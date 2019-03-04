#include <public.h>
#include <lib/util.h>

#include <tst/tst-live-sig-hand-ut.h>

extern uint8_t enter[];
extern uint8_t leave[];
asm ("enter: " ERI_STR (ERS_SYSCALL (0)) "; leave: ret");

static void
fix_ctx (struct eri_mcontext *ctx, void *mem)
{
  ctx->rax = -1;
}

TST_LIVE_SIG_HAND_DEFINE_INIT_STEP (fix_ctx, enter, leave, 0, 0, 0, 0)
