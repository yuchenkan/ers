#include <public/public.h>

#include <lib/util.h>
#include <live/tst/tst-sig-hand-ut.h>

extern uint8_t enter[];
extern uint8_t leave[];
asm ("enter: " ERI_STR (ERS_ATOMIC_INC (0, b, (%rcx))) "; leave: ret");

static void
fix_ctx (struct eri_mcontext *ctx, void *mem)
{
  ctx->rcx = (uint64_t) mem;
  *(uint8_t *) mem = 0xff;
}

TST_LIVE_SIG_HAND_DEFINE_INIT_STEP (fix_ctx, enter, leave, 0, 1, 0, 0)
