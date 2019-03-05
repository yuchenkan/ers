#include <lib/util.h>

#include <public.h>
#include <live/tst/tst-sig-hand-ut.h>

extern uint8_t enter[];
extern uint8_t leave[];
asm ("enter: " ERI_STR (ERS_ATOMIC_CMPXCHG (0, b, %cl, (%rbx))) "; leave: ret");

static void
fix_ctx (struct eri_mcontext *ctx, void *mem)
{
  ctx->rax = 0xff;
  ctx->rcx = 0x1;
  ctx->rbx = (uint64_t) mem;;
  *(uint8_t *) mem = 0xff;
}

TST_LIVE_SIG_HAND_DEFINE_INIT_STEP (fix_ctx, enter, leave, 0, 1, 0, 0)
