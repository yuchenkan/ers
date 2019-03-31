#include <public/public.h>

#include <lib/util.h>
#include <live/tst/tst-sig-hand-ut.h>

extern uint8_t enter[];
extern uint8_t leave[];
extern uint8_t repeat[];
asm ("enter: " ERI_STR (ERS_SYNC_ASYNC (0, repeat: rep	movsb))
     "; leave: ret");

const uint16_t src = 0x1234;

static void
fix_ctx (struct eri_mcontext *ctx, void *mem)
{
  ctx->rsi = (uint64_t) &src;
  ctx->rdi = (uint64_t) mem;
  ctx->rcx = sizeof src;
  *(uint16_t *) mem = 0;
}

TST_LIVE_SIG_HAND_DEFINE_INIT_STEP (fix_ctx, enter, leave,
				    repeat, sizeof src, 1, 0)
