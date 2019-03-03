#include <compiler.h>

#include <public/impl.h>

#include <lib/util.h>

#include <tst/tst-live-sig-hand-ut.h>

extern uint8_t enter[];
extern uint8_t leave[];
asm ("enter: " ERI_STR (_ERS_SYSCALL (0)) "; leave: ret");

static void
fix_ctx (struct eri_mcontext *ctx)
{
  ctx->rax = -1;
}

uint32_t
tst_live_sig_hand_init_step (struct tst_live_sig_hand_step *step)
{
  step->fix_ctx = fix_ctx;
  step->enter = (uint64_t) enter;
  step->leave = (uint64_t) leave;
  return 1;
}
