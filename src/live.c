#include "live.h"

#include "lib/util.h"
#include "lib/syscall.h"

struct eri_sigset eri_live_sigempty;

uint64_t
eri_live_copy_stack (uint64_t bot, struct eri_siginfo *info,
		     struct eri_ucontext *ctx, uint64_t cur)
{
  uint64_t sz = bot + ERI_SIG_STACK_SIZE - cur;
  uint64_t rsp = eri_round_down (ctx->mctx.rsp - 128 - sz, 16) - 8;
  eri_memcpy ((void *) rsp, (void *) cur, sz);

  if (ctx->mctx.fpstate)
    ctx->mctx.fpstate = (void *) (rsp + (uint64_t) ctx->mctx.fpstate - cur);
  *(uint64_t *) (cur - 24) = rsp + (uint64_t) info - cur;
  *(uint64_t *) (cur - 16) = rsp + (uint64_t) ctx - cur;
  return rsp;
}

struct eri_live_internal eri_live_internal;

uint64_t
eri_live_atomic_hash_mem (uint64_t mem, struct eri_live_thread *thread)
{
  return 0;
}

void
eri_live_atomic_load (uint64_t mem, uint64_t ver, uint64_t val,
		      struct eri_live_thread *thread)
{
}

void
eri_live_atomic_stor (uint64_t mem, uint64_t ver,
		      struct eri_live_thread *thread)
{
}

void
eri_live_atomic_load_stor (uint64_t mem, uint64_t ver, uint64_t val,
			   struct eri_live_thread *thread)
{
}
