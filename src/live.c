#include "live.h"

#include "lib/util.h"
#include "lib/syscall.h"

struct eri_sigset eri_live_sigempty;

void
eri_live_init_thread (struct eri_live_thread *th, void *internal,
		      uint64_t stack_top, uint64_t stack_size)
{
  uint8_t *text = (uint8_t *) th + eri_size_of (*th, 16);
  eri_memcpy (text, eri_live_thread_text,
	      eri_live_thread_text_end - eri_live_thread_text);
#define SET_TH_RELA(field, entry) \
  do {									\
    th->field = (uint64_t) text + (entry - eri_live_thread_text);	\
  } while (0)

  th->common.internal = internal;

  SET_TH_RELA (common.thread_entry, eri_live_thread_text_entry);
  th->entry = (uint64_t) eri_live_entry;

  th->top = stack_top;
  th->top_saved = stack_top - ERI_LIVE_ENTRY_SAVED_REG_SIZE;
  th->rsp = stack_top;
  th->stack_size = stack_size;

  SET_TH_RELA (thread_internal_cont, eri_live_thread_text_internal_cont);
  SET_TH_RELA (thread_external_cont, eri_live_thread_text_external_cont);
  SET_TH_RELA (thread_cont_end, eri_live_thread_text_cont_end);

  SET_TH_RELA (thread_ret, eri_live_thread_text_ret);
  SET_TH_RELA (thread_ret_end, eri_live_thread_text_ret_end);

  SET_TH_RELA (thread_resume, eri_live_thread_text_resume);
  SET_TH_RELA (thread_resume_ret, eri_live_thread_text_resume_ret);
  th->resume_ret = (uint64_t) eri_live_resume_ret;
}

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
