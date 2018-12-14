#include "live.h"
#include "live-entry.h"

#include "lib/util.h"
#include "lib/syscall.h"

void
eri_live_init_thread_entry (struct eri_live_thread_entry *entry,
		 void *thread, uint64_t stack_top, uint64_t stack_size,
		 void *sig_stack)
{
  uint8_t *text = (uint8_t *) entry + eri_size_of (*entry, 16);
#define TEXT(text)	_ERS_PASTE (eri_live_thread_entry_, text)
  eri_memcpy (text, TEXT (text), TEXT (text_end) - TEXT (text));
#define SET_ENTRY_RELA(field, val) \
  do {									\
    entry->field = (uint64_t) text + (TEXT (val) - TEXT (text));	\
  } while (0)

  entry->public.mark = 0;
  entry->public.op = 0;
  entry->public.ret = 0;
  entry->public.cont = 0;
  entry->public.dir = 0;

  SET_ENTRY_RELA (public.thread_entry, text_entry);
  entry->entry = (uint64_t) eri_live_entry;

  entry->top = stack_top;
  entry->top_saved = stack_top - ERI_LIVE_ENTRY_SAVED_REG_SIZE;
  entry->rsp = stack_top;
  entry->stack_size = stack_size;

  SET_ENTRY_RELA (thread_internal_cont, text_internal_cont);
  SET_ENTRY_RELA (thread_external_cont, text_external_cont);
  SET_ENTRY_RELA (thread_cont_end, text_cont_end);

  SET_ENTRY_RELA (thread_ret, text_ret);
  SET_ENTRY_RELA (thread_ret_end, text_ret_end);

  SET_ENTRY_RELA (thread_resume, text_resume);
  SET_ENTRY_RELA (thread_resume_ret, text_resume_ret);
  entry->resume_ret = (uint64_t) eri_live_resume_ret;

  entry->complete_start = 0;

  entry->fix_restart = 0;
  entry->restart = 0;

  entry->thread = thread;

  entry->tst_skip_ctf = 0;

  *(struct eri_live_thread_entry **) sig_stack = entry;
}

void
eri_tst_live_assert_thread_entry (struct eri_live_thread_entry *entry)
{
  eri_assert (entry->public.mark == 0);
  eri_assert (entry->public.dir == 0);
  eri_assert (entry->rsp == entry->top);
  eri_assert (entry->fix_restart == 0);
  eri_assert (entry->restart == 0);
}

void
eri_live_entry_start_sigaction (int32_t sig, struct eri_siginfo *info,
			struct eri_ucontext *ctx, uint64_t bot, uint64_t cur)
{
  /* TODO: fix ctx->stack */
  uint64_t size = bot + ERI_LIVE_SIG_STACK_SIZE - cur;
  uint64_t rsp = eri_round_down (ctx->mctx.rsp - 128 - size, 16) - 8;
  eri_memcpy ((void *) rsp, (void *) cur, size);

  if (ctx->mctx.fpstate)
    ctx->mctx.fpstate = (void *) (rsp + (uint64_t) ctx->mctx.fpstate - cur);

  struct eri_live_entry_sigaction_info *act_info
			= (void *) (cur - eri_size_of (*act_info, 16) - 8);

  act_info->rsi = rsp + (uint64_t) info - cur;
  act_info->rdx = rsp + (uint64_t) ctx - cur;
  act_info->rsp = rsp;
  eri_live_start_sigaction (sig, act_info,
			    (*(struct eri_live_thread_entry **) bot)->thread);
}
