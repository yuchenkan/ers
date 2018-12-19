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
  entry->top_saved = stack_top - ERI_LIVE_ENTRY_SAVED_REG_SIZE16;
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

  entry->sig_stack = (uint64_t) sig_stack;
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
  struct eri_live_entry_sigaction_info *act_info
			= (void *) (cur - eri_size_of (*act_info, 16) - 8);

  struct eri_stack stack;
  act_info->rsi = (uint64_t) info;
  act_info->rdx = (uint64_t) ctx;
  eri_live_start_sigaction (sig, &stack, act_info,
			    (*(struct eri_live_thread_entry **) bot)->thread);

  uint8_t switch_stack = stack.size
			 && ! (ctx->mctx.rsp > stack.sp
			       && ctx->mctx.rsp - stack.sp <= stack.size);

  uint64_t size = bot + ERI_LIVE_SIG_STACK_SIZE - cur;
  uint64_t rsp = eri_round_down (
	(switch_stack ? stack.sp + stack.size : ctx->mctx.rsp - 128) - size,
	16) - 8;

  eri_memcpy ((void *) rsp, (void *) cur, size);

  if (ctx->mctx.fpstate)
    ctx->mctx.fpstate = (void *) (rsp + (uint64_t) ctx->mctx.fpstate - cur);

  act_info->rsi = rsp + (uint64_t) info - cur;
  act_info->rdx = rsp + (uint64_t) ctx - cur;
  act_info->rsp = rsp;
}

uint8_t
eri_live_entry_do_clone (struct eri_live_thread_entry *entry,
			 struct eri_sigmask *sig_mask,
			 struct eri_live_entry_clone_info *clone_info,
			 struct eri_live_entry_syscall_info *info);

uint8_t
eri_live_entry_clone (struct eri_live_thread_entry *entry,
		      struct eri_live_thread_entry *child_entry,
		      struct eri_live_entry_clone_info *clone_info,
		      struct eri_live_entry_syscall_info *info)
{
  /* Block all signals for copied sigaltstack.  */
  struct eri_sigset set;
  eri_sigfillset (&set);
  struct eri_sigmask mask;
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK, &set,
		      &mask.mask, ERI_SIG_SETSIZE);
  mask.mask_all = eri_sigset_full (&mask.mask);

#ifndef ERI_NON_TST
  info->rflags &= ~info->tst_clone_tf;
#endif

  child_entry->public.mark
		= ERI_LIVE_ENTRY_MARK_SEC_PART_BIT | entry->public.mark;
  child_entry->public.op = entry->public.op;
  child_entry->public.cont = entry->public.cont;
  child_entry->public.rbx = entry->public.rbx;

  child_entry->rsp = clone_info->child_stack;

  child_entry->syscall_new_thread = 1;

  eri_assert (entry->rflags_saved);
  child_entry->rflags_saved = 1;
  child_entry->tst_skip_ctf = entry->tst_skip_ctf;

  eri_memcpy ((void *) child_entry->top_saved, (void *) entry->top_saved,
	      ERI_LIVE_ENTRY_SAVED_REG_SIZE16);

  child_entry->ext_rbp = entry->ext_rbp;
  child_entry->ext_r12 = entry->ext_r12;
  child_entry->ext_r13 = entry->ext_r13;
  child_entry->ext_r14 = entry->ext_r14;
  child_entry->ext_r15 = entry->ext_r15;

  /* See eri_live_entry_do_clone for the child stack layout.  */

  uint64_t info_size = eri_size_of (struct eri_live_entry_syscall_info, 16);
  uint64_t stack_child_info = child_entry->top_saved - info_size;

#ifndef ERI_NON_TST
  ((struct eri_live_entry_syscall_info *) stack_child_info)->tst_clone_tf
							= info->tst_clone_tf;
#endif

  uint64_t *stack_syscall_ret = (uint64_t *) (stack_child_info - 24);
  *stack_syscall_ret = *(uint64_t *) (entry->top_saved - info_size - 24);

  uint64_t *stack_start = stack_syscall_ret - 1;
  *stack_start = (uint64_t) clone_info->start;

  struct eri_sigmask *stack_child_mask
		= (void *) ((uint64_t) stack_start - eri_size_of (mask, 16));
  *stack_child_mask = mask;

  uint64_t *stack_info = (uint64_t *) stack_child_mask - 2;
  *stack_info = stack_child_info;

  uint64_t *stack_rbx = stack_info - 2;
  *stack_rbx = (uint64_t) child_entry;

  clone_info->child_stack = (uint64_t) stack_rbx;
  return eri_live_entry_do_clone (entry, &mask, clone_info, info);
}
