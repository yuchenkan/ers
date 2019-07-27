#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/lock.h>
#include <lib/syscall.h>
#include <lib/malloc.h>

#include <common/common.h>
#include <common/entry.h>

#include <live/rtld.h>

#include <plain/thread.h>

struct sig_act
{
  eri_lock_t lock;
  struct eri_sigaction act;
};

struct thread_group
{
  struct eri_mtpool *pool;
  struct eri_range map_range;
  struct sig_act sig_acts[ERI_NSIG - 1];
};

struct thread
{
  struct thread_group *group;

  struct eri_entry *entry;

  struct eri_stack sig_alt_stack;

  eri_aligned16 uint8_t sig_stack[ERI_MINSIGSTKSZ];
  eri_aligned16 uint8_t stack[4096];
};

static eri_noreturn void main_entry (struct eri_entry *entry);
static eri_noreturn void sig_action (struct eri_entry *entry);

static void sig_handler (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *ctx);

static struct thread *
create (struct thread_group *group)
{
  struct thread *th = eri_assert_mtmalloc (group->pool, sizeof *th);
  th->group = group;

  struct eri_entry__create_args args = {
    group->pool, &group->map_range, th, th->stack + sizeof (th->stack),
    main_entry, sig_action
  };

  th->entry = eri_entry__create (&args);
  return th;
}

static void
destroy (struct thread *th)
{
  eri_entry__destroy (th->entry);
  eri_assert_mtfree (th->group->pool, th);
}

static eri_noreturn void
start (struct thread *th, eri_sigset_t mask)
{
  eri_assert_syscall (sigaltstack, 0, &th->sig_alt_stack);
  struct eri_stack st = {
    (uint64_t) th->sig_stack, ERI_SS_AUTODISARM, sizeof (th->sig_stack)
  };
  *(void **) th->sig_stack = th;
  eri_assert_syscall (sigaltstack, &st, 0);

  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_GS, th->entry);
  eri_assert_sys_sigprocmask (&mask, 0);

  eri_entry__leave (th->entry);
}

eri_noreturn void
eri_plain_start (struct eri_live_rtld_args *rtld_args)
{
  struct eri_mtpool *pool = eri_init_mtpool_from_buf (
				rtld_args->buf, rtld_args->buf_size, 0);
  struct thread_group *group
			= eri_assert_malloc (&pool->pool, sizeof *group);
  group->pool = pool;

  int32_t sig;
  for (sig = 1; sig < ERI_NSIG; ++sig)
    {
      eri_assert_sys_sigaction (sig, 0, &group->sig_acts[sig - 1].act);
      void *act = group->sig_acts[sig - 1].act.act;
      if (act != ERI_SIG_DFL && act != ERI_SIG_IGN)
	{
	  struct eri_sigaction act = {
	    sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK,
	    eri_assert_sys_sigreturn
	  };
	  eri_sig_fill_set (&act.mask);
	  eri_assert_sys_sigaction (sig, &act, 0);
        }
    }

  group->map_range.start = rtld_args->map_start;
  group->map_range.end = rtld_args->map_end;

  struct thread *th = create (group);

  struct eri_registers *regs = eri_entry__get_regs (th->entry);
  eri_memset (regs, 0, sizeof regs);
  regs->rsp = rtld_args->rsp;
  regs->rdx = rtld_args->rdx;
  regs->rip = rtld_args->rip;

  eri_jump (eri_entry__get_stack (th->entry) - 8, start, th,
	    (void *) rtld_args->sig_mask, 0);
}

static eri_noreturn void
sig_action (struct eri_entry *entry)
{
  struct thread *th = eri_entry__get_th (entry);
  struct eri_siginfo *info = eri_entry__get_sig_info (entry);

  struct sig_act *sig_act = th->group->sig_acts + info->sig - 1;
  eri_assert_lock (&sig_act->lock);
  struct eri_sigaction act = sig_act->act;
  eri_assert_unlock (&sig_act->lock);

  eri_assert (eri_entry__setup_user_frame (entry, &act,
					   &th->sig_alt_stack, 0, 0));

  eri_entry__clear_signal (entry);
  eri_assert_sys_sigprocmask (&act.mask, 0);

  eri_entry__leave (th->entry);
}

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  struct thread *th = *(void **) ctx->stack.sp;
  struct eri_entry *entry = th->entry;

  if (eri_si_single_step (info)
      && eri_entry__sig_test_clear_single_step (entry, ctx->mctx.rip))
    return;

  if (eri_entry__sig_is_access_fault (entry, info))
    {
      eri_entry__sig_access_fault (entry, &ctx->mctx, info->fault.addr);
      return;
    }

  if (eri_si_sync (info) && eri_within (&th->group->map_range, ctx->mctx.rip))
    eri_assert (eri_si_access_fault (info)
		&& eri_op_is_pub_atomic (eri_entry__get_op_code (entry))
		&& eri_entry__get_interrupt (entry));

  eri_entry__sig_test_interrupted (entry, &ctx->mctx);

  eri_entry__sig_set_test_op_ret (entry,
			eri_struct_of (info, struct eri_sigframe, info));
  eri_sig_fill_set (&ctx->sig_mask);
}

static eri_noreturn void
syscall_clone (struct thread *th)
{
  struct eri_registers *regs = eri_entry__get_regs (th->entry);

  int32_t flags = regs->rdi;
  uint64_t stack = regs->rsi;
  int32_t *ptid = (void *) regs->rdx;
  int32_t *ctid = (void *) regs->r10;
  void *new_tls = (void *) regs->r8;

  eri_assert (flags == ERI_CLONE_SUPPORTED_FLAGS);

  struct thread *cth = create (th->group);
  struct eri_registers *cregs = eri_entry__get_regs (cth->entry);

  *cregs = *regs;
  cregs->rsp = stack;

  eri_sigset_t mask, old_mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, &old_mask);

  struct eri_sys_clone_args args = {
    flags, eri_entry__get_stack (cth->entry) - 8, ptid, ctid, new_tls,
    start, cth, (void *) old_mask
  };

  uint64_t res = eri_sys_clone (&args);
  if (eri_syscall_is_error (res)) destroy (cth);

  eri_assert_sys_sigprocmask (&old_mask, 0);
  eri_entry__syscall_leave (th->entry, res);
}

static eri_noreturn void
syscall_rt_sigaction (struct thread *th)
{
  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);

  int32_t sig = regs->rdi;
  const struct eri_sigaction *user_act = (void *) regs->rsi;
  struct eri_sigaction *user_old_act = (void *) regs->rdx;

  if (! eri_sig_catchable (sig))
    eri_entry__syscall_leave (entry, ERI_EINVAL);

  if (! user_act && ! user_old_act)
    eri_entry__syscall_leave (entry, 0);

  struct eri_sigaction act;
  if (user_act && ! eri_entry__copy_obj_from_user (entry, &act, user_act, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  uint8_t hand = user_act
		 && (act.act != ERI_SIG_DFL && act.act != ERI_SIG_IGN);
  struct eri_sigaction set_act;
  if (user_act)
    {
      set_act = act;
      if (hand)
	{
	  set_act.act = sig_handler;
	  set_act.flags = ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK;
	  set_act.restorer = eri_assert_sys_sigreturn;
	  eri_sig_fill_set (&set_act.mask);
	}
    }

  uint64_t res;
  struct eri_sigaction old_act;
  if (user_act)
    {
      if (! eri_entry__syscall_interruptible (entry, &res, (1, &set_act),
					(2, user_old_act ? &old_act : 0)))
	eri_entry__restart (entry);
    }
  else res = eri_entry__syscall (entry, (2, &old_act));

  eri_entry__syscall_leave_if_error (entry, res);

  uint8_t old_hand = user_old_act
	&& (old_act.act != ERI_SIG_DFL && old_act.act != ERI_SIG_IGN);

  struct sig_act *sig_act = th->group->sig_acts + sig - 1;
  if (hand || old_hand)
    {
      eri_assert_lock (&sig_act->lock);
      if (old_hand) old_act = sig_act->act;
      if (hand) sig_act->act = act;
      eri_assert_unlock (&sig_act->lock);
    }

  if (user_old_act
      && ! eri_entry__copy_obj_to_user (entry, user_old_act, &old_act, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  eri_entry__syscall_leave (entry, res);
}

static eri_noreturn void
syscall (struct thread *th)
{
  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);

  int32_t nr = regs->rax;

  if (nr == __NR_exit || nr == __NR_exit_group)
    {
      int32_t status = regs->rdi;
      if (nr == __NR_exit) destroy (th);
      eri_assert_sys_exit_nr (nr, status);
    }
  else if (nr == __NR_clone) syscall_clone (th);
  else if (nr == __NR_rt_sigaction) syscall_rt_sigaction (th);
  else if (nr == __NR_rt_sigreturn)
    {
      struct eri_stack st = {
	(uint64_t) th->sig_stack, ERI_SS_AUTODISARM, sizeof th->sig_stack
      };
      eri_assert (eri_entry__syscall_rt_sigreturn (entry, &st, 0, 0));
      th->sig_alt_stack = st;
      eri_entry__leave (entry);
    }
  else if (nr == __NR_sigaltstack)
    eri_entry__syscall_leave (entry,
	  eri_entry__syscall_sigaltstack (entry, &th->sig_alt_stack, 0));
  else
    {
      uint64_t res;
      if (! eri_entry__syscall_interruptible (entry, &res))
	eri_entry__restart (entry);
      eri_entry__syscall_leave (entry, res);
    }
}

static eri_noreturn void
atomic (struct thread *th)
{
  // TODO
  eri_assert_unreachable ();
}

static eri_noreturn void
main_entry (struct eri_entry *entry)
{
  struct thread *th = eri_entry__get_th (entry);
  uint16_t code = eri_entry__get_op_code (entry);
  if (code == ERI_OP_SYSCALL) syscall (th);
  else if (code == ERI_OP_SYNC_ASYNC) eri_entry__leave (entry);
  else if (eri_op_is_pub_atomic (code)) atomic (th);
  else eri_assert_unreachable ();
}
