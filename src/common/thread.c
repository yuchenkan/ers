/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/atomic.h>
#include <lib/syscall.h>
#include <lib/malloc.h>

#include <common/debug.h>
#include <common/thread.h>
#include <common/thread-local.h>

#define th_text_size	(th_text_end - th_text)

#define th_get_text(entry, text) \
  ((uint64_t) (entry) + sizeof (struct eri_thread_entry) + (text - th_text))
#define th_get_enter(entry)	(th_get_text (entry, th_text_enter))
#define th_get_leave(entry)	(th_get_text (entry, th_text_leave))

#define th_copy_text(entry) \
  eri_memcpy ((void *) th_get_text (entry, th_text), th_text, th_text_size)

#define set_mctx(creg, reg, mctx, regs)	mctx->reg = regs->reg;
#define set_mctx_from_regs(mctx, regs) \
  do { struct eri_mcontext *_mctx = mctx;				\
       struct eri_registers *_regs = regs;				\
       _ERI_FOREACH_REG (set_mctx, _mctx, _regs) } while (0)

#define set_regs(creg, reg, regs, mctx)	regs->reg = mctx->reg;
#define set_regs_from_mctx(regs, mctx) \
  do { struct eri_registers *_regs = regs;				\
       struct eri_mcontext *_mctx = mctx;				\
       _ERI_FOREACH_REG (set_regs, _regs, _mctx) } while (0)

struct eri_thread_entry *
eri_thread_entry__create (struct eri_thread_entry__create_args *args)
{
  struct eri_thread_entry *entry = eri_assert_mtmalloc (args->pool,
					sizeof *entry + th_text_size);
  entry->_zero = 0;

  entry->_op.ret = 0;
  entry->_op.args = 0;
  entry->_op.code = ERI_OP_NOP;

  entry->_enter = (uint64_t) enter;
  entry->_th_enter = th_get_enter (entry);
  entry->_th_leave = th_get_leave (entry);

  entry->_sig_wait_pending = 0;
  entry->_sig_pending = 0;
  entry->_sig_swallow_single_step = 0;

  entry->_pool = args->pool;
  entry->_map_range = args->map_range;
  entry->_th = args->th;
  entry->_stack = args->stack;
  entry->_entry = args->entry;
  entry->_sig_action = args->sig_action;

  entry->_test_access = 0;
  entry->_syscall_interrupt = 0;

  th_copy_text (entry);
  return entry;
}

void
eri_thread_entry__destroy (struct eri_thread_entry *entry)
{
  eri_assert_mtfree (entry->_pool, entry);
}

typedef eri_noreturn void (* th_noreturn_call_t) (void *);
#define th_noreturn_call(fn, th)	((th_noreturn_call_t) (fn)) (th)

#define to_swallow_single_step(code) \
  ({ uint16_t _c = code;						\
     _c == ERI_OP_NOP || _c == ERI_OP_SYSCALL || _c == ERI_OP_SYNC_ASYNC; })

eri_noreturn void
sig_action (struct eri_thread_entry *entry)
{
  th_noreturn_call (entry->_sig_action, entry->_th);
}

eri_noreturn void
eri_thread_entry__leave (struct eri_thread_entry *entry)
{
  eri_atomic_store (&entry->_op.ret, 1);
  eri_barrier ();

  if (eri_atomic_load (&entry->_sig_pending))
    {
      entry->_op.ret = 0;
      th_noreturn_call (entry->_sig_action, entry->_th);
    }

  if (to_swallow_single_step (entry->_op.code)
      && entry->_regs.rflags & ERI_RFLAGS_TF)
    entry->_sig_swallow_single_step = 1;

  eri_thread_entry__do_leave (entry);
}

static uint8_t
copy (struct eri_thread_entry *entry,
      void *dst, const void *src, uint64_t size)
{
  if (! eri_thread_entry__test_access (entry)) return 0;

  eri_memcpy (dst, src, size);
  eri_thread_entry__reset_test_access (entry);
  return 1;
}

uint8_t
eri_thread_entry__copy_from (struct eri_thread_entry *entry,
			     void *dst, const void *src, uint64_t size)
{
  return ! eri_cross (entry->_map_range, (uint64_t) src, size)
	 && copy (entry, dst, src, size);
}

uint8_t
eri_thread_entry__copy_to (struct eri_thread_entry *entry,
			   void *dst, const void *src, uint64_t size)
{
  return ! eri_cross (entry->_map_range, (uint64_t) dst, size)
	 && copy (entry, dst, src, size);
}

#define copy_from_size(entry, dst, src, size) \
  eri_thread_entry__copy_from (entry, dst, src, size)
#define copy_to_size(entry, dst, src, size) \
  eri_thread_entry__copy_to (entry, dst, src, size)

#define copy_from(entry, dst, src) \
  ({ typeof (dst) _dst = dst;						\
     copy_from_size (entry, _dst, src, sizeof *_dst); })
#define copy_to(entry, dst, src) \
  ({ typeof (dst) _dst = dst;						\
     copy_to_size (entry, _dst, src, sizeof *_dst); })
#define copy_from_fault(entry, dst, src) \
  (copy_from (entry, dst, src) ? 0 : ERI_EFAULT)
#define copy_to_fault(entry, dst, src) \
  (copy_to (entry, dst, src) ? 0 : ERI_EFAULT)

uint64_t
eri_thread_entry__syscall_get_rt_sigprocmask (struct eri_thread_entry *entry,
			struct eri_sigset *old_mask, struct eri_sigset *mask)
{
  int32_t how = entry->_regs.rdi;
  const struct eri_sigset *user_mask = (void *) entry->_regs.rsi;
  uint64_t sig_set_size = entry->_regs.r10;

  if ((how != ERI_SIG_BLOCK && how != ERI_SIG_UNBLOCK
       && how != ERI_SIG_SETMASK)
      || sig_set_size != ERI_SIG_SETSIZE) return ERI_EINVAL;

  if (! user_mask) return 0;

  if (! copy_from (entry, mask, user_mask)) return ERI_EFAULT;

  if (how == ERI_SIG_BLOCK) eri_sig_union_set (mask, old_mask);
  else if (how == ERI_SIG_UNBLOCK)
    {
      struct eri_sigset old = *old_mask;
      eri_sig_diff_set (&old, mask);
      *mask = old;
    }

  return 0;
}

uint64_t
eri_thread_entry__syscall_set_rt_sigprocmask (struct eri_thread_entry *entry,
					      struct eri_sigset *old_mask)
{
  struct eri_sigset *user_old_mask = (void *) entry->_regs.rdx;
  if (! user_old_mask) return 0;
  return copy_to_fault (entry, user_old_mask, old_mask);
}

static uint8_t
on_sig_alt_stack (const struct eri_stack *stack, uint64_t rsp)
{
  return ! (stack->flags & ERI_SS_AUTODISARM)
	 && rsp > stack->sp && rsp <= stack->sp + stack->size;
}

static void
disable_sig_alt_stack (struct eri_stack *stack)
{
  stack->sp = 0;
  stack->flags = ERI_SS_DISABLE;
  stack->size = 0;
}

static uint64_t
set_sig_alt_stack (struct eri_stack *stack, uint64_t rsp,
		   struct eri_stack *new_stack)
{
  if (on_sig_alt_stack (stack, rsp)) return ERI_EPERM;

  int32_t flags = new_stack->flags & ERI_SS_FLAG_BITS;
  int32_t mode = new_stack->flags & ~ERI_SS_FLAG_BITS;
  if (mode != ERI_SS_DISABLE && mode != ERI_SS_ONSTACK && mode != 0)
    return ERI_EINVAL;

  if (mode == ERI_SS_DISABLE) disable_sig_alt_stack (new_stack);
  else
    {
      if (new_stack->size < ERI_MINSIGSTKSZ) return ERI_ENOMEM;
      new_stack->flags = flags;
    }

  *stack = *new_stack;
  return 0;
}

uint64_t
eri_thread_entry__syscall_sigaltstack (struct eri_thread_entry *entry,
				       struct eri_stack *stack)
{
  const struct eri_stack *user_stack = (void *) entry->_regs.rdi;
  struct eri_stack *user_old_stack = (void *) entry->_regs.rsi;
  uint64_t rsp = entry->_regs.rsp;

  if (! user_stack && ! user_old_stack) return 0;

  struct eri_stack old_stack;
  if (user_old_stack)
    {
      old_stack = *stack;
      old_stack.flags |= on_sig_alt_stack (stack, rsp) ? ERI_SS_ONSTACK : 0;
    }

  if (user_stack)
    {
      struct eri_stack new_stack;
      if (! copy_from (entry, &new_stack, user_stack)) return ERI_EFAULT;

      uint64_t res = set_sig_alt_stack (stack, rsp, &new_stack);
      if (eri_syscall_is_error (res)) return res;
    }

  if (! user_old_stack) return 0;

  return copy_to_fault (entry, user_old_stack, &old_stack);
}

uint8_t
eri_thread_entry__syscall_rt_sigreturn (struct eri_thread_entry *entry,
			struct eri_stack *stack, struct eri_sigset *mask)
{
  uint64_t rsp = entry->_regs.rsp;
  const struct eri_sigframe *user_frame = (void *) (rsp - 8);

  struct eri_sigframe frame;
  if (! copy_from (entry, &frame, user_frame)) return 0;

  uint8_t buf[ERI_MINSIGSTKSZ];
  uint64_t top = (uint64_t) buf + sizeof buf;

  struct eri_ucontext *ctx = &frame.ctx;
  if (ctx->mctx.fpstate)
    {
      const struct eri_fpstate *user_fpstate = ctx->mctx.fpstate;
      struct eri_fpstate_base fpstate_base;
      if (! copy_from (entry, &fpstate_base, user_fpstate)) return 0;

      uint64_t fpstate_size = fpstate_base.size;
      top = fpstate_size + 64 + sizeof frame + 16 + 8 >= ERI_MINSIGSTKSZ
		? 0 : eri_round_down (top - fpstate_size, 64);
      if (! copy_from_size (entry, (void *) top, user_fpstate, fpstate_size))
	return 0;

      ctx->mctx.fpstate = (void *) top;
    }

  *mask = ctx->sig_mask;
  eri_sig_empty_set (&ctx->sig_mask);

  struct eri_stack st = *stack;
  set_sig_alt_stack (stack, rsp, &ctx->stack);
  ctx->stack = st;

  set_regs_from_mctx (&entry->_regs, &ctx->mctx);
  entry->_leave = entry->_regs.rip;

  frame.restorer = eri_assert_sys_sigreturn;

  struct eri_sigframe *sig_frame
	= (void *) eri_round_down (top - sizeof *sig_frame, 16) - 8;
  *sig_frame = frame;

  sig_return_back (sig_frame);
  return 1;
}

uint64_t
eri_thread_entry__syscall_get_rt_sigtimedwait (
			struct eri_thread_entry *entry,
			struct eri_sigset *set, struct eri_timespec *timeout)
{
  const struct eri_sigset *user_set = (void *) entry->_regs.rdi;
  const struct eri_timespec *user_timeout = (void *) entry->_regs.rdx;
  uint64_t size = entry->_regs.r10;

  if (size != ERI_SIG_SETSIZE) return ERI_EINVAL;

  if (! copy_from (entry, set, user_set)) return ERI_EFAULT;

  return user_timeout ? copy_from_fault (entry, timeout, user_timeout) : 0;
}

uint64_t
eri_thread_entry__syscall_get_signalfd (struct eri_thread_entry *entry,
				int32_t *flags, struct eri_sigset *mask)
{
  const struct eri_sigset *user_mask = (void *) entry->_regs.rsi;
  uint64_t size = entry->_regs.rdx;
  *flags = entry->_regs.rax == __NR_signalfd4 ? entry->_regs.r10 : 0;

  if ((*flags & ~(ERI_SFD_CLOEXEC | ERI_SFD_NONBLOCK))
      || size != ERI_SIG_SETSIZE) return ERI_EINVAL;

  return copy_from (entry, mask, user_mask) ? 0 : ERI_EINVAL; /* by kernel */
}

struct eri_sigframe *
eri_thread_entry__setup_user_frame (
	struct eri_thread_entry *entry, const struct eri_sigaction *act,
	struct eri_stack *stack, const struct eri_sigset *mask)
{
  struct eri_registers *regs = &entry->_regs;

  struct eri_sigframe frame;
  /* XXX: default restorer */
  frame.restorer = act->flags & ERI_SA_RESTORER ? act->restorer : 0;
  frame.ctx = entry->_ctx;
  frame.ctx.stack = *stack;
  set_mctx_from_regs (&frame.ctx.mctx, regs);
  frame.ctx.sig_mask = *mask;
  frame.info = entry->_sig_info;

  uint8_t alt = (act->flags & ERI_SA_ONSTACK)
		&& ! on_sig_alt_stack (stack, regs->rsp);
  uint64_t rsp = alt ? stack->sp + stack->size : regs->rsp - 128;

  if (stack->flags & ERI_SS_AUTODISARM) disable_sig_alt_stack (stack);

  if (entry->_ctx.mctx.fpstate)
    {
      uint32_t fpstate_size = entry->_fpstate.base.size;
      rsp = eri_round_down (rsp - fpstate_size, 64);
      if (! copy_to_size (entry, (void *) rsp,
			  &entry->_fpstate, fpstate_size)) return 0;
      frame.ctx.mctx.fpstate = (void *) rsp;
    }

  struct eri_sigframe *user_frame
	= (void *) (eri_round_down (rsp - sizeof *user_frame, 16) - 8);

  entry->_leave = (uint64_t) act->act;
  regs->rax = 0;
  regs->rdi = frame.info.sig;
  regs->rsi = (uint64_t) &user_frame->info;
  regs->rdx = (uint64_t) &user_frame->ctx;
  regs->rsp = (uint64_t) user_frame;
  regs->rip = (uint64_t) entry->_leave;
  regs->rflags &= ~(ERI_RFLAGS_TF | ERI_RFLAGS_DF | ERI_RFLAGS_RF);

  return copy_to (entry, user_frame, &frame) ? user_frame : 0;
}

void
eri_thread_entry__set_signal (struct eri_thread_entry *entry,
	const struct eri_siginfo *info, const struct eri_ucontext *ctx)
{
  const struct eri_fpstate *fpstate = ctx->mctx.fpstate;

  entry->_ctx = *ctx;
  if (fpstate) eri_memcpy (&entry->_fpstate, fpstate, fpstate->base.size);
  entry->_sig_info = *info;
  entry->_sig_pending = 1;
  if (entry->_sig_wait_pending)
    eri_assert_syscall (futex, &entry->_sig_pending, ERI_FUTEX_WAKE, 1);
}

uint8_t
eri_thread_entry__sig_wait_pending (struct eri_thread_entry *entry,
				    struct eri_timespec *timeout)
{
  eri_atomic_store (&entry->_sig_wait_pending, 1);
  eri_barrier ();

  uint8_t res = eri_assert_sys_futex_wait (&entry->_sig_pending, 0, timeout);
  entry->_sig_wait_pending = 0;
  return res;
}

uint8_t
eri_thread_entry__sig_test_clear_single_step (
			struct eri_thread_entry *entry, uint64_t rip)
{
  return ! entry->_op.ret || eri_within (entry->_map_range, rip)
	 || eri_atomic_exchange (&entry->_sig_swallow_single_step, 0);
}

eri_noreturn void
eri_thread_entry__sig_op_ret (struct eri_thread_entry *entry,
			      struct eri_sigframe *frame)
{
  entry->_op.ret = 0;
  entry->_sig_swallow_single_step = 0;

  struct eri_mcontext *mctx = &frame->ctx.mctx;
  uint8_t internal = eri_within (entry->_map_range, mctx->rip);

  if (! internal) set_regs_from_mctx (&entry->_regs, mctx);

  sig_op_ret (entry, frame);
}

void
eri_thread_entry__sig_test_syscall_interrupted (
		struct eri_thread_entry *entry, struct eri_mcontext *mctx)
{
  uint64_t intr = entry->_syscall_interrupt;
  if (intr && mctx->rip != intr)
    {
      mctx->rax = ERI_EINTR;
      mctx->rip = intr;
    }
}
