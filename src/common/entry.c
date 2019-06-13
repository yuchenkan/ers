/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/atomic.h>
#include <lib/syscall.h>
#include <lib/malloc.h>

#include <common/debug.h>
#include <common/entry.h>
#include <common/entry-local.h>

#define th_text_size	(th_text_end - th_text)

#define th_get_text(entry, text) \
  ((uint64_t) (entry) + sizeof (struct eri_entry) + (text - th_text))
#define th_get_enter(entry)	(th_get_text (entry, th_text_enter))
#define th_get_leave(entry)	(th_get_text (entry, th_text_leave))

#define th_copy_text(entry) \
  eri_memcpy ((void *) th_get_text (entry, th_text), th_text, th_text_size)

struct eri_entry *
eri_entry__create (struct eri_entry__create_args *args)
{
  struct eri_entry *entry = eri_assert_mtmalloc (args->pool,
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
  entry->_main_entry = args->entry;
  entry->_sig_action = args->sig_action;
  entry->_exit = args->exit;

  entry->_test_access = 0;
  entry->_syscall_interrupt = 0;

  th_copy_text (entry);
  return entry;
}

void
eri_entry__destroy (struct eri_entry *entry)
{
  eri_assert_mtfree (entry->_pool, entry);
}

typedef eri_noreturn void (* th_noreturn_call_t) (void *);
#define th_noreturn_call(fn, entry)	((th_noreturn_call_t) (fn)) (entry)

#define to_swallow_single_step(code) \
  ({ uint16_t _c = code;						\
     _c == ERI_OP_NOP || _c == ERI_OP_SYSCALL || _c == ERI_OP_SYNC_ASYNC; })

static eri_noreturn void
sig_action (struct eri_entry *entry)
{
  entry->_op.ret = 0;
  entry->_op.code = ERI_OP_NOP;
  th_noreturn_call (entry->_sig_action, entry);
}

eri_noreturn void
eri_entry__do_leave (struct eri_entry *entry)
{
  if (entry->_exit) th_noreturn_call (entry->_exit, entry);
  leave (entry);
}

eri_noreturn void
eri_entry__leave (struct eri_entry *entry)
{
  eri_atomic_store (&entry->_op.ret, 1, 1);

  if (entry->_sig_pending)
    {
      if (entry->_op.code == ERI_OP_SYNC_ASYNC)
	entry->_regs.rip = entry->_start;
      sig_action (entry);
    }

  if (to_swallow_single_step (entry->_op.code)
      && entry->_regs.rflags & ERI_RFLAGS_TF)
    entry->_sig_swallow_single_step = 1;

  eri_entry__do_leave (entry);
}

eri_noreturn void
eri_entry__syscall_leave (struct eri_entry *entry, uint64_t res)
{
  entry->_regs.rax = res;
  entry->_regs.rcx = entry->_regs.rip;
  entry->_regs.r11 = entry->_regs.rflags;
  eri_entry__leave (entry);
}

static eri_noreturn void
atomic_post_interleave (struct eri_entry *entry)
{
  entry->_entry = entry->_main_entry;
  entry->_regs.rip = entry->_atomic.leave;
  eri_entry__leave (entry);
}

eri_noreturn void
eri_entry__atomic_interleave (struct eri_entry *entry, uint64_t val)
{
  entry->_atomic.val = val;
  entry->_entry = atomic_post_interleave;
  eri_entry__do_leave (entry);
}

uint64_t
eri_entry__copy_from (struct eri_entry *entry,
		      void *dst, const void *src, uint64_t size)
{
  uint64_t done;
  if (! eri_entry__test_access (entry, src, size, &done))
    {
      eri_assert (done != size);
      return done;
    }
  eri_memcpy (dst, src, size);
  eri_entry__reset_test_access (entry);
  return size;
}

uint64_t
eri_entry__copy_to (struct eri_entry *entry,
		    void *dst, const void *src, uint64_t size)
{
  uint64_t done;
  if (! eri_entry__test_access (entry, dst, size, &done))
    {
      eri_assert (done != size);
      return done;
    }
  eri_memcpy (dst, src, size);
  eri_entry__reset_test_access (entry);
  return size;
}

#define copy_from_size(entry, dst, src, size) \
  ({ uint64_t _size = size;						\
     eri_entry__copy_from (entry, dst, src, _size) == _size; })
#define copy_to_size(entry, dst, src, size) \
  ({ uint64_t _size = size;						\
     eri_entry__copy_to (entry, dst, src, _size) == _size; })

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
eri_entry__syscall_get_rt_sigprocmask (struct eri_entry *entry,
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
eri_entry__syscall_set_rt_sigprocmask (struct eri_entry *entry,
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
eri_entry__syscall_sigaltstack (struct eri_entry *entry,
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
eri_entry__syscall_rt_sigreturn (struct eri_entry *entry,
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

  eri_registers_from_mcontext (&entry->_regs, &ctx->mctx);

  frame.restorer = eri_assert_sys_sigreturn;

  struct eri_sigframe *sig_frame
	= (void *) eri_round_down (top - sizeof *sig_frame, 16) - 8;
  *sig_frame = frame;

  sig_return_back (sig_frame);
  return 1;
}

uint64_t
eri_entry__syscall_get_rt_sigtimedwait (struct eri_entry *entry,
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
eri_entry__syscall_get_signalfd (struct eri_entry *entry, int32_t *flags)
{
  uint64_t size = entry->_regs.rdx;
  *flags = entry->_regs.rax == __NR_signalfd4 ? entry->_regs.r10 : 0;

  return (*flags & ~(ERI_SFD_CLOEXEC | ERI_SFD_NONBLOCK))
	 || size != ERI_SIG_SETSIZE ? ERI_EINVAL : 0;
}

uint64_t
eri_entry__syscall_get_rw_iov (struct eri_entry *entry,
	struct eri_mtpool *pool, struct eri_iovec **iov, int32_t *iov_cnt)
{
  int32_t dummy;
  if (! iov_cnt) iov_cnt = &dummy;

  const struct eri_iovec *user_iov = (void *) entry->_regs.rsi;
  *iov_cnt = entry->_regs.rdx;

  if (*iov_cnt > ERI_UIO_MAXIOV) return ERI_EINVAL;

  /* XXX: fastiov */
  uint64_t iov_size = sizeof **iov * *iov_cnt;
  *iov = eri_assert_mtmalloc (pool, iov_size);

  if (eri_entry__copy_from (entry, *iov, user_iov, iov_size) != iov_size)
    {
      eri_assert_mtfree (pool, *iov);
      return ERI_EFAULT;
    }

  return 0;
}

struct eri_sigframe *
eri_entry__setup_user_frame (
	struct eri_entry *entry, const struct eri_sigaction *act,
	struct eri_stack *stack, const struct eri_sigset *mask)
{
  struct eri_registers *regs = &entry->_regs;

  struct eri_sigframe frame;
  /* XXX: default restorer */
  frame.restorer = act->flags & ERI_SA_RESTORER ? act->restorer : 0;
  frame.ctx = entry->_ctx;
  frame.ctx.stack = *stack;
  eri_mcontext_from_registers (&frame.ctx.mctx, regs);
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

  regs->rax = 0;
  regs->rdi = frame.info.sig;
  regs->rsi = (uint64_t) &user_frame->info;
  regs->rdx = (uint64_t) &user_frame->ctx;
  regs->rsp = (uint64_t) user_frame;
  regs->rip = (uint64_t) act->act;
  regs->rflags &= ~(ERI_RFLAGS_TF | ERI_RFLAGS_DF | ERI_RFLAGS_RF);

  return copy_to (entry, user_frame, &frame) ? user_frame : 0;
}

void
eri_entry__set_signal (struct eri_entry *entry,
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
eri_entry__sig_wait_pending (struct eri_entry *entry,
			     struct eri_timespec *timeout)
{
  eri_atomic_store (&entry->_sig_wait_pending, 1, 1);

  uint8_t res = eri_assert_sys_futex_wait (&entry->_sig_pending, 0, timeout);
  entry->_sig_wait_pending = 0;
  return res;
}

uint8_t
eri_entry__sig_test_clear_single_step (struct eri_entry *entry, uint64_t rip)
{
  return ! entry->_op.ret || eri_within (entry->_map_range, rip)
	 || eri_atomic_exchange (&entry->_sig_swallow_single_step, 0, 0);
}

void
_eri_entry__sig_op_ret (struct eri_entry *entry, struct eri_sigframe *frame)
{
  entry->_op.ret = 0;
  entry->_sig_swallow_single_step = 0;

  struct eri_mcontext *mctx = &frame->ctx.mctx;

  if (! eri_within (entry->_map_range, mctx->rip))
    {
      if (entry->_op.code == ERI_OP_SYNC_ASYNC
	  && mctx->rip == entry->_regs.rip)
	mctx->rip = entry->_start;
      eri_registers_from_mcontext (&entry->_regs, mctx);
    }
  else if (entry->_op.code == ERI_OP_SYNC_ASYNC)
    entry->_regs.rip = entry->_start;

  entry->_op.code = ERI_OP_NOP;

  mctx->rip = (uint64_t) sig_action;
  mctx->rsp = (uint64_t) entry->_stack - 8;
  mctx->rdi = (uint64_t) entry;
  mctx->rflags = 0;
}

void
eri_entry__sig_test_syscall_interrupted (
		struct eri_entry *entry, struct eri_mcontext *mctx)
{
  uint64_t intr = entry->_syscall_interrupt;
  if (intr && mctx->rip != intr)
    {
      mctx->rax = ERI_EINTR;
      mctx->rip = intr;
    }
}