/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/list.h>
#include <lib/atomic-common.h>
#include <lib/lock.h>
#include <lib/syscall.h>
#include <lib/malloc.h>

#include <common/common.h>
#include <common/debug.h>
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

  eri_lock_t thread_lock;
  ERI_LST_LIST_FIELDS (thread)
};

struct thread
{
  struct thread_group *group;

  ERI_LST_NODE_FIELDS (thread)

  struct eri_entry *entry;

  uint8_t sig_tf;
  struct eri_stack sig_alt_stack;

  eri_aligned16 uint8_t sig_stack[4096];
  eri_aligned16 uint8_t stack[8192];
};

ERI_DEFINE_LIST (static, thread, struct thread_group, struct thread)

static eri_noreturn void main_entry (struct eri_entry *entry);
static eri_noreturn void sig_action (struct eri_entry *entry);

static void sig_handler (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *ctx);

static struct thread *
create (struct thread_group *group)
{
  eri_assert_lock (&group->thread_lock);

  struct thread *th = eri_assert_mtmalloc (group->pool, sizeof *th);
  th->group = group;

  struct eri_entry__create_args args = {
    group->pool, &group->map_range, th, th->stack + sizeof (th->stack),
    main_entry, sig_action
  };

  th->entry = eri_entry__create (&args);
  th->sig_tf = 0;

  thread_lst_append (group, th);
  eri_assert_unlock (&group->thread_lock);
  return th;
}

static void
destroy (struct thread *th)
{
  struct thread_group *group = th->group;
  eri_assert_lock (&group->thread_lock);
  thread_lst_remove (group, th);
  eri_entry__destroy (th->entry);
  eri_assert_mtfree (group->pool, th);
  eri_assert_unlock (&group->thread_lock);
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
  if (rtld_args->envp)
    {
      char **p;
      for (p = rtld_args->envp; *p; ++p)
	eri_get_arg_int (*p, "ERI_DEBUG=", &eri_global_enable_debug, 10);
    }
  eri_debug ("base = %lx\n", rtld_args->base);

  struct eri_mtpool *pool = eri_init_mtpool_from_buf (
				rtld_args->buf, rtld_args->buf_size, 1);
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

  group->thread_lock = 0;
  ERI_LST_INIT_LIST (thread, group);

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

  if (th->sig_tf)
    {
      eri_entry__get_regs (entry)->rflags |= ERI_RFLAGS_TF;
      th->sig_tf = 0;
    }

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

  if (ctx->mctx.rflags & ERI_RFLAGS_TF) th->sig_tf = 1;

  ctx->mctx.rflags &= ~ERI_RFLAGS_TF;
  eri_sig_fill_set (&ctx->sig_mask);
}

static eri_noreturn void
syscall_clone (struct thread *th)
{
  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);

  int32_t flags = regs->rdi;
  uint64_t stack = regs->rsi;
  int32_t *ptid = (void *) regs->rdx;
  int32_t *ctid = (void *) regs->r10;
  void *new_tls = (void *) regs->r8;

  if (flags & ERI_CLONE_VM)
    {
      eri_xassert (flags & ERI_CLONE_THREAD, eri_info);

      eri_sigset_t mask, old_mask;
      eri_sig_fill_set (&mask);
      eri_assert_sys_sigprocmask (&mask, &old_mask);

      if (eri_entry__sig_is_pending (entry))
	{
	  eri_assert_sys_sigprocmask (&old_mask, 0);
	  eri_entry__restart (entry);
	}

      struct thread *cth = create (th->group);
      struct eri_registers *cregs = eri_entry__get_regs (cth->entry);

      *cregs = *regs;
      cregs->rsp = stack;
      cregs->rax = 0;

      struct eri_sys_clone_args args = {
	flags, eri_entry__get_stack (cth->entry) - 8, ptid, ctid, new_tls,
	start, cth, (void *) old_mask
      };

      uint64_t res = eri_sys_clone (&args);
      if (eri_syscall_is_error (res)) destroy (cth);

      eri_assert_sys_sigprocmask (&old_mask, 0);
      eri_entry__syscall_leave (entry, res);
    }
  else
    {
      uint64_t res;
      if (! eri_entry__syscall_interruptible (entry, &res, (1, 0)))
	eri_entry__restart (entry);

      if (res == 0)
	{
	  if (stack) regs->rsp = stack;
	  struct thread *t, *nt;
	  ERI_LST_FOREACH_SAFE (thread, th->group, t, nt)
	    if (t != th) destroy (t);
	}
      eri_entry__syscall_leave (th->entry, res);
    }
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

#define _MOV_LM(label, dst, reg) \
  leaq	label(%%rip), reg;						\
  movq	reg, dst

#define _ATOMIC_INTR(name, intr, restart, pend, res, at, ...) \
  ERI_STR (								\
	  _MOV_LM (ERI_PASTE (.latomic_intr_restart_, name),		\
		   %ERI_PASTE (q, restart), %%r11);			\
	  _MOV_LM (ERI_PASTE (.latomic_intr_, name),			\
		   %ERI_PASTE (q, intr), %%r11);			\
	  cmpl	$0, %pend;						\
	  je	ERI_PASTE (.latomic_, name);				\
	ERI_PASTE (.latomic_intr_restart_, name):			\
	  movq	$0, %ERI_PASTE (q, intr);				\
	  xorb	%ERI_PASTE (b, res), %ERI_PASTE (b, res);		\
	  jmp	ERI_PASTE (.latomic_return_, name);			\
	ERI_PASTE (.latomic_, name):					\
	  at ((ERI_PASTE (.latomic_intr_, name), intr), ##__VA_ARGS__);	\
	  movb	$1, %ERI_PASTE (b, res);				\
	ERI_PASTE (.latomic_return_, name):)

#define __ATOMIC_INTR_RESET(l, intr) \
l:									\
  movq	$0, %ERI_PASTE(q, intr)

#define _ATOMIC_INTR_RESET(lintr) \
  __ATOMIC_INTR_RESET lintr

#define _ATOMIC_VAL(_e)	eri_entry__get_atomic_val (_e)
#define _ATOMIC_MEM(_e)	*(uint64_t *) eri_entry__get_atomic_mem (_e)
#define _ATOMIC_RFLAGS(_e)	(eri_entry__get_regs (_e)->rflags)

#define _ATOMIC_INTR_WRITES(_e) \
  "=m" (_e->_interrupt), "=m" (_e->_interrupt_restart)

#define _ATOMIC_INTR_READS(_e)	"m" (_e->_sig_pending)

#define _ATOMIC_INTR_LOAD(lintr, sz, _m, _r) \
  ERI_PASTE (mov, sz)	%_m, %_ERI_ASM_TEMPLATE_SIZE (sz, _r);		\
  _ATOMIC_INTR_RESET (lintr)

#define _ATOMIC_LOAD(_e, sz, val) \
  ({ uint64_t *_v = val;						\
     uint8_t _r;							\
     asm volatile (_ATOMIC_INTR (ERI_PASTE (load, sz), 2, 3, 5, 0,	\
				 _ATOMIC_INTR_LOAD, sz, 4, 1)		\
		   : "=r" (_r), "=r" (*_v), _ATOMIC_INTR_WRITES (_e)	\
		   : "m" (_ATOMIC_MEM (_e)), _ATOMIC_INTR_READS (_e)	\
		   : "r11"); _r; })

#define _ATOMIC_INTR_STORE(lintr, sz, _r, _m) \
  ERI_PASTE (mov, sz)	%_ERI_ASM_TEMPLATE_SIZE (sz, _r), %_m;		\
  _ATOMIC_INTR_RESET (lintr)

#define _ATOMIC_STORE(_e, sz) \
  ({ uint8_t _r;							\
     asm volatile (_ATOMIC_INTR (ERI_PASTE (store, sz), 2, 3, 5, 0,	\
				 _ATOMIC_INTR_STORE, sz, 4, 1)		\
		   : "=r" (_r), "=m" (_ATOMIC_MEM (_e)),		\
		     _ATOMIC_INTR_WRITES (_e)				\
		   : "r" (_ATOMIC_VAL (_e)), _ATOMIC_INTR_READS (_e)	\
		   : "r11"); _r; })

#define _ATOMIC_INTR_COMM(lintr, op, sz, _m, _f) \
  pushq	%ERI_PASTE (p, _f); popf;					\
  lock ERI_PASTE (op, sz)	%_m;					\
  _ATOMIC_INTR_RESET (lintr);						\
  pushfq; popq	%ERI_PASTE (p, _f)

#define _ATOMIC_COMM(cop, op, _e, sz) \
  ({ uint8_t _r;							\
     asm volatile (_ATOMIC_INTR (ERI_PASTE (op, sz), 3, 4, 5, 0,	\
				 _ATOMIC_INTR_COMM, op, sz, 1, 2)	\
		   : "=r" (_r), "+m" (_ATOMIC_MEM (_e)),		\
		     "+r" (_ATOMIC_RFLAGS (_e)),			\
		     _ATOMIC_INTR_WRITES (_e)				\
		   : _ATOMIC_INTR_READS (_e) : "r11", "cc"); _r; })

#define _ATOMIC_INTR_COMM2(lintr, op, sz, _r, _m, _f) \
  pushq	%ERI_PASTE (p, _f); popf;					\
  lock ERI_PASTE (op, sz)	%_ERI_ASM_TEMPLATE_SIZE (sz, _r), %_m;	\
  _ATOMIC_INTR_RESET (lintr);						\
  pushfq; popq	%ERI_PASTE (p, _f)

#define _ATOMIC_COMM2(cop, op, _e, sz) \
  ({ uint8_t _r;							\
     asm volatile (_ATOMIC_INTR (ERI_PASTE (op, sz), 3, 4, 6, 0,	\
				 _ATOMIC_INTR_COMM2, op, sz, 5, 1, 2)	\
		   : "=r" (_r), "+m" (_ATOMIC_MEM (_e)),		\
		     "+r" (_ATOMIC_RFLAGS (_e)),			\
		     _ATOMIC_INTR_WRITES (_e)				\
		   : "r" (_ATOMIC_VAL (_e)), _ATOMIC_INTR_READS (_e)	\
		   : "r11", "cc"); _r; })

#define _ATOMIC_INC(_e, sz)	_ATOMIC_COMM (INC, inc, _e, sz)
#define _ATOMIC_DEC(_e, sz)	_ATOMIC_COMM (DEC, dec, _e, sz)

#define _ATOMIC_INTR_XCHG(lintr, sz, _r, _m) \
  ERI_PASTE (xchg, sz)	%_ERI_ASM_TEMPLATE_SIZE (sz, _r), %_m;		\
  _ATOMIC_INTR_RESET (lintr)

#define _ATOMIC_XCHG(_e, sz, val) \
  ({ uint8_t _r; uint64_t *_v = val; *_v = _ATOMIC_VAL (_e);		\
     asm volatile (_ATOMIC_INTR (ERI_PASTE (xchg, sz), 3, 4, 5, 0,	\
				 _ATOMIC_INTR_XCHG, sz, 1, 2)		\
		   : "=r" (_r), "+r" (*_v), "+m" (_ATOMIC_MEM (_e)),	\
		     _ATOMIC_INTR_WRITES (_e)				\
		   : _ATOMIC_INTR_READS (_e) : "r11", "cc"); _r; })	\

#define _ATOMIC_INTR_CMPXCHG(lintr, sz, _r, _m, _f) \
  pushq	%ERI_PASTE (q, _f); popfq;					\
  lock ERI_PASTE (cmpxchg, sz)	%_ERI_ASM_TEMPLATE_SIZE (sz, _r), %_m;	\
  _ATOMIC_INTR_RESET (lintr);						\
  pushfq; popq	%ERI_PASTE (q, _f)

#define _ATOMIC_CMPXCHG(_e, sz) \
  ({ uint8_t _r;							\
     asm volatile (_ATOMIC_INTR (ERI_PASTE (cmpxchg, sz), 4, 5, 7, 0,	\
				 _ATOMIC_INTR_CMPXCHG, sz, 6, 1, 3)	\
		   : "=r" (_r), "+m" (_ATOMIC_MEM (_e)),		\
		     "+a" (eri_entry__get_regs (_e)->rax),		\
		     "+r" (_ATOMIC_RFLAGS (_e)),			\
		     _ATOMIC_INTR_WRITES (_e)				\
		   : "r" (_ATOMIC_VAL (_e)), _ATOMIC_INTR_READS (_e)	\
		   : "r11", "cc"); _r; })

#define _ATOMIC_ADD(_e, sz)	_ATOMIC_COMM2 (ADD, add, _e, sz)
#define _ATOMIC_SUB(_e, sz)	_ATOMIC_COMM2 (SUB, sub, _e, sz)
#define _ATOMIC_ADC(_e, sz)	_ATOMIC_COMM2 (ADC, adc, _e, sz)
#define _ATOMIC_SBB(_e, sz)	_ATOMIC_COMM2 (SBB, sbb, _e, sz)
#define _ATOMIC_NEG(_e, sz)	_ATOMIC_COMM (NEG, neg, _e, sz)
#define _ATOMIC_AND(_e, sz)	_ATOMIC_COMM2 (AND, and, _e, sz)
#define _ATOMIC_OR(_e, sz)	_ATOMIC_COMM2 (OR, or, _e, sz)
#define _ATOMIC_XOR(_e, sz)	_ATOMIC_COMM2 (XOR, xor, _e, sz)
#define _ATOMIC_NOT(_e, sz)	_ATOMIC_COMM (NOT, not, _e, sz)
#define _ATOMIC_BTC(_e, sz)	_ATOMIC_COMM2 (BTC, btc, _e, sz)
#define _ATOMIC_BTR(_e, sz)	_ATOMIC_COMM2 (BTR, btr, _e, sz)
#define _ATOMIC_BTS(_e, sz)	_ATOMIC_COMM2 (BTS, bts, _e, sz)

#define _ATOMIC_INTR_XADD(lintr, sz, _r, _m, _f) \
  pushq	%ERI_PASTE (q, _f); popfq;					\
  lock ERI_PASTE (xadd, sz)	%_ERI_ASM_TEMPLATE_SIZE (sz, _r), %_m;	\
  _ATOMIC_INTR_RESET (lintr);						\
  pushfq; popq	%ERI_PASTE (q, _f)

#define _ATOMIC_XADD(_e, sz, val) \
  ({ uint8_t _r; uint64_t *_v = val; *_v = _ATOMIC_VAL (_e);		\
     asm volatile (_ATOMIC_INTR (ERI_PASTE (xadd, sz), 4, 5, 6, 0,	\
				 _ATOMIC_INTR_XADD, sz, 1, 2, 3)	\
		   : "=r" (_r), "+r" (*_v), "+m" (_ATOMIC_MEM (_e)),	\
		     "+r" (_ATOMIC_RFLAGS (_e)),			\
		     _ATOMIC_INTR_WRITES (_e)				\
		   : _ATOMIC_INTR_READS (_e) : "r11", "cc"); _r; })

#define ATOMIC(entry, op, ...) \
  do {									\
    struct eri_entry *_e = entry;					\
    uint8_t _r;								\
    switch (eri_entry__get_atomic_size (_e))				\
      {									\
      case 1:								\
	_r = ERI_PASTE (_ATOMIC_, op) (_e, b, ##__VA_ARGS__); break;	\
      case 2:								\
	_r = ERI_PASTE (_ATOMIC_, op) (_e, w, ##__VA_ARGS__); break;	\
      case 4:								\
	_r = ERI_PASTE (_ATOMIC_, op) (_e, l, ##__VA_ARGS__); break;	\
      case 8:								\
	_r = ERI_PASTE (_ATOMIC_, op) (_e, q, ##__VA_ARGS__); break;	\
      default: eri_assert_unreachable ();				\
      }									\
    if (! _r) eri_entry__restart (_e);					\
  } while (0)

#define ATOMIC1(entry, op, ...) \
  do {									\
    struct eri_entry *_e = entry;					\
    uint8_t _r;								\
    switch (eri_entry__get_atomic_size (_e))				\
      {									\
      case 2:								\
	_r = ERI_PASTE (_ATOMIC_, op) (_e, w, ##__VA_ARGS__); break;	\
      case 4:								\
	_r = ERI_PASTE (_ATOMIC_, op) (_e, l, ##__VA_ARGS__); break;	\
      case 8:								\
	_r = ERI_PASTE (_ATOMIC_, op) (_e, q, ##__VA_ARGS__); break;	\
      default: eri_assert_unreachable ();				\
      }									\
    if (! _r) eri_entry__restart (_e);					\
  } while (0)

static eri_noreturn void
atomic (struct thread *th)
{
  struct eri_entry *entry = th->entry;
  uint64_t val = 0;
  switch (eri_entry__get_op_code (entry))
    {
    case ERI_OP_ATOMIC_LOAD: ATOMIC (entry, LOAD, &val); break;
    case ERI_OP_ATOMIC_STORE: ATOMIC (entry, STORE); break;
    case ERI_OP_ATOMIC_INC: ATOMIC (entry, INC); break;
    case ERI_OP_ATOMIC_DEC: ATOMIC (entry, DEC); break;
    case ERI_OP_ATOMIC_XCHG: ATOMIC (entry, XCHG, &val); break;
    case ERI_OP_ATOMIC_CMPXCHG: ATOMIC (entry, CMPXCHG); break;
    case ERI_OP_ATOMIC_ADD: ATOMIC (entry, ADD); break;
    case ERI_OP_ATOMIC_SUB: ATOMIC (entry, SUB); break;
    case ERI_OP_ATOMIC_ADC: ATOMIC (entry, ADC); break;
    case ERI_OP_ATOMIC_SBB: ATOMIC (entry, SBB); break;
    case ERI_OP_ATOMIC_NEG: ATOMIC (entry, NEG); break;
    case ERI_OP_ATOMIC_AND: ATOMIC (entry, AND); break;
    case ERI_OP_ATOMIC_OR: ATOMIC (entry, OR); break;
    case ERI_OP_ATOMIC_XOR: ATOMIC (entry, XOR); break;
    case ERI_OP_ATOMIC_NOT: ATOMIC (entry, NOT); break;
    case ERI_OP_ATOMIC_BTC: ATOMIC1 (entry, BTC); break;
    case ERI_OP_ATOMIC_BTR: ATOMIC1 (entry, BTR); break;
    case ERI_OP_ATOMIC_BTS: ATOMIC1 (entry, BTS); break;
    case ERI_OP_ATOMIC_XADD: ATOMIC (entry, XADD, &val); break;
    default: eri_assert_unreachable ();
    }
  eri_entry__atomic_leave (entry, val);
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
