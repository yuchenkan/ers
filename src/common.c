#include <common.h>
#include <common-local.h>

#include <lib/util.h>
#include <lib/lock.h>
#include <lib/syscall.h>

uint8_t eri_global_enable_debug = 0;

void
eri_build_path (const char *path, const char *name, uint64_t id, char *buf)
{
  eri_strcpy (buf, path);
  buf += eri_strlen (path);
  *buf++ = '/';
  eri_strcpy (buf, name);
  buf += eri_strlen (name);
  char a[eri_itoa_size (id)];
  eri_assert_itoa (id, a, 16);
  uint8_t l = eri_strlen (a);
  uint8_t i;
  for (i = 0; i < (l + 3) / 4 * 4 - l; ++i)
    *buf++ = '0';
  eri_strcpy (buf, a);
}

void
eri_mkdir (const char *path)
{
  eri_assert (path[0]);
  char b[eri_strlen (path) + 1];
  eri_strcpy (b, path);
  uint8_t l = b[0] == '/';
  char *p;
  for (p = b + 1; *p; ++p)
    if (*p == '/' && ! l)
      {
	*p = '\0';
	eri_assert_sys_mkdir (b, 0755);
	*p = '/';
	l = 1;
      }
    else if (*p != '/') l = 0;
  eri_assert_sys_mkdir (b, 0755);
}

void
eri_sig_init_acts (struct eri_sig_act *sig_acts, eri_sig_handler_t hand)
{
  int32_t sig;
  for (sig = 1; sig < ERI_NSIG; ++sig)
    {
      if (! eri_sig_catchable (sig)) continue;

      eri_init_lock (&sig_acts[sig - 1].lock, 0);
      struct eri_sigaction act = {
	hand, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK,
	eri_assert_sys_sigreturn
      };
      eri_sig_fill_set (&act.mask);
      eri_assert_sys_sigaction (sig, &act, &sig_acts[sig - 1].act);
    }
}

void
eri_sig_get_act (struct eri_sig_act *sig_acts, int32_t sig,
		 struct eri_sigaction *act)
{
  struct eri_sig_act *sig_act = sig_acts + sig - 1;
  eri_assert_lock (&sig_act->lock);
  *act = sig_act->act;
  eri_assert_unlock (&sig_act->lock);
}

void
eri_sig_set_act (struct eri_sig_act *sig_acts, int32_t sig,
	const struct eri_sigaction *act, struct eri_sigaction *old_act)
{
  struct eri_sig_act *sig_act = sig_acts + sig - 1;
  eri_assert_lock (&sig_act->lock);

  if (old_act) *old_act = sig_act->act;
  sig_act->act = *act;

  eri_assert_unlock (&sig_act->lock);
}

void
eri_sig_digest_act (const struct eri_siginfo *info,
		    const struct eri_sigset *mask, struct eri_sigaction *act)
{
  int32_t sig = info->sig;
  if (eri_si_sync (info)
      && (eri_sig_set_set (mask, sig) || act->act == ERI_SIG_DFL))
    act->act = ERI_SIG_DFL;

  if (act->act == ERI_SIG_IGN)
    act->act = 0;
  else if (act->act == ERI_SIG_DFL)
    {
      if (sig == ERI_SIGCHLD || sig == ERI_SIGCONT
	  || sig == ERI_SIGURG || sig == ERI_SIGWINCH)
	act->act = 0;
      else if (sig == ERI_SIGHUP || sig == ERI_SIGINT || sig == ERI_SIGKILL
	       || sig == ERI_SIGPIPE || sig == ERI_SIGALRM
	       || sig == ERI_SIGTERM || sig == ERI_SIGUSR1
	       || sig == ERI_SIGUSR2 || sig == ERI_SIGIO
	       || sig == ERI_SIGPROF || sig == ERI_SIGVTALRM
	       || sig == ERI_SIGSTKFLT || sig == ERI_SIGPWR
	       || (sig >= ERI_SIGRTMIN && sig <= ERI_SIGRTMAX))
	act->act = ERI_SIG_ACT_TERM;
      else if (sig == ERI_SIGQUIT || sig == ERI_SIGILL || sig == ERI_SIGABRT
	       || sig == ERI_SIGFPE || sig == ERI_SIGSEGV || sig == ERI_SIGBUS
	       || sig == ERI_SIGSYS || sig == ERI_SIGTRAP
	       || sig == ERI_SIGXCPU || sig == ERI_SIGXFSZ)
	act->act = ERI_SIG_ACT_CORE;
      else if (sig == ERI_SIGTSTP || sig == ERI_SIGTTIN || sig == ERI_SIGTTOU)
	act->act = ERI_SIG_ACT_STOP;
      else eri_assert_unreachable ();
    }
}

typedef uint8_t (*copy_user_t) (void *, void *, const void *, uint64_t);
#define copy_user(copy, args, dst, src) \
  ((copy_user_t) (copy)) (args, dst, src, sizeof *(dst))
#define copy_user_error(copy, args, dst, src) \
  (copy_user (copy, args, dst, src) ? 0 : ERI_EFAULT)

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

struct eri_sigframe *
eri_sig_setup_user_frame (struct eri_sigframe *frame,
		const struct eri_sigaction *act, struct eri_stack *stack,
		const struct eri_sigset *mask, void *copy, void *args)
{
  struct eri_ucontext *ctx = &frame->ctx;
  uint8_t alt = (act->flags & ERI_SA_ONSTACK)
		&& ! on_sig_alt_stack (stack, ctx->mctx.rsp);
  uint64_t rsp = alt ? stack->sp + stack->size : ctx->mctx.rsp - 128;

  ctx->stack = *stack;
  if (stack->flags & ERI_SS_AUTODISARM) disable_sig_alt_stack (stack);

  ctx->sig_mask = *mask;
  /* XXX: default restorer */
  frame->restorer = act->flags & ERI_SA_RESTORER ? act->restorer : 0;

  if (ctx->mctx.fpstate)
    {
      uint32_t fpstate_size = ctx->mctx.fpstate->size;
      rsp = eri_round_down (rsp - fpstate_size, 64);
      if (! ((copy_user_t) copy) (args, (void *) rsp,
				  ctx->mctx.fpstate, fpstate_size))
	return 0;
      ctx->mctx.fpstate = (void *) rsp;
    }

  struct eri_sigframe *user_frame
	= (void *) (eri_round_down (rsp - sizeof *user_frame, 16) - 8);
  return copy_user (copy, args, user_frame, frame) ? user_frame : 0;
}

#define COMMON_SYSCALL_RETURN(sregs, res) \
  do { (sregs)->rax = res; return ; } while (0)

#define COMMON_SYSCALL_RETURN_ERROR(sregs, res) \
  do {									\
    uint64_t _res = res;						\
    (sregs)->rax = _res;						\
    return ! eri_syscall_is_error (_res);				\
  } while (0)

uint8_t
eri_common_syscall_rt_sigprocmask_get (
		struct eri_entry_scratch_registers *sregs,
		const struct eri_sigset *old_mask, struct eri_sigset *mask,
		void *copy, void *args)
{
  int32_t how = sregs->rdi;
  const struct eri_sigset *user_mask = (void *) sregs->rsi;
  uint64_t sig_set_size = sregs->r10;

  if ((how != ERI_SIG_BLOCK && how != ERI_SIG_UNBLOCK
       && how != ERI_SIG_SETMASK)
      || sig_set_size != ERI_SIG_SETSIZE)
    COMMON_SYSCALL_RETURN_ERROR (sregs, ERI_EINVAL);

  if (! user_mask) return 1;

  if (! copy_user (copy, args, mask, user_mask))
    COMMON_SYSCALL_RETURN_ERROR (sregs, ERI_EFAULT);

  if (how == ERI_SIG_BLOCK)
    eri_sig_union_set (mask, old_mask);
  else if (how == ERI_SIG_UNBLOCK)
    {
      struct eri_sigset old = *old_mask;
      eri_sig_diff_set (&old, mask);
      *mask = old;
    }

  return 1;
}

void
eri_common_syscall_rt_sigprocmask_set (
		struct eri_entry_scratch_registers *sregs,
		const struct eri_sigset *old_mask, void *copy, void *args)
{
  struct eri_sigset *user_old_mask = (void *) sregs->rdx;
  if (! user_old_mask) return;

  sregs->rax = copy_user_error (copy, args, user_old_mask, old_mask);
}

uint8_t
eri_common_syscall_rt_sigaction_get (
		struct eri_entry_scratch_registers *sregs,
		struct eri_sigaction *act, void *copy, void *args)
{
  int32_t sig = sregs->rdi;
  const struct eri_sigaction *user_act = (void *) sregs->rsi;
  if (! eri_sig_catchable (sig))
    COMMON_SYSCALL_RETURN_ERROR (sregs, ERI_EINVAL);

  if (! user_act) return 1;

  if (user_act && ! copy_user (copy, args, act, user_act))
    COMMON_SYSCALL_RETURN_ERROR (sregs, ERI_EFAULT);

  return 1;
}

void
eri_common_syscall_rt_sigaction_set (
		struct eri_entry_scratch_registers *sregs,
		const struct eri_sigaction *old_act, void *copy, void *args)
{
  struct eri_sigaction *user_old_act = (void *) sregs->rdx;
  if (! user_old_act) return;

  sregs->rax = copy_user_error (copy, args, user_old_act, old_act);
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

void
eri_common_syscall_sigaltstack (
		struct eri_entry_scratch_registers *sregs, uint64_t rsp,
		struct eri_stack *stack,
		void *copy_from, void *copy_to, void *args)
{
  const struct eri_stack *user_stack = (void *) sregs->rdi;
  struct eri_stack *user_old_stack = (void *) sregs->rsi;

  if (! user_stack && ! user_old_stack)
    COMMON_SYSCALL_RETURN (sregs, 0);

  struct eri_stack old_stack;
  if (user_old_stack)
    {
      old_stack = *stack;
      old_stack.flags |= on_sig_alt_stack (stack, rsp) ? ERI_SS_ONSTACK : 0;
    }

  if (user_stack)
    {
      struct eri_stack new_stack;
      if (! copy_user (copy_from, args, &new_stack, user_stack))
	COMMON_SYSCALL_RETURN (sregs, ERI_EFAULT);

      uint64_t err = set_sig_alt_stack (stack, rsp, &new_stack);
      if (err) COMMON_SYSCALL_RETURN (sregs, err);
    }

  if (! user_old_stack) COMMON_SYSCALL_RETURN (sregs, 0);

  COMMON_SYSCALL_RETURN (sregs, user_old_stack
	? copy_user_error (copy_to, args, user_old_stack, &old_stack) : 0);
}

uint8_t
eri_common_syscall_rt_sigreturn (
		struct eri_common_syscall_rt_sigreturn_args *args)
{
  struct eri_entry_thread_context *th_ctx = args->th_ctx;

  copy_user_t copy = args->copy;
  void *copy_args = args->args;

  const struct eri_sigframe *user_frame = (void *) (th_ctx->rsp - 8);

  struct eri_sigframe frame;
  if (! copy (copy_args, &frame, user_frame, sizeof frame)) return 0;

  uint8_t buf[ERI_MINSIGSTKSZ];
  uint64_t top = (uint64_t) buf + sizeof buf;

  struct eri_ucontext *ctx = &frame.ctx;
  if (ctx->mctx.fpstate)
    {
      const struct eri_fpstate *user_fpstate = ctx->mctx.fpstate;
      struct eri_fpstate fpstate;
      if (! copy (copy_args, &fpstate, user_fpstate, sizeof fpstate))
	return 0;

      top = fpstate.size + 64 + sizeof frame + 16 + 8 >= ERI_MINSIGSTKSZ
		? 0 : eri_round_down (top - fpstate.size, 64);
      if (! copy (copy_args, (void *) top, user_fpstate, fpstate.size))
	return 0;

      ctx->mctx.fpstate = (void *) top;
    }

  *args->mask = ctx->sig_mask;
  eri_sig_empty_set (&ctx->sig_mask);

  set_sig_alt_stack (args->sig_alt_stack, th_ctx->rsp, &ctx->stack);
  ctx->stack = *args->stack;

  args->entry->rbx = ctx->mctx.rbx;
  args->entry->ret = ctx->mctx.rip;
  args->th_ctx->rsp = ctx->mctx.rsp;
#define SET_REG(creg, reg, x)	(x)->reg = ctx->mctx.reg;
  ERI_ENTRY_FOREACH_SREG (SET_REG, &args->th_ctx->sregs)
  ERI_ENTRY_FOREACH_EREG (SET_REG, args->eregs)
  ctx->mctx.rflags = 0;

  frame.restorer = eri_assert_sys_sigreturn;

  struct eri_sigframe *sig_stack
	= (void *) eri_round_down (top - sizeof *sig_stack, 16) - 8;
  *sig_stack = frame;

  sig_return_back (sig_stack);
  return 1;
}

void
eri_serialize_uint8 (eri_file_t file, uint8_t v)
{
  eri_assert_fwrite (file, &v, 1, 0);
}

uint8_t
eri_unserialize_uint8 (eri_file_t file)
{
  uint8_t v;
  eri_assert_fread (file, &v, 1, 0);
  return v;
}

uint8_t
eri_unserialize_uint8_or_eof (eri_file_t file, uint8_t *v)
{
  uint64_t len;
  eri_assert_fread (file, v, 1, &len);
  eri_assert (len == 1 || len == 0);
  return len != 0;
}

void
eri_serialize_uint16 (eri_file_t file, uint16_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

uint16_t
eri_unserialize_uint16 (eri_file_t file)
{
  uint16_t v;
  eri_assert_fread (file, &v, sizeof v, 0);
  return v;
}

void
eri_serialize_int32 (eri_file_t file, int32_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

int32_t
eri_unserialize_int32 (eri_file_t file)
{
  int32_t v;
  eri_assert_fread (file, &v, sizeof v, 0);
  return v;
}

void
eri_serialize_uint64 (eri_file_t file, uint64_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

uint64_t
eri_unserialize_uint64 (eri_file_t file)
{
  uint64_t v;
  eri_assert_fread (file, &v, sizeof v, 0);
  return v;
}

void
eri_serialize_uint8_array (eri_file_t file, const uint8_t *arr, uint64_t size)
{
  eri_assert_fwrite (file, arr, size, 0);
}

void
eri_unserialize_uint8_array (eri_file_t file, uint8_t *arr, uint64_t size)
{
  eri_assert_fread (file, arr, size, 0);
}

void
eri_unserialize_skip_uint8_array (eri_file_t file, uint64_t size)
{
  eri_assert_fseek (file, size, ERI_SEEK_CUR);
}

void
eri_serialize_sigset (eri_file_t file, const struct eri_sigset *set)
{
  eri_assert_fwrite (file, set->val, ERI_SIG_SETSIZE, 0);
}

void
eri_unserialize_sigset (eri_file_t file, struct eri_sigset *set)
{
  eri_assert_fread (file, set->val, ERI_SIG_SETSIZE, 0);
}

void
eri_serialize_stack (eri_file_t file, const struct eri_stack *stack)
{
  eri_serialize_uint64 (file, stack->sp);
  eri_serialize_int32 (file, stack->flags);
  eri_serialize_uint64 (file, stack->size);
}

void
eri_serialize_siginfo (eri_file_t file, const struct eri_siginfo *info)
{
  eri_serialize_int32 (file, info->sig);
  if (! info->sig) return;
  eri_serialize_int32 (file, info->errno);
  eri_serialize_int32 (file, info->code);
  /* XXX: add check in analysis */
  if (info->code == ERI_SI_TKILL || info->code == ERI_SI_USER)
    {
      eri_serialize_int32 (file, info->kill.pid);
      eri_serialize_int32 (file, info->kill.uid);
    }
  else if (info->sig == ERI_SIGCHLD && eri_si_from_kernel (info))
    {
      eri_serialize_int32 (file, info->chld.pid);
      eri_serialize_int32 (file, info->chld.uid);
      eri_serialize_int32 (file, info->chld.status);
    }
}

void
eri_unserialize_siginfo (eri_file_t file, struct eri_siginfo *info)
{
  info->sig = eri_unserialize_int32 (file);
  if (! info->sig) return;
  info->errno = eri_unserialize_int32 (file);
  info->code = eri_unserialize_int32 (file);
  if (info->code == ERI_SI_TKILL || info->code == ERI_SI_USER)
    {
      info->kill.pid = eri_unserialize_int32 (file);
      info->kill.uid = eri_unserialize_int32 (file);
    }
  else if (info->sig == ERI_SIGCHLD && eri_si_from_kernel (info))
    {
      info->chld.pid = eri_unserialize_int32 (file);
      info->chld.uid = eri_unserialize_int32 (file);
      info->chld.status = eri_unserialize_int32 (file);
    }
}

void
eri_unserialize_stack (eri_file_t file, struct eri_stack *stack)
{
  stack->sp = eri_unserialize_uint64 (file);
  stack->flags = eri_unserialize_int32 (file);
  stack->size = eri_unserialize_uint64 (file);
}

void
eri_serialize_init_record (eri_file_t file, const struct eri_init_record *rec)
{
  eri_serialize_uint64 (file, rec->ver);
  eri_serialize_uint64 (file, rec->rdx);
  eri_serialize_uint64 (file, rec->rsp);
  eri_serialize_uint64 (file, rec->rip);

  eri_serialize_sigset (file, &rec->sig_mask);
  eri_serialize_stack (file, &rec->sig_alt_stack);

  eri_serialize_int32 (file, rec->user_pid);

  eri_serialize_uint64 (file, rec->start);
  eri_serialize_uint64 (file, rec->end);
  eri_serialize_uint64 (file, rec->atomic_table_size);
}

void
eri_unserialize_init_record (eri_file_t file, struct eri_init_record *rec)
{
  rec->ver = eri_unserialize_uint64 (file);
  rec->rdx = eri_unserialize_uint64 (file);
  rec->rsp = eri_unserialize_uint64 (file);
  rec->rip = eri_unserialize_uint64 (file);

  eri_unserialize_sigset (file, &rec->sig_mask);
  eri_unserialize_stack (file, &rec->sig_alt_stack);

  rec->user_pid = eri_unserialize_int32 (file);

  rec->start = eri_unserialize_uint64 (file);
  rec->end = eri_unserialize_uint64 (file);
  rec->atomic_table_size = eri_unserialize_uint64 (file);
}

void
eri_serialize_init_map_record (eri_file_t file,
			       const struct eri_init_map_record *rec)
{
  eri_serialize_uint64 (file, rec->start);
  eri_serialize_uint64 (file, rec->end);
  eri_serialize_uint8 (file, rec->prot);
  eri_serialize_uint8 (file, rec->grows_down);
  eri_serialize_uint8 (file, rec->data_count);
}

void
eri_unserialize_init_map_record (eri_file_t file,
				 struct eri_init_map_record *rec)
{
  rec->start = eri_unserialize_uint64 (file);
  rec->end = eri_unserialize_uint64 (file);
  rec->prot = eri_unserialize_uint8 (file);
  rec->grows_down = eri_unserialize_uint8 (file);
  rec->data_count = eri_unserialize_uint8 (file);
}

void
eri_serialize_signal_record (eri_file_t file,
			     const struct eri_signal_record *rec)
{
  eri_serialize_uint64 (file, rec->in);
  eri_serialize_siginfo (file, &rec->info);
}

void
eri_unserialize_signal_record (eri_file_t file,
			       struct eri_signal_record *rec)
{
  rec->in = eri_unserialize_uint64 (file);
  eri_unserialize_siginfo (file, &rec->info);
}

void
eri_serialize_syscall_clone_record (eri_file_t file,
			const struct eri_syscall_clone_record *rec)
{
  eri_serialize_uint64 (file, rec->out);
  eri_serialize_uint64 (file, rec->result);
  if (eri_syscall_is_error (rec->result)) return;
  eri_serialize_uint64 (file, rec->id);
}

void
eri_unserialize_syscall_clone_record (eri_file_t file,
			struct eri_syscall_clone_record *rec)
{
  rec->out = eri_unserialize_uint64 (file);
  rec->result = eri_unserialize_uint64 (file);
  if (eri_syscall_is_error (rec->result)) return;
  rec->id = eri_unserialize_uint64 (file);
}

#define ATOMIC_RECORD_UPDATED	1
#define ATOMIC_RECORD_SAME_VER	2
#define ATOMIC_RECORD_ZERO_VAL	4

void
eri_serialize_atomic_record (eri_file_t file,
			     const struct eri_atomic_record *rec)
{
  uint8_t flags = (rec->updated ? ATOMIC_RECORD_UPDATED : 0)
		  | (rec->ver[0] == rec->ver[1] ? ATOMIC_RECORD_SAME_VER : 0)
		  | (rec->val == 0 ? ATOMIC_RECORD_ZERO_VAL : 0);
  eri_serialize_uint8 (file, flags);
  eri_serialize_uint64 (file, rec->ver[0]);
  if (! (flags & ATOMIC_RECORD_SAME_VER))
    eri_serialize_uint64 (file, rec->ver[1]);
  if (! (flags & ATOMIC_RECORD_ZERO_VAL))
    eri_serialize_uint64 (file, rec->val);
}

void
eri_unserialize_atomic_record (eri_file_t file,
			       struct eri_atomic_record *rec)
{
  uint8_t flags = eri_unserialize_uint8 (file);
  rec->updated = !! (flags & ATOMIC_RECORD_UPDATED);
  rec->ver[0] = eri_unserialize_uint64 (file);
  rec->ver[1] = flags & ATOMIC_RECORD_SAME_VER
		? rec->ver[0] : eri_unserialize_uint64 (file);
  rec->val = flags & ATOMIC_RECORD_ZERO_VAL
		? 0 : eri_unserialize_uint64 (file);
}
