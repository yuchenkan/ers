#include <common.h>

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
      if (sig == ERI_SIGSTOP || sig == ERI_SIGKILL) continue;

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

#define COMMON_SYSCALL_RETURN(sregs, res) \
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
    COMMON_SYSCALL_RETURN (sregs, ERI_EINVAL);

  if (! user_mask) return 1;

  if (! copy_user (copy, args, mask, user_mask))
    COMMON_SYSCALL_RETURN (sregs, ERI_EFAULT);

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
  if (sig == 0 || sig >= ERI_NSIG
      || sig == ERI_SIGKILL || sig == ERI_SIGSTOP)
    COMMON_SYSCALL_RETURN (sregs, ERI_EINVAL);

  if (! user_act) return 1;

  if (user_act && ! copy_user (copy, args, act, user_act))
    COMMON_SYSCALL_RETURN (sregs, ERI_EFAULT);

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
