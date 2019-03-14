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
