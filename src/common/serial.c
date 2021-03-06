#include <lib/util.h>
#include <lib/syscall.h>

#include <common/common.h>
#include <common/serial.h>

void
eri_serialize_uint8 (eri_file_t file, uint8_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

uint8_t
eri_try_unserialize_uint8 (eri_file_t file, uint8_t *v)
{
  return ! eri_fread (file, v, sizeof *v, 0);
}

uint8_t
eri_unserialize_uint8 (eri_file_t file)
{
  uint8_t v;
  eri_assert (eri_try_unserialize_uint8 (file, &v));
  return v;
}

uint8_t
eri_unserialize_uint8_or_eof (eri_file_t file, uint8_t *v)
{
  uint64_t len;
  eri_assert_fread (file, v, sizeof *v, &len);
  eri_assert (len == 1 || len == 0);
  return len != 0;
}

void
eri_serialize_uint16 (eri_file_t file, uint16_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

uint8_t
eri_try_unserialize_uint16 (eri_file_t file, uint16_t *v)
{
  return ! eri_fread (file, v, sizeof *v, 0);
}

uint16_t
eri_unserialize_uint16 (eri_file_t file)
{
  uint16_t v;
  eri_assert (eri_try_unserialize_uint16 (file, &v));
  return v;
}

void
eri_serialize_int16 (eri_file_t file, int16_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

uint8_t
eri_try_unserialize_int16 (eri_file_t file, int16_t *v)
{
  return ! eri_fread (file, v, sizeof *v, 0);
}

int16_t
eri_unserialize_int16 (eri_file_t file)
{
  int16_t v;
  eri_assert (eri_try_unserialize_int16 (file, &v));
  return v;
}

void
eri_serialize_int32 (eri_file_t file, int32_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

uint8_t
eri_try_unserialize_int32 (eri_file_t file, int32_t *v)
{
  return ! eri_fread (file, v, sizeof *v, 0);
}

int32_t
eri_unserialize_int32 (eri_file_t file)
{
  int32_t v;
  eri_assert (eri_try_unserialize_int32 (file, &v));
  return v;
}

void
eri_serialize_uint32 (eri_file_t file, uint32_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

uint8_t
eri_try_unserialize_uint32 (eri_file_t file, uint32_t *v)
{
  return ! eri_fread (file, v, sizeof *v, 0);
}

uint32_t
eri_unserialize_uint32 (eri_file_t file)
{
  uint32_t v;
  eri_assert (eri_try_unserialize_uint32 (file, &v));
  return v;
}

void
eri_serialize_uint64 (eri_file_t file, uint64_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

uint8_t
eri_try_unserialize_uint64 (eri_file_t file, uint64_t *v)
{
  return ! eri_fread (file, v, sizeof *v, 0);
}

uint64_t
eri_unserialize_uint64 (eri_file_t file)
{
  uint64_t v;
  eri_assert (eri_try_unserialize_uint64 (file, &v));
  return v;
}

void
eri_serialize_int64 (eri_file_t file, int64_t v)
{
  eri_assert_fwrite (file, &v, sizeof v, 0);
}

uint8_t
eri_try_unserialize_int64 (eri_file_t file, int64_t *v)
{
  return ! eri_fread (file, v, sizeof *v, 0);
}

int64_t
eri_unserialize_int64 (eri_file_t file)
{
  int64_t v;
  eri_assert (eri_try_unserialize_int64 (file, &v));
  return v;
}

void
eri_serialize_uint8_array (eri_file_t file, const uint8_t *a, uint64_t len)
{
  eri_assert_fwrite (file, a, sizeof *a * len, 0);
}

uint8_t
eri_try_unserialize_uint8_array (eri_file_t file, uint8_t *a, uint64_t len)
{
  return ! eri_fread (file, a, sizeof *a * len, 0);
}

void
eri_unserialize_uint8_array (eri_file_t file, uint8_t *a, uint64_t len)
{
  eri_assert (eri_try_unserialize_uint8_array (file, a, len));
}

void
eri_unserialize_skip_uint8_array (eri_file_t file, uint64_t len)
{
  eri_assert_fseek (file, sizeof (uint8_t) * len, 1);
}

void
eri_serialize_int32_array (eri_file_t file, const int32_t *a, uint64_t len)
{
  eri_assert_fwrite (file, a, sizeof *a * len, 0);
}

uint8_t
eri_try_unserialize_int32_array (eri_file_t file, int32_t *a, uint64_t len)
{
  return ! eri_fread (file, a, sizeof *a * len, 0);
}

void
eri_unserialize_int32_array (eri_file_t file, int32_t *a, uint64_t len)
{
  eri_assert (eri_try_unserialize_int32_array (file, a, len));
}

void
eri_serialize_uint64_array (eri_file_t file,
			    const uint64_t *a, uint64_t len)
{
  eri_assert_fwrite (file, a, sizeof *a * len, 0);
}

uint8_t
eri_try_unserialize_uint64_array (eri_file_t file,
				  uint64_t *a, uint64_t len)
{
  return ! eri_fread (file, a, sizeof *a * len, 0);
}

void
eri_unserialize_uint64_array (eri_file_t file, uint64_t *a, uint64_t len)
{
  eri_assert (eri_try_unserialize_uint64_array (file, a, len));
}

void
eri_serialize_str (eri_file_t file, const char *s, uint64_t len)
{
  uint64_t n = eri_strlen (s);
  eri_assert (n < len);
  eri_serialize_uint64 (file, n);
  eri_serialize_uint8_array (file, (void *) s, n);
}

uint8_t
eri_try_unserialize_str (eri_file_t file, char *s, uint64_t len)
{
  uint64_t n;
  if (! eri_try_unserialize_uint64 (file, &n) || n >= len
      || ! eri_try_unserialize_uint8_array (file, (void *) s, n)) return 0;
  s[n] = '\0';
  return 1;
}

void
eri_unserialize_str (eri_file_t file, char *s, uint64_t len)
{
  eri_assert (eri_try_unserialize_str (file, s, len));
}

void
eri_serialize_pair (eri_file_t file, struct eri_pair pair)
{
  eri_serialize_uint64 (file, pair.first);
  eri_serialize_uint64 (file, pair.second);
}

uint8_t
eri_try_unserialize_pair (eri_file_t file, struct eri_pair *pair)
{
  return eri_try_unserialize_uint64 (file, &pair->first)
	 && eri_try_unserialize_uint64 (file, &pair->second);
}

struct eri_pair
eri_unserialize_pair (eri_file_t file)
{
  struct eri_pair pair;
  eri_assert (eri_try_unserialize_pair (file, &pair));
  return pair;
}

void
eri_serialize_sigset (eri_file_t file, const eri_sigset_t *set)
{
  eri_assert_fwrite (file, set, ERI_SIG_SETSIZE, 0);
}

uint8_t
eri_try_unserialize_sigset (eri_file_t file, eri_sigset_t *set)
{
  return ! eri_fread (file, set, ERI_SIG_SETSIZE, 0);
}

void
eri_unserialize_sigset (eri_file_t file, eri_sigset_t *set)
{
  eri_assert (eri_try_unserialize_sigset (file, set));
}

void
eri_serialize_stack (eri_file_t file, const struct eri_stack *stack)
{
  eri_serialize_uint64 (file, stack->sp);
  eri_serialize_int32 (file, stack->flags);
  eri_serialize_uint64 (file, stack->size);
}

uint8_t
eri_try_unserialize_stack (eri_file_t file, struct eri_stack *stack)
{
  return eri_try_unserialize_uint64 (file, &stack->sp)
	 && eri_try_unserialize_int32 (file, &stack->flags)
	 && eri_try_unserialize_uint64 (file, &stack->size);
}

void
eri_unserialize_stack (eri_file_t file, struct eri_stack *stack)
{
  eri_assert (eri_try_unserialize_stack (file, stack));
}

void
eri_serialize_siginfo (eri_file_t file, const struct eri_siginfo *info)
{
  eri_serialize_int32 (file, info->sig);
  if (! info->sig) return;
  eri_serialize_int32 (file, info->errno);
  eri_serialize_int32 (file, info->code);
  /* XXX: add field access check in analysis */
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
  else if ((info->sig == ERI_SIGILL || info->sig == ERI_SIGFPE
	    || info->sig == ERI_SIGSEGV || info->sig == ERI_SIGBUS)
	   && eri_si_from_kernel (info) && info->code != ERI_SI_KERNEL)
    eri_serialize_uint64 (file, info->fault.addr);
}

uint8_t
eri_try_unserialize_siginfo (eri_file_t file, struct eri_siginfo *info)
{
  if (! eri_try_unserialize_int32 (file, &info->sig)) return 0;
  if (! info->sig) return 1;
  if (! eri_try_unserialize_int32 (file, &info->errno)
      || ! eri_try_unserialize_int32 (file, &info->code)) return 0;
  if (info->code == ERI_SI_TKILL || info->code == ERI_SI_USER)
    return eri_try_unserialize_int32 (file, &info->kill.pid)
	   && eri_try_unserialize_int32 (file, &info->kill.uid);
  if (info->sig == ERI_SIGCHLD && eri_si_from_kernel (info))
    return eri_try_unserialize_int32 (file, &info->chld.pid)
	   && eri_try_unserialize_int32 (file, &info->chld.uid)
	   && eri_try_unserialize_int32 (file, &info->chld.status);
  if ((info->sig == ERI_SIGILL || info->sig == ERI_SIGFPE
       || info->sig == ERI_SIGSEGV || info->sig == ERI_SIGBUS)
      && eri_si_from_kernel (info) && info->code != ERI_SI_KERNEL)
    return eri_try_unserialize_uint64 (file, &info->fault.addr);
  return 1;
}

void
eri_unserialize_siginfo (eri_file_t file, struct eri_siginfo *info)
{
  eri_assert (eri_try_unserialize_siginfo (file, info));
}

void
eri_serialize_sigaction (eri_file_t file, const struct eri_sigaction *act)
{
  eri_serialize_uint64 (file, (uint64_t) act->act);
  if (act->act == ERI_SIG_DFL || act->act == ERI_SIG_IGN) return;
  eri_serialize_int32 (file, act->flags);
  eri_serialize_uint64 (file, (uint64_t) act->restorer);
  eri_serialize_sigset (file, &act->mask);
}

uint8_t
eri_try_unserialize_sigaction (eri_file_t file, struct eri_sigaction *act)
{
  return eri_try_unserialize_uint64 (file, (void *) &act->act)
	 && (act->act == ERI_SIG_DFL || act->act == ERI_SIG_IGN
	     || (eri_try_unserialize_int32 (file, &act->flags)
		 && eri_try_unserialize_uint64 (file, (void *) &act->restorer)
		 && eri_try_unserialize_sigset (file, &act->mask)));
}

void
eri_unserialize_sigaction (eri_file_t file, struct eri_sigaction *act)
{
  eri_assert (eri_try_unserialize_sigaction (file, act));
}

void
eri_serialize_sig_act (eri_file_t file, const struct eri_sig_act *act)
{
  eri_serialize_uint8 (file, act->type);
  if (act->type == ERI_SIG_ACT_LOST) return;
  eri_serialize_sigaction (file, &act->act);
  eri_serialize_uint64 (file, act->ver);
}

uint8_t
eri_try_unserialize_sig_act (eri_file_t file, struct eri_sig_act *act)
{
  return eri_try_unserialize_uint8 (file, &act->type)
         && (act->type == ERI_SIG_ACT_LOST
	     || (eri_try_unserialize_sigaction (file, &act->act)
		 && eri_try_unserialize_uint64 (file, &act->ver)));
}

void
eri_unserialize_sig_act (eri_file_t file, struct eri_sig_act *act)
{
  eri_assert (eri_try_unserialize_sig_act (file, act));
}

void
eri_serialize_timespec (eri_file_t file,
			const struct eri_timespec *timespec)
{
  eri_serialize_int64 (file, timespec->sec);
  eri_serialize_int64 (file, timespec->nsec);
}

uint8_t
eri_try_unserialize_timespec (eri_file_t file,
			      struct eri_timespec *timespec)
{
  return eri_try_unserialize_int64 (file, &timespec->sec)
	 && eri_try_unserialize_int64 (file, &timespec->nsec);
}

void
eri_unserialize_timespec (eri_file_t file, struct eri_timespec *timespec)
{
  eri_assert (eri_try_unserialize_timespec (file, timespec));
}

void
eri_serialize_timeval (eri_file_t file,
		       const struct eri_timeval *timeval)
{
  eri_serialize_int64 (file, timeval->sec);
  eri_serialize_int64 (file, timeval->usec);
}

uint8_t
eri_try_unserialize_timeval (eri_file_t file,
			     struct eri_timeval *timeval)
{
  return eri_try_unserialize_int64 (file, &timeval->sec)
	 && eri_try_unserialize_int64 (file, &timeval->usec);
}

void
eri_unserialize_timeval (eri_file_t file, struct eri_timeval *timeval)
{
  eri_assert (eri_try_unserialize_timeval (file, timeval));
}

void
eri_serialize_tms (eri_file_t file, const struct eri_tms *tms)
{
  eri_serialize_int64 (file, tms->utime);
  eri_serialize_int64 (file, tms->stime);
  eri_serialize_int64 (file, tms->cutime);
  eri_serialize_int64 (file, tms->cstime);
}

uint8_t
eri_try_unserialize_tms (eri_file_t file, struct eri_tms *tms)
{
  return eri_try_unserialize_int64 (file, &tms->utime)
	 && eri_try_unserialize_int64 (file, &tms->stime)
	 && eri_try_unserialize_int64 (file, &tms->cutime)
	 && eri_try_unserialize_int64 (file, &tms->cstime);
}

void
eri_unserialize_tms (eri_file_t file, struct eri_tms *tms)
{
  eri_assert (eri_try_unserialize_tms (file, tms));
}

void
eri_serialize_stat (eri_file_t file, const struct eri_stat *stat)
{
  eri_serialize_uint64 (file, stat->dev);
  eri_serialize_uint64 (file, stat->ino);
  eri_serialize_uint64 (file, stat->nlink);
  eri_serialize_uint32 (file, stat->mode);
  eri_serialize_uint32 (file, stat->uid);
  eri_serialize_uint32 (file, stat->gid);
  eri_serialize_uint64 (file, stat->rdev);
  eri_serialize_int64 (file, stat->size);
  eri_serialize_int64 (file, stat->blksize);
  eri_serialize_int64 (file, stat->blocks);
  eri_serialize_timespec (file, &stat->atime);
  eri_serialize_timespec (file, &stat->mtime);
  eri_serialize_timespec (file, &stat->ctime);
}

uint8_t
eri_try_unserialize_stat (eri_file_t file, struct eri_stat *stat)
{
  return eri_try_unserialize_uint64 (file, &stat->dev)
	 && eri_try_unserialize_uint64 (file, &stat->ino)
	 && eri_try_unserialize_uint64 (file, &stat->nlink)
	 && eri_try_unserialize_uint32 (file, &stat->mode)
	 && eri_try_unserialize_uint32 (file, &stat->uid)
	 && eri_try_unserialize_uint32 (file, &stat->gid)
	 && eri_try_unserialize_uint64 (file, &stat->rdev)
	 && eri_try_unserialize_int64 (file, &stat->size)
	 && eri_try_unserialize_int64 (file, &stat->blksize)
	 && eri_try_unserialize_int64 (file, &stat->blocks)
	 && eri_try_unserialize_timespec (file, &stat->atime)
	 && eri_try_unserialize_timespec (file, &stat->mtime)
	 && eri_try_unserialize_timespec (file, &stat->ctime);
}

void
eri_unserialize_stat (eri_file_t file, struct eri_stat *stat)
{
  eri_assert (eri_try_unserialize_stat (file, stat));
}

void
eri_serialize_utsname (eri_file_t file, const struct eri_utsname *utsname)
{
  eri_serialize_str (file, utsname->sysname, sizeof utsname->sysname);
  eri_serialize_str (file, utsname->nodename, sizeof utsname->nodename);
  eri_serialize_str (file, utsname->release, sizeof utsname->release);
  eri_serialize_str (file, utsname->version, sizeof utsname->version);
  eri_serialize_str (file, utsname->machine, sizeof utsname->machine);
  eri_serialize_str (file, utsname->domainname, sizeof utsname->domainname);
}

uint8_t
eri_try_unserialize_utsname (eri_file_t file, struct eri_utsname *utsname)
{
  return eri_try_unserialize_str (file, utsname->sysname,
				  sizeof utsname->sysname)
	 && eri_try_unserialize_str (file, utsname->nodename,
				     sizeof utsname->nodename)
	 && eri_try_unserialize_str (file, utsname->release,
				     sizeof utsname->release)
	 && eri_try_unserialize_str (file, utsname->version,
				     sizeof utsname->version)
	 && eri_try_unserialize_str (file, utsname->machine,
				     sizeof utsname->machine)
	 && eri_try_unserialize_str (file, utsname->domainname,
				     sizeof utsname->domainname);
}

void
eri_unserialize_utsname (eri_file_t file, struct eri_utsname *utsname)
{
  eri_assert (eri_try_unserialize_utsname (file, utsname));
}

void
eri_serialize_rlimit (eri_file_t file, const struct eri_rlimit *rlimit)
{
  eri_serialize_uint64 (file, rlimit->cur);
  eri_serialize_uint64 (file, rlimit->max);
}

uint8_t
eri_try_unserialize_rlimit (eri_file_t file, struct eri_rlimit *rlimit)
{
  return eri_try_unserialize_uint64 (file, &rlimit->cur)
	 && eri_try_unserialize_uint64 (file, &rlimit->max);
}

void
eri_unserialize_rlimit (eri_file_t file, struct eri_rlimit *rlimit)
{
  eri_assert (eri_try_unserialize_rlimit (file, rlimit));
}

void
eri_serialize_rusage (eri_file_t file, const struct eri_rusage *rusage)
{
  eri_serialize_timeval (file, &rusage->utime);
  eri_serialize_timeval (file, &rusage->stime);
  eri_serialize_int64 (file, rusage->maxrss);
  eri_serialize_int64 (file, rusage->ixrss);
  eri_serialize_int64 (file, rusage->idrss);
  eri_serialize_int64 (file, rusage->isrss);
  eri_serialize_int64 (file, rusage->minflt);
  eri_serialize_int64 (file, rusage->majflt);
  eri_serialize_int64 (file, rusage->nswap);
  eri_serialize_int64 (file, rusage->inblock);
  eri_serialize_int64 (file, rusage->oublock);
  eri_serialize_int64 (file, rusage->msgsnd);
  eri_serialize_int64 (file, rusage->msgrcv);
  eri_serialize_int64 (file, rusage->nsignals);
  eri_serialize_int64 (file, rusage->nvcsw);
  eri_serialize_int64 (file, rusage->nivcsw);
}

uint8_t
eri_try_unserialize_rusage (eri_file_t file, struct eri_rusage *rusage)
{
  return eri_try_unserialize_timeval (file, &rusage->utime)
	 && eri_try_unserialize_timeval (file, &rusage->stime)
	 && eri_try_unserialize_int64 (file, &rusage->maxrss)
	 && eri_try_unserialize_int64 (file, &rusage->ixrss)
	 && eri_try_unserialize_int64 (file, &rusage->idrss)
	 && eri_try_unserialize_int64 (file, &rusage->isrss)
	 && eri_try_unserialize_int64 (file, &rusage->minflt)
	 && eri_try_unserialize_int64 (file, &rusage->majflt)
	 && eri_try_unserialize_int64 (file, &rusage->nswap)
	 && eri_try_unserialize_int64 (file, &rusage->inblock)
	 && eri_try_unserialize_int64 (file, &rusage->oublock)
	 && eri_try_unserialize_int64 (file, &rusage->msgsnd)
	 && eri_try_unserialize_int64 (file, &rusage->msgrcv)
	 && eri_try_unserialize_int64 (file, &rusage->nsignals)
	 && eri_try_unserialize_int64 (file, &rusage->nvcsw)
	 && eri_try_unserialize_int64 (file, &rusage->nivcsw);
}

void
eri_unserialize_rusage (eri_file_t file, struct eri_rusage *rusage)
{
  eri_assert (eri_try_unserialize_rusage (file, rusage));
}

void
eri_serialize_ustat (eri_file_t file, const struct eri_ustat *ustat)
{
  eri_serialize_int32 (file, ustat->tfree);
  eri_serialize_uint64 (file, ustat->tinode);
  eri_serialize_uint8_array (file, (void *) ustat->fname,
			     sizeof ustat->fname);
  eri_serialize_uint8_array (file, (void *) ustat->fpack,
			     sizeof ustat->fpack);
}
uint8_t
eri_try_unserialize_ustat (eri_file_t file, struct eri_ustat *ustat)
{
  return eri_try_unserialize_int32 (file, &ustat->tfree)
	 && eri_try_unserialize_uint64 (file, &ustat->tinode)
	 && eri_try_unserialize_uint8_array (file, (void *) ustat->fname,
					     sizeof ustat->fname)
	 && eri_try_unserialize_uint8_array (file, (void *) ustat->fpack,
					     sizeof ustat->fpack);
}

void eri_unserialize_ustat (eri_file_t file, struct eri_ustat *ustat)
{
  eri_assert (eri_try_unserialize_ustat (file, ustat));
}

void
eri_serialize_statfs (eri_file_t file, const struct eri_statfs *statfs)
{
  eri_serialize_int64 (file, statfs->type);
  eri_serialize_int64 (file, statfs->bsize);
  eri_serialize_uint64 (file, statfs->blocks);
  eri_serialize_uint64 (file, statfs->bfree);
  eri_serialize_uint64 (file, statfs->bavail);
  eri_serialize_uint64 (file, statfs->files);
  eri_serialize_uint64 (file, statfs->ffree);
  eri_serialize_int32 (file, statfs->fsid.val[0]);
  eri_serialize_int32 (file, statfs->fsid.val[1]);
  eri_serialize_int64 (file, statfs->namelen);
  eri_serialize_int64 (file, statfs->frsize);
  eri_serialize_int64 (file, statfs->flags);
}

uint8_t
eri_try_unserialize_statfs (eri_file_t file, struct eri_statfs *statfs)
{
  return eri_try_unserialize_int64 (file, &statfs->type)
	 && eri_try_unserialize_int64 (file, &statfs->bsize)
	 && eri_try_unserialize_uint64 (file, &statfs->blocks)
	 && eri_try_unserialize_uint64 (file, &statfs->bfree)
	 && eri_try_unserialize_uint64 (file, &statfs->bavail)
	 && eri_try_unserialize_uint64 (file, &statfs->files)
	 && eri_try_unserialize_uint64 (file, &statfs->ffree)
	 && eri_try_unserialize_int32 (file, statfs->fsid.val)
	 && eri_try_unserialize_int32 (file, statfs->fsid.val + 1)
	 && eri_try_unserialize_int64 (file, &statfs->namelen)
	 && eri_try_unserialize_int64 (file, &statfs->frsize)
	 && eri_try_unserialize_int64 (file, &statfs->flags);
}

void
eri_unserialize_statfs (eri_file_t file, struct eri_statfs *statfs)
{
  eri_assert (eri_try_unserialize_statfs (file, statfs));
}

void
eri_serialize_sysinfo (eri_file_t file, const struct eri_sysinfo *info)
{
  eri_serialize_int64 (file, info->uptime);
  eri_serialize_uint64 (file, info->loads[0]);
  eri_serialize_uint64 (file, info->loads[1]);
  eri_serialize_uint64 (file, info->loads[2]);
  eri_serialize_uint64 (file, info->totalram);
  eri_serialize_uint64 (file, info->freeram);
  eri_serialize_uint64 (file, info->sharedram);
  eri_serialize_uint64 (file, info->bufferram);
  eri_serialize_uint64 (file, info->totalswap);
  eri_serialize_uint64 (file, info->freeswap);
  eri_serialize_uint16 (file, info->procs);
  eri_serialize_uint64 (file, info->totalhigh);
  eri_serialize_uint64 (file, info->freehigh);
  eri_serialize_uint32 (file, info->mem_unit);
}

uint8_t
eri_try_unserialize_sysinfo (eri_file_t file, struct eri_sysinfo *info)
{
  return eri_try_unserialize_int64 (file, &info->uptime)
	 && eri_try_unserialize_uint64 (file, info->loads)
	 && eri_try_unserialize_uint64 (file, info->loads + 1)
	 && eri_try_unserialize_uint64 (file, info->loads + 2)
	 && eri_try_unserialize_uint64 (file, &info->totalram)
	 && eri_try_unserialize_uint64 (file, &info->freeram)
	 && eri_try_unserialize_uint64 (file, &info->sharedram)
	 && eri_try_unserialize_uint64 (file, &info->bufferram)
	 && eri_try_unserialize_uint64 (file, &info->totalswap)
	 && eri_try_unserialize_uint64 (file, &info->freeswap)
	 && eri_try_unserialize_uint16 (file, &info->procs)
	 && eri_try_unserialize_uint64 (file, &info->totalhigh)
	 && eri_try_unserialize_uint64 (file, &info->freehigh)
	 && eri_try_unserialize_uint32 (file, &info->mem_unit);
}

void
eri_unserialize_sysinfo (eri_file_t file, struct eri_sysinfo *info)
{
  eri_assert (eri_try_unserialize_sysinfo (file, info));
}

void
eri_serialize_epoll_event (eri_file_t file,
			   const struct eri_epoll_event *event)
{
  eri_serialize_uint32 (file, event->events);
  eri_serialize_uint64 (file, event->data);
}

uint8_t
eri_try_unserialize_epoll_event (eri_file_t file,
				 struct eri_epoll_event *event)
{
  return eri_try_unserialize_uint32 (file, &event->events)
	 && eri_try_unserialize_uint64 (file, &event->data);
}

void
eri_unserialize_epoll_event (eri_file_t file,
			     struct eri_epoll_event *event)
{
  eri_assert (eri_try_unserialize_epoll_event (file, event));
}

#if 0
void
eri_serialize_epoll_event_array (eri_file_t file,
			const struct eri_epoll_event *events, uint64_t len)
{
  uint64_t i;
  for (i = 0; i < len; ++i)
    eri_serialize_epoll_event (file, events + i);
}

uint8_t
eri_try_unserialize_epoll_event_array (eri_file_t file,
			struct eri_epoll_event *events, uint64_t len)
{
  uint64_t i;
  for (i = 0; i < len; ++i)
    if (! eri_try_unserialize_epoll_event (file, events + i))
      return 0;
  return 1;
}

void
eri_unserialize_epoll_event_array (eri_file_t file,
			struct eri_epoll_event *events, uint64_t len)
{
  eri_assert (eri_try_unserialize_epoll_event_array (file, events, len));
}
#endif

void
eri_serialize_init_record (eri_file_t file, const struct eri_init_record *rec)
{
  eri_serialize_uint64 (file, rec->ver);
  eri_serialize_uint64 (file, rec->rdx);
  eri_serialize_uint64 (file, rec->rsp);
  eri_serialize_uint64 (file, rec->rip);

  eri_serialize_uint64 (file, rec->page_size);
  eri_serialize_uint64 (file, rec->brk);
  eri_serialize_sigset (file, &rec->sig_mask);
  eri_serialize_stack (file, &rec->sig_alt_stack);

  eri_serialize_int32 (file, rec->user_pid);

  eri_serialize_uint64 (file, rec->map_range.start);
  eri_serialize_uint64 (file, rec->map_range.end);
  eri_serialize_uint64 (file, rec->atomic_table_size);
}

void
eri_unserialize_init_record (eri_file_t file, struct eri_init_record *rec)
{
  rec->ver = eri_unserialize_uint64 (file);
  rec->rdx = eri_unserialize_uint64 (file);
  rec->rsp = eri_unserialize_uint64 (file);
  rec->rip = eri_unserialize_uint64 (file);

  rec->page_size = eri_unserialize_uint64 (file);
  rec->brk = eri_unserialize_uint64 (file);
  eri_unserialize_sigset (file, &rec->sig_mask);
  eri_unserialize_stack (file, &rec->sig_alt_stack);

  rec->user_pid = eri_unserialize_int32 (file);

  rec->map_range.start = eri_unserialize_uint64 (file);
  rec->map_range.end = eri_unserialize_uint64 (file);
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
  eri_serialize_uint8 (file, rec->type);
}

void
eri_unserialize_init_map_record (eri_file_t file,
				 struct eri_init_map_record *rec)
{
  rec->start = eri_unserialize_uint64 (file);
  rec->end = eri_unserialize_uint64 (file);
  rec->prot = eri_unserialize_uint8 (file);
  rec->grows_down = eri_unserialize_uint8 (file);
  rec->type = eri_unserialize_uint8 (file);
}

void
eri_serialize_async_signal_record (eri_file_t file,
				const struct eri_async_signal_record *rec)
{
  eri_serialize_uint64 (file, rec->in);
  eri_serialize_siginfo (file, &rec->info);
  if (rec->info.sig) eri_serialize_sig_act (file, &rec->act);
}

uint8_t
eri_try_unserialize_async_signal_record (eri_file_t file,
				struct eri_async_signal_record *rec)
{
  if (! eri_try_unserialize_uint64 (file, &rec->in)
      || ! eri_try_unserialize_siginfo (file, &rec->info)) return 0;
  if (! rec->info.sig) return 1;
  return eri_try_unserialize_sig_act (file, &rec->act);
}

void
eri_unserialize_async_signal_record (eri_file_t file,
				struct eri_async_signal_record *rec)
{
  eri_assert (eri_try_unserialize_async_signal_record (file, rec));
}

#define ATOMIC_RECORD_SAME_VER	1

void
eri_serialize_atomic_record (eri_file_t file,
			     const struct eri_atomic_record *rec)
{
  eri_serialize_uint8 (file, rec->ok);
  if (! rec->ok) return;

  uint8_t flags = rec->ver.first == rec->ver.second
				? ATOMIC_RECORD_SAME_VER : 0;
  eri_serialize_uint8 (file, flags);
  eri_serialize_uint64 (file, rec->ver.first);
  if (! (flags & ATOMIC_RECORD_SAME_VER))
    eri_serialize_uint64 (file, rec->ver.second);
}

uint8_t
eri_try_unserialize_atomic_record (eri_file_t file,
				   struct eri_atomic_record *rec)
{
  if (! eri_try_unserialize_uint8 (file, &rec->ok)) return 0;
  if (! rec->ok) return 1;

  if (rec->ok != 1) return 0;

  uint8_t flags;
  if (! eri_try_unserialize_uint8 (file, &flags)) return 0;
  if (! eri_try_unserialize_uint64 (file, &rec->ver.first)) return 0;
  if (flags & ATOMIC_RECORD_SAME_VER) rec->ver.second = rec->ver.first;
  else if (! eri_try_unserialize_uint64 (file, &rec->ver.second)) return 0;
  return 1;
}

void
eri_unserialize_atomic_record (eri_file_t file,
			       struct eri_atomic_record *rec)
{
  eri_assert (eri_try_unserialize_atomic_record (file, rec));
}

void
eri_serialize_syscall_res_in_record (eri_file_t file,
			const struct eri_syscall_res_in_record *rec)
{
  eri_serialize_uint64 (file, rec->result);
  eri_serialize_uint64 (file, rec->in);
}

uint8_t
eri_try_unserialize_syscall_res_in_record (eri_file_t file,
			struct eri_syscall_res_in_record *rec)
{
  return eri_try_unserialize_uint64 (file, &rec->result)
	 && eri_try_unserialize_uint64 (file, &rec->in);
}

void
eri_unserialize_syscall_res_in_record (eri_file_t file,
			struct eri_syscall_res_in_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_res_in_record (file, rec));
}

void
eri_serialize_syscall_res_io_record (eri_file_t file,
			const struct eri_syscall_res_io_record *rec)
{
  eri_serialize_uint64 (file, rec->out);
  eri_serialize_syscall_res_in_record (file, &rec->res);
}

uint8_t
eri_try_unserialize_syscall_res_io_record (eri_file_t file,
			struct eri_syscall_res_io_record *rec)
{
  return eri_try_unserialize_uint64 (file, &rec->out)
	 && eri_try_unserialize_syscall_res_in_record (file, &rec->res);
}

void
eri_unserialize_syscall_res_io_record (eri_file_t file,
			struct eri_syscall_res_io_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_res_io_record (file, rec));
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

uint8_t
eri_try_unserialize_syscall_clone_record (eri_file_t file,
			struct eri_syscall_clone_record *rec)
{
  if (! eri_try_unserialize_uint64 (file, &rec->out)
      || ! eri_try_unserialize_uint64 (file, &rec->result)) return 0;
  if (eri_syscall_is_error (rec->result)) return 1;
  return eri_try_unserialize_uint64 (file, &rec->id);
}

void
eri_unserialize_syscall_clone_record (eri_file_t file,
			struct eri_syscall_clone_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_clone_record (file, rec));
}

void
eri_serialize_syscall_exit_record (eri_file_t file,
			const struct eri_syscall_exit_record *rec)
{
  eri_serialize_uint64 (file, rec->out);
  eri_serialize_atomic_record (file, &rec->clear_tid);
}

uint8_t
eri_try_unserialize_syscall_exit_record (eri_file_t file,
			struct eri_syscall_exit_record *rec)
{
  return eri_try_unserialize_uint64 (file, &rec->out)
	 && eri_try_unserialize_atomic_record (file, &rec->clear_tid);
}

void
eri_unserialize_syscall_exit_record (eri_file_t file,
			struct eri_syscall_exit_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_exit_record (file, rec));
}

void
eri_serialize_syscall_rt_sigpending_record (eri_file_t file,
			const struct eri_syscall_rt_sigpending_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  eri_serialize_sigset (file, &rec->set);
}

uint8_t
eri_try_unserialize_syscall_rt_sigpending_record (eri_file_t file,
			struct eri_syscall_rt_sigpending_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && eri_try_unserialize_sigset (file, &rec->set);
}

void
eri_unserialize_syscall_rt_sigpending_record (eri_file_t file,
			struct eri_syscall_rt_sigpending_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_rt_sigpending_record (file, rec));
}

void
eri_serialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			const struct eri_syscall_rt_sigtimedwait_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_siginfo (file, &rec->info);
}

uint8_t
eri_try_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_siginfo (file, &rec->info));
}

void
eri_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_rt_sigtimedwait_record (file, rec));
}

void
eri_serialize_syscall_stat_record (eri_file_t file,
			const struct eri_syscall_stat_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_stat (file, &rec->stat);
}

uint8_t
eri_try_unserialize_syscall_stat_record (eri_file_t file,
			struct eri_syscall_stat_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_stat (file, &rec->stat));
}

void
eri_unserialize_syscall_stat_record (eri_file_t file,
			struct eri_syscall_stat_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_stat_record (file, rec));
}

void
eri_serialize_syscall_uname_record (eri_file_t file,
			const struct eri_syscall_uname_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  eri_serialize_utsname (file, &rec->utsname);
}

uint8_t
eri_try_unserialize_syscall_uname_record (eri_file_t file,
			struct eri_syscall_uname_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && eri_try_unserialize_utsname (file, &rec->utsname);
}

void
eri_unserialize_syscall_uname_record (eri_file_t file,
			struct eri_syscall_uname_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_uname_record (file, rec));
}

void
eri_serialize_syscall_times_record (eri_file_t file,
			const struct eri_syscall_times_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_tms (file, &rec->tms);
}

uint8_t
eri_try_unserialize_syscall_times_record (eri_file_t file,
			struct eri_syscall_times_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_tms (file, &rec->tms));
}

void
eri_unserialize_syscall_times_record (eri_file_t file,
			struct eri_syscall_times_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_times_record (file, rec));
}

void
eri_serialize_syscall_gettimeofday_record (eri_file_t file,
			const struct eri_syscall_gettimeofday_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_timeval (file, &rec->time);
}

uint8_t
eri_try_unserialize_syscall_gettimeofday_record (eri_file_t file,
			struct eri_syscall_gettimeofday_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_timeval (file, &rec->time));
}

void
eri_unserialize_syscall_gettimeofday_record (eri_file_t file,
			struct eri_syscall_gettimeofday_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_gettimeofday_record (file, rec));
}

void
eri_serialize_syscall_clock_gettime_record (eri_file_t file,
			const struct eri_syscall_clock_gettime_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_timespec (file, &rec->time);
}

uint8_t
eri_try_unserialize_syscall_clock_gettime_record (eri_file_t file,
			struct eri_syscall_clock_gettime_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_timespec (file, &rec->time));
}

void
eri_unserialize_syscall_clock_gettime_record (eri_file_t file,
			struct eri_syscall_clock_gettime_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_clock_gettime_record (file, rec));
}

void
eri_serialize_syscall_getrlimit_record (eri_file_t file,
			const struct eri_syscall_getrlimit_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_rlimit (file, &rec->rlimit);
}

uint8_t
eri_try_unserialize_syscall_getrlimit_record (eri_file_t file,
			struct eri_syscall_getrlimit_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_rlimit (file, &rec->rlimit));
}

void
eri_unserialize_syscall_getrlimit_record (eri_file_t file,
			struct eri_syscall_getrlimit_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_getrlimit_record (file, rec));
}

void
eri_serialize_syscall_prlimit64_record (eri_file_t file,
			const struct eri_syscall_prlimit64_record *rec)
{
  eri_serialize_uint64 (file, rec->out);
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_rlimit (file, &rec->rlimit);
}

uint8_t
eri_try_unserialize_syscall_prlimit64_record (eri_file_t file,
			struct eri_syscall_prlimit64_record *rec)
{
  return eri_try_unserialize_uint64 (file, &rec->out)
	 && eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_rlimit (file, &rec->rlimit));
}

void
eri_unserialize_syscall_prlimit64_record (eri_file_t file,
			struct eri_syscall_prlimit64_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_prlimit64_record (file, rec));
}

void
eri_serialize_syscall_getrusage_record (eri_file_t file,
			const struct eri_syscall_getrusage_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_rusage (file, &rec->rusage);
}

uint8_t
eri_try_unserialize_syscall_getrusage_record (eri_file_t file,
			struct eri_syscall_getrusage_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_rusage (file, &rec->rusage));
}

void
eri_unserialize_syscall_getrusage_record (eri_file_t file,
			struct eri_syscall_getrusage_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_getrusage_record (file, rec));
}

void
eri_serialize_syscall_accept_record (eri_file_t file,
			const struct eri_syscall_accept_record *rec)
{
  eri_serialize_uint64 (file, rec->out);
  eri_serialize_syscall_res_in_record (file, &rec->res);
  eri_serialize_uint32 (file, rec->addrlen);
  if (rec->addrlen)
    eri_serialize_uint8_array (file, (void *) &rec->addr, rec->addrlen);
}

uint8_t
eri_try_unserialize_syscall_accept_record (eri_file_t file,
			struct eri_syscall_accept_record *rec)
{
  return eri_try_unserialize_uint64 (file, &rec->out)
	 && eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && eri_try_unserialize_uint32 (file, &rec->addrlen)
	 && (! rec->addrlen
	     || (rec->addrlen <= sizeof rec->addr
		 && eri_try_unserialize_uint8_array (file,
				(void *) &rec->addr, rec->addrlen)));
}

void
eri_unserialize_syscall_accept_record (eri_file_t file,
			struct eri_syscall_accept_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_accept_record (file, rec));
}

void
eri_serialize_syscall_getsockname_record (eri_file_t file,
			const struct eri_syscall_getsockname_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  eri_serialize_uint32 (file, rec->addrlen);
  if (rec->addrlen)
    eri_serialize_uint8_array (file, (void *) &rec->addr, rec->addrlen);
}

uint8_t
eri_try_unserialize_syscall_getsockname_record (eri_file_t file,
			struct eri_syscall_getsockname_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && eri_try_unserialize_uint32 (file, &rec->addrlen)
	 && (! rec->addrlen
	     || (rec->addrlen <= sizeof rec->addr
		 && eri_try_unserialize_uint8_array (file,
				(void *) &rec->addr, rec->addrlen)));
}

void
eri_unserialize_syscall_getsockname_record (eri_file_t file,
			struct eri_syscall_getsockname_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_getsockname_record (file, rec));
}

void
eri_serialize_syscall_ustat_record (eri_file_t file,
			const struct eri_syscall_ustat_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_ustat (file, &rec->ustat);
}

uint8_t
eri_try_unserialize_syscall_ustat_record (eri_file_t file,
			struct eri_syscall_ustat_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_ustat (file, &rec->ustat));
}

void
eri_unserialize_syscall_ustat_record (eri_file_t file,
			struct eri_syscall_ustat_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_ustat_record (file, rec));
}

void
eri_serialize_syscall_statfs_record (eri_file_t file,
			const struct eri_syscall_statfs_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_statfs (file, &rec->statfs);
}

uint8_t
eri_try_unserialize_syscall_statfs_record (eri_file_t file,
			struct eri_syscall_statfs_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_statfs (file, &rec->statfs));
}

void
eri_unserialize_syscall_statfs_record (eri_file_t file,
			struct eri_syscall_statfs_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_statfs_record (file, rec));
}

void
eri_serialize_syscall_pipe_record (eri_file_t file,
			const struct eri_syscall_pipe_record *rec)
{
  eri_serialize_uint64 (file, rec->out);
  eri_serialize_syscall_res_in_record (file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    eri_serialize_int32_array (file, rec->pipe, eri_length_of (rec->pipe));
}

uint8_t
eri_try_unserialize_syscall_pipe_record (eri_file_t file,
			struct eri_syscall_pipe_record *rec)
{
  return eri_try_unserialize_uint64 (file, &rec->out)
	 && eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && (eri_syscall_is_non_fault_error (rec->res.result)
	     || eri_try_unserialize_int32_array (file, rec->pipe,
						 eri_length_of (rec->pipe)));
}

void
eri_unserialize_syscall_pipe_record (eri_file_t file,
			struct eri_syscall_pipe_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_pipe_record (file, rec));
}

void
eri_serialize_syscall_sysinfo_record (eri_file_t file,
			const struct eri_syscall_sysinfo_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  eri_serialize_sysinfo (file, &rec->info);
}

uint8_t
eri_try_unserialize_syscall_sysinfo_record (eri_file_t file,
			struct eri_syscall_sysinfo_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && eri_try_unserialize_sysinfo (file, &rec->info);
}

void
eri_unserialize_syscall_sysinfo_record (eri_file_t file,
			struct eri_syscall_sysinfo_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_sysinfo_record (file, rec));
}

void
eri_serialize_syscall_futex_record (eri_file_t file,
			const struct eri_syscall_futex_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  eri_serialize_atomic_record (file, &rec->atomic);
}

uint8_t
eri_try_unserialize_syscall_futex_record (eri_file_t file,
			struct eri_syscall_futex_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && eri_try_unserialize_atomic_record (file, &rec->atomic);
}

void
eri_unserialize_syscall_futex_record (eri_file_t file,
			struct eri_syscall_futex_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_futex_record (file, rec));
}


void
eri_serialize_syscall_futex_requeue_record (eri_file_t file,
			const struct eri_syscall_futex_requeue_record *rec)
{
  eri_serialize_syscall_res_in_record (file, &rec->res);
  eri_serialize_uint8 (file, rec->cmp);
  if (rec->cmp)
    eri_serialize_atomic_record (file, &rec->atomic);
}

uint8_t
eri_try_unserialize_syscall_futex_requeue_record (eri_file_t file,
			struct eri_syscall_futex_requeue_record *rec)
{
  return eri_try_unserialize_syscall_res_in_record (file, &rec->res)
	 && eri_try_unserialize_uint8 (file, &rec->cmp)
	 && (! rec->cmp
	     || eri_try_unserialize_atomic_record (file, &rec->atomic));
}

void
eri_unserialize_syscall_futex_requeue_record (eri_file_t file,
			struct eri_syscall_futex_requeue_record *rec)
{
  eri_assert (
	eri_try_unserialize_syscall_futex_requeue_record (file, rec));
}
