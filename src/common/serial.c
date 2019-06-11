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
eri_serialize_uint8_array (eri_file_t file, const uint8_t *a, uint64_t size)
{
  eri_assert_fwrite (file, a, sizeof *a * size, 0);
}

uint8_t
eri_try_unserialize_uint8_array (eri_file_t file, uint8_t *a, uint64_t size)
{
  return ! eri_fread (file, a, sizeof *a * size, 0);
}

void
eri_unserialize_uint8_array (eri_file_t file, uint8_t *a, uint64_t size)
{
  eri_assert (eri_try_unserialize_uint8_array (file, a, size));
}

void
eri_unserialize_skip_uint8_array (eri_file_t file, uint64_t size)
{
  eri_assert_fseek (file, sizeof (uint8_t) * size, 1);
}

void
eri_serialize_uint64_array (eri_file_t file,
			    const uint64_t *a, uint64_t size)
{
  eri_assert_fwrite (file, a, sizeof *a * size, 0);
}

uint8_t
eri_try_unserialize_uint64_array (eri_file_t file,
				  uint64_t *a, uint64_t size)
{
  return ! eri_fread (file, a, sizeof *a * size, 0);
}

void
eri_unserialize_uint64_array (eri_file_t file, uint64_t *a, uint64_t size)
{
  eri_assert (eri_try_unserialize_uint64_array (file, a, size));
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
eri_serialize_sigset (eri_file_t file, const struct eri_sigset *set)
{
  eri_assert_fwrite (file, set->val, ERI_SIG_SETSIZE, 0);
}

uint8_t
eri_try_unserialize_sigset (eri_file_t file, struct eri_sigset *set)
{
  return ! eri_fread (file, set->val, ERI_SIG_SETSIZE, 0);
}

void
eri_unserialize_sigset (eri_file_t file, struct eri_sigset *set)
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
  if (eri_sig_act_internal_act (act->act)) return;
  eri_serialize_int32 (file, act->flags);
  eri_serialize_uint64 (file, (uint64_t) act->restorer);
  eri_serialize_sigset (file, &act->mask);
}

uint8_t
eri_try_unserialize_sigaction (eri_file_t file, struct eri_sigaction *act)
{
  return eri_try_unserialize_uint64 (file, (void *) &act->act)
	 && (eri_sig_act_internal_act (act->act)
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
eri_serialize_ver_sigaction (eri_file_t file,
			     const struct eri_ver_sigaction *act)
{
  eri_serialize_sigaction (file, &act->act);
  if (act->act.act == ERI_SIG_ACT_LOST) return;
  eri_serialize_uint64 (file, act->ver);
}

uint8_t
eri_try_unserialize_ver_sigaction (eri_file_t file,
				   struct eri_ver_sigaction *act)
{
  return eri_try_unserialize_sigaction (file, &act->act)
         && (act->act.act == ERI_SIG_ACT_LOST
	     || eri_try_unserialize_uint64 (file, &act->ver));
}

void
eri_unserialize_ver_sigaction (eri_file_t file,
			       struct eri_ver_sigaction *act)
{
  eri_assert (eri_try_unserialize_ver_sigaction (file, act));
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
eri_serialize_async_signal_record (eri_file_t file,
				const struct eri_async_signal_record *rec)
{
  eri_serialize_uint64 (file, rec->in);
  eri_serialize_siginfo (file, &rec->info);
  if (rec->info.sig)
    eri_serialize_ver_sigaction (file, &rec->act);
}

uint8_t
eri_try_unserialize_async_signal_record (eri_file_t file,
				struct eri_async_signal_record *rec)
{
  if (! eri_try_unserialize_uint64 (file, &rec->in)
      || ! eri_try_unserialize_siginfo (file, &rec->info)) return 0;
  if (! rec->info.sig) return 1;
  return eri_try_unserialize_ver_sigaction (file, &rec->act);
}

void
eri_unserialize_async_signal_record (eri_file_t file,
				struct eri_async_signal_record *rec)
{
  eri_assert (eri_try_unserialize_async_signal_record (file, rec));
}

#define ATOMIC_RECORD_UPDATED	1
#define ATOMIC_RECORD_SAME_VER	2
#define ATOMIC_RECORD_ZERO_VAL	4

void
eri_serialize_atomic_record (eri_file_t file,
			     const struct eri_atomic_record *rec)
{
  uint8_t flags = (rec->updated ? ATOMIC_RECORD_UPDATED : 0)
		  | (rec->ver.first == rec->ver.second
					? ATOMIC_RECORD_SAME_VER : 0)
		  | (rec->val == 0 ? ATOMIC_RECORD_ZERO_VAL : 0);
  eri_serialize_uint8 (file, flags);
  eri_serialize_uint64 (file, rec->ver.first);
  if (! (flags & ATOMIC_RECORD_SAME_VER))
    eri_serialize_uint64 (file, rec->ver.second);
  if (! (flags & ATOMIC_RECORD_ZERO_VAL))
    eri_serialize_uint64 (file, rec->val);
}

uint8_t
eri_try_unserialize_atomic_record (eri_file_t file,
				   struct eri_atomic_record *rec)
{
  uint8_t flags;
  if (! eri_try_unserialize_uint8 (file, &flags)) return 0;
  rec->updated = !! (flags & ATOMIC_RECORD_UPDATED);
  if (! eri_try_unserialize_uint64 (file, &rec->ver.first)) return 0;
  if (flags & ATOMIC_RECORD_SAME_VER) rec->ver.second = rec->ver.first;
  else if (! eri_try_unserialize_uint64 (file, &rec->ver.second)) return 0;
  if (flags & ATOMIC_RECORD_ZERO_VAL) rec->val = 0;
  else if (! eri_try_unserialize_uint64 (file, &rec->val)) return 0;
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
  eri_serialize_uint64 (file, rec->result);
  eri_serialize_uint64 (file, rec->in);
}

uint8_t
eri_try_unserialize_syscall_res_io_record (eri_file_t file,
			struct eri_syscall_res_io_record *rec)
{
  return eri_try_unserialize_uint64 (file, &rec->out)
	 && eri_try_unserialize_uint64 (file, &rec->result)
	 && eri_try_unserialize_uint64 (file, &rec->in);
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
eri_serialize_syscall_exit_clear_tid_record (eri_file_t file,
			const struct eri_syscall_exit_clear_tid_record *rec)
{
  eri_serialize_uint64 (file, rec->out);
  eri_serialize_atomic_record (file, &rec->clear_tid);
}

uint8_t
eri_try_unserialize_syscall_exit_clear_tid_record (eri_file_t file,
			struct eri_syscall_exit_clear_tid_record *rec)
{
  return eri_try_unserialize_uint64 (file, &rec->out)
	 && eri_try_unserialize_atomic_record (file, &rec->clear_tid);
}

void
eri_unserialize_syscall_exit_clear_tid_record (eri_file_t file,
			struct eri_syscall_exit_clear_tid_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_exit_clear_tid_record (file, rec));
}

void
eri_serialize_syscall_rt_sigpending_record (eri_file_t file,
			const struct eri_syscall_rt_sigpending_record *rec)
{
  eri_serialize_uint64 (file, rec->result);
  if (eri_syscall_is_error (rec->result)) return;
  eri_serialize_uint64 (file, rec->in);
  eri_serialize_sigset (file, &rec->set);
}

uint8_t
eri_try_unserialize_syscall_rt_sigpending_record (eri_file_t file,
			struct eri_syscall_rt_sigpending_record *rec)
{
  if (! eri_try_unserialize_uint64 (file, &rec->result)) return 0;
  if (eri_syscall_is_error (rec->result)) return 1;
  return eri_try_unserialize_uint64 (file, &rec->in)
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
  eri_serialize_uint64 (file, rec->result);
  if (! eri_syscall_is_error (rec->result) || rec->result == ERI_EINTR)
    eri_serialize_uint64 (file, rec->in);
  if (! eri_syscall_is_error (rec->result))
    eri_serialize_siginfo (file, &rec->info);
}

uint8_t
eri_try_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec)
{
  if (! eri_try_unserialize_uint64 (file, &rec->result)) return 0;
  if ((! eri_syscall_is_error (rec->result) || rec->result == ERI_EINTR)
      && ! eri_try_unserialize_uint64 (file, &rec->in)) return 0;
  return eri_syscall_is_error (rec->result)
	 || eri_try_unserialize_siginfo (file, &rec->info);
}

void
eri_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec)
{
  eri_assert (eri_try_unserialize_syscall_rt_sigtimedwait_record (file, rec));
}
