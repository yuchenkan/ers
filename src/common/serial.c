#include <lib/util.h>
#include <lib/syscall.h>

#include <common/serial.h>

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
eri_serialize_uint8_array (eri_file_t file, const uint8_t *a, uint64_t size)
{
  eri_assert_fwrite (file, a, size, 0);
}

void
eri_unserialize_uint8_array (eri_file_t file, uint8_t *a, uint64_t size)
{
  eri_assert_fread (file, a, size, 0);
}

void
eri_unserialize_skip_uint8_array (eri_file_t file, uint64_t size)
{
  eri_assert_fseek (file, size, 1);
}

void
eri_serialize_uint64_array (eri_file_t file, const uint64_t *a, uint64_t size)
{
  eri_assert_fwrite (file, a, size * sizeof a[0], 0);
}

void
eri_unserialize_uint64_array (eri_file_t file, uint64_t *a, uint64_t size)
{
  eri_assert_fread (file, a, size * sizeof a[0], 0);
}

void
eri_serialize_pair (eri_file_t file, struct eri_pair pair)
{
  eri_serialize_uint64 (file, pair.first);
  eri_serialize_uint64 (file, pair.second);
}

struct eri_pair
eri_unserialize_pair (eri_file_t file)
{
  struct eri_pair pair = {
    .first = eri_unserialize_uint64 (file),
    .second = eri_unserialize_uint64 (file)
  };
  return pair;
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
eri_unserialize_stack (eri_file_t file, struct eri_stack *stack)
{
  stack->sp = eri_unserialize_uint64 (file);
  stack->flags = eri_unserialize_int32 (file);
  stack->size = eri_unserialize_uint64 (file);
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
eri_serialize_sigaction (eri_file_t file, const struct eri_sigaction *act)
{
  eri_serialize_uint64 (file, (uint64_t) act->act);
  if ((uint64_t) act->act < 16) return;
  eri_serialize_int32 (file, act->flags);
  eri_serialize_uint64 (file, (uint64_t) act->restorer);
  eri_serialize_sigset (file, &act->mask);
}

void
eri_unserialize_sigaction (eri_file_t file, struct eri_sigaction *act)
{
  act->act = (void *) eri_unserialize_uint64 (file);
  if ((uint64_t) act->act < 16) return;
  act->flags = eri_unserialize_int32 (file);
  act->restorer = (void *) eri_unserialize_uint64 (file);
  eri_unserialize_sigset (file, &act->mask);
}

void
eri_serialize_ver_sigaction (eri_file_t file,
			     const struct eri_ver_sigaction *act)
{
  eri_serialize_sigaction (file, &act->act);
  eri_serialize_uint64 (file, act->ver);
}

void
eri_unserialize_ver_sigaction (eri_file_t file,
			       struct eri_ver_sigaction *act)
{
  eri_unserialize_sigaction (file, &act->act);
  act->ver = eri_unserialize_uint64 (file);
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
eri_serialize_signal_record (eri_file_t file,
			     const struct eri_async_signal_record *rec)
{
  eri_serialize_uint64 (file, rec->in);
  eri_serialize_siginfo (file, &rec->info);
  if (rec->info.sig)
    eri_serialize_ver_sigaction (file, &rec->act);
}

void
eri_unserialize_signal_record (eri_file_t file,
			       struct eri_async_signal_record *rec)
{
  rec->in = eri_unserialize_uint64 (file);
  eri_unserialize_siginfo (file, &rec->info);
  if (rec->info.sig)
    eri_unserialize_ver_sigaction (file, &rec->act);
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

void
eri_unserialize_atomic_record (eri_file_t file,
			       struct eri_atomic_record *rec)
{
  uint8_t flags = eri_unserialize_uint8 (file);
  rec->updated = !! (flags & ATOMIC_RECORD_UPDATED);
  rec->ver.first = eri_unserialize_uint64 (file);
  rec->ver.second = flags & ATOMIC_RECORD_SAME_VER
		? rec->ver.first : eri_unserialize_uint64 (file);
  rec->val = flags & ATOMIC_RECORD_ZERO_VAL
		? 0 : eri_unserialize_uint64 (file);
}

void
eri_serialize_syscall_res_in_record (eri_file_t file,
			const struct eri_syscall_res_in_record *rec)
{
  eri_serialize_uint64 (file, rec->result);
  eri_serialize_uint64 (file, rec->in);
}

void
eri_unserialize_syscall_res_in_record (eri_file_t file,
			struct eri_syscall_res_in_record *rec)
{
  rec->result = eri_unserialize_uint64 (file);
  rec->in = eri_unserialize_uint64 (file);
}

void
eri_serialize_syscall_res_io_record (eri_file_t file,
			const struct eri_syscall_res_io_record *rec)
{
  eri_serialize_uint64 (file, rec->out);
  eri_serialize_uint64 (file, rec->result);
  eri_serialize_uint64 (file, rec->in);
}

void
eri_unserialize_syscall_res_io_record (eri_file_t file,
			struct eri_syscall_res_io_record *rec)
{
  rec->out = eri_unserialize_uint64 (file);
  rec->result = eri_unserialize_uint64 (file);
  rec->in = eri_unserialize_uint64 (file);
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

void
eri_serialize_syscall_exit_clear_tid_record (eri_file_t file,
			const struct eri_syscall_exit_clear_tid_record *rec)
{
  eri_serialize_uint64 (file, rec->out);
  eri_serialize_atomic_record (file, &rec->clear_tid);
}

void
eri_unserialize_syscall_exit_clear_tid_record (eri_file_t file,
			struct eri_syscall_exit_clear_tid_record *rec)
{
  rec->out = eri_unserialize_uint64 (file);
  eri_unserialize_atomic_record (file, &rec->clear_tid);
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

void
eri_unserialize_syscall_rt_sigpending_record (eri_file_t file,
			struct eri_syscall_rt_sigpending_record *rec)
{
  rec->result = eri_unserialize_uint64 (file);
  if (eri_syscall_is_error (rec->result)) return;
  rec->in = eri_unserialize_uint64 (file);
  eri_unserialize_sigset (file, &rec->set);
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

void
eri_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec)
{
  rec->result = eri_unserialize_uint64 (file);
  if (! eri_syscall_is_error (rec->result) || rec->result == ERI_EINTR)
    rec->in = eri_unserialize_uint64 (file);
  if (! eri_syscall_is_error (rec->result))
    eri_unserialize_siginfo (file, &rec->info);
}

static uint8_t
copy_serialize_uint8_array (eri_file_t file, uint8_t *buf, uint8_t size,
	uint8_t (*copy) (void *, void *, const void *, uint64_t), void *args,
	uint8_t ok, uint8_t serial)
{
  if (! copy)
    {
      eri_unserialize_uint8_array (file, buf, size);
      return 1;
    }

  uint64_t cur;
  uint8_t cur_buf[1024];
  for (cur = 0; cur < size; cur += sizeof cur_buf)
    {
      uint64_t cur_size = eri_min (sizeof cur_buf, size - cur);
      if (serial)
	{
	  if (ok)
	    ok = copy (args, cur_buf, buf + cur, cur_size);
	  eri_serialize_uint8_array (file, cur_buf, cur_size);
	}
      else
	{
	  eri_unserialize_uint8_array (file, cur_buf, cur_size);
	  if (ok)
	    ok = copy (args, buf + cur, cur_buf, cur_size);
	}
    }
  return ok;
}

void
eri_serialize_syscall_read_record (eri_file_t file,
			const struct eri_syscall_read_record *rec)
{
  eri_serialize_uint64 (file, rec->result);
  eri_serialize_uint64 (file, rec->in);
  if (eri_syscall_is_error (rec->result)) return;

  copy_serialize_uint8_array (file, rec->buf, rec->result,
			      rec->copy, rec->args, 1, 1);
}

void
eri_unserialize_syscall_read_record (eri_file_t file,
			struct eri_syscall_read_record *rec)
{
  rec->result = eri_unserialize_uint64 (file);
  rec->in = eri_unserialize_uint64 (file);
  if (eri_syscall_is_error (rec->result)) return;

  copy_serialize_uint8_array (file, rec->buf, rec->result,
			      rec->copy, rec->args, 1, 0);
}

static void
serialize_iovec (eri_file_t file, struct eri_iovec *iov, uint64_t bytes,
		 void *copy, void *args, uint8_t serial)
{
  uint8_t ok = 1;
  uint64_t cur, cur_len;
  uint8_t i = 0;
  for (cur = 0; cur < bytes; cur += cur_len)
    {
      cur_len = ok ? eri_min (iov[i].len, bytes - cur) : bytes - cur;
      ok = copy_serialize_uint8_array (file, iov[i].base,
				       cur_len, copy, args, ok, serial);
    }
}

void
eri_serialize_syscall_readv_record (eri_file_t file,
			const struct eri_syscall_readv_record *rec)
{
  eri_serialize_uint64 (file, rec->result);
  eri_serialize_uint64 (file, rec->in);
  if (eri_syscall_is_error (rec->result)) return;

  serialize_iovec (file, rec->iov, rec->result, rec->copy, rec->args, 1);
}

void
eri_unserialize_syscall_readv_record (eri_file_t file,
			struct eri_syscall_readv_record *rec)
{
  rec->result = eri_unserialize_uint64 (file);
  rec->in = eri_unserialize_uint64 (file);
  if (eri_syscall_is_error (rec->result)) return;

  serialize_iovec (file, rec->iov, rec->result, rec->copy, rec->args, 0);
}

