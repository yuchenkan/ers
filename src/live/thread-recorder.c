/* vim: set ft=cpp: */

#include <stdarg.h>

#include <lib/malloc.h>
#include <lib/atomic.h>
#include <lib/buf.h>
#include <lib/printf.h>
#include <lib/syscall-common.h>

#include <common/debug.h>
#include <common/common.h>
#include <common/serial.h>
#include <common/entry.h>

#include <live/thread-recorder.h>

struct eri_live_thread_recorder_group
{
  struct eri_mtpool *pool;
  const char *path;
  uint64_t file_buf_size;
  uint64_t page_size;

  uint64_t mmap;
};

struct eri_live_thread_recorder_group *
eri_live_thread_recorder__create_group (struct eri_mtpool *pool,
	const char *path, uint64_t file_buf_size, uint64_t page_size)
{
  if (! path) return 0;

  eri_mkdir (path);
  struct eri_live_thread_recorder_group *group
	= eri_assert_mtmalloc_struct (pool, typeof (*group),
				      (path, eri_strlen (path) + 1));
  group->pool = pool;
  eri_strcpy ((void *) group->path, path);
  group->file_buf_size = file_buf_size;
  group->page_size = page_size;
  group->mmap = 0;
  return group;
}

void
eri_live_thread_recorder__destroy_group (
			struct eri_live_thread_recorder_group *group)
{
  if (group) eri_assert_mtfree (group->pool, group);
}

struct eri_live_thread_recorder
{
  struct eri_live_thread_recorder_group *group;

  struct eri_entry *entry;
  eri_file_t log;

  uint8_t pending_sync_async;
  uint64_t sync_async_cnt;

  eri_file_t file;
  uint8_t buf[0];
};

struct eri_live_thread_recorder *
eri_live_thread_recorder__create (
	struct eri_live_thread_recorder_group *group,
	struct eri_entry *entry, uint64_t id, eri_file_t log)
{
  if (! group) return 0;

  uint64_t buf_size = group->file_buf_size;
  struct eri_live_thread_recorder *th_rec
		= eri_assert_mtmalloc (group->pool, sizeof *th_rec + buf_size);
  th_rec->group = group;
  th_rec->entry = entry;
  th_rec->log = log;

  th_rec->pending_sync_async = 0;

  char name[eri_build_path_len (group->path, "t", id)];
  eri_build_path (group->path, "t", id, name);
  th_rec->file = eri_assert_fopen (name, 0, th_rec->buf, buf_size);

  return th_rec;
}

static void
write_sync_async (struct eri_live_thread_recorder *th_rec, uint64_t step)
{
  eri_serialize_mark (th_rec->file, ERI_SYNC_RECORD);
  eri_serialize_magic (th_rec->file, ERI_SYNC_ASYNC_MAGIC);
  eri_serialize_uint64 (th_rec->file, step);
}

static void
submit_sync_async (struct eri_live_thread_recorder *th_rec)
{
  if (! th_rec->pending_sync_async) return;

  write_sync_async (th_rec, 0);
  th_rec->pending_sync_async = 0;
}

void
eri_live_thread_recorder__destroy (struct eri_live_thread_recorder *th_rec)
{
  if (! th_rec) return;

  submit_sync_async (th_rec);
  eri_assert_fclose (th_rec->file);
  eri_assert_mtfree (th_rec->group->pool, th_rec);
}

static uint8_t
record_mmap_file (struct eri_live_thread_recorder *th_rec,
		  uint64_t start, uint64_t len)
{
  struct eri_live_thread_recorder_group *group = th_rec->group;
  uint64_t id = eri_atomic_inc_fetch (&group->mmap, 0);
  eri_serialize_uint64 (th_rec->file, id);

  char name[eri_build_path_len (group->path, "m", id)];
  eri_build_path (group->path, "m", id, name);
  int32_t fd = eri_assert_sys_open (name, 0);

  uint8_t *buf = (void *) start;
  uint64_t c = 0;
  while (c < len)
    {
      uint64_t l = eri_syscall (write, fd, buf + c, len - c);
      if (l == ERI_EINTR) continue;
      if (l == ERI_EFAULT) break;
      eri_assert (eri_syscall_is_ok (l));
      c += l;
    }

  eri_assert_syscall (close, fd);
  return c == len;
}

struct record_init_map_args
{
  struct eri_live_thread_recorder *th_rec;
  uint64_t rsp;
};

static void
record_init_map (const struct eri_smaps_map *map, void *args)
{
  struct record_init_map_args *a = args;
  struct eri_live_thread_recorder *th_rec = a->th_rec;

  uint64_t start = map->range.start;
  uint64_t end = map->range.end;
  int32_t prot = map->prot;
  const char *path = map->path;
  eri_xassert (! map->grows_down, eri_info);

  eri_log (th_rec->log, "%s %lx %lx %u\n", path ? : "<>", start, end, prot);

  uint8_t type = eri_within (&map->range, a->rsp)
			? ERI_INIT_MAP_STACK
			: (path ? ERI_INIT_MAP_FILE : ERI_INIT_MAP_EMPTY);

  eri_file_t file = th_rec->file;
  struct eri_init_map_record rec = {
    start, end, prot, 0, type
  };
  eri_serialize_mark (file, ERI_INIT_MAP_RECORD);
  eri_serialize_init_map_record (file, &rec);

  if (type == ERI_INIT_MAP_STACK)
    {
      eri_serialize_uint64 (file, a->rsp);
      eri_serialize_uint8_array (file, (void *) a->rsp, end - a->rsp);
    }
  else if (type == ERI_INIT_MAP_FILE)
    {
      if (! prot & ERI_PROT_READ)
	eri_assert_syscall (mprotect, start, end - start,
			    prot | ERI_PROT_READ);

      eri_assert (record_mmap_file (th_rec, start, end - start));

      if (! prot & ERI_PROT_READ)
	eri_assert_syscall (mprotect, start, end - start, prot);
    }
}

void
eri_live_thread_recorder__rec_init (
			struct eri_live_thread_recorder *th_rec,
			struct eri_init_record *rec)
{
  if (! th_rec) return;

  if (eri_global_enable_debug) eri_dump_maps ();

  eri_serialize_mark (th_rec->file, ERI_INIT_RECORD);
  eri_serialize_init_record (th_rec->file, rec);

  struct record_init_map_args args = { th_rec, rec->rsp };
  eri_init_foreach_map (th_rec->group->pool, &rec->map_range,
			     record_init_map, &args);
  eri_log (th_rec->log, "leave rec_init\n");
}

void
eri_live_thread_recorder__rec_signal (
			struct eri_live_thread_recorder *th_rec,
			uint8_t async, void *rec)
{
  if (! th_rec) return;

  submit_sync_async (th_rec);

  if (async)
    {
      eri_serialize_mark (th_rec->file, ERI_ASYNC_RECORD);
      eri_serialize_async_signal_record (th_rec->file, rec);
    }
  else
    {
      eri_serialize_mark (th_rec->file, ERI_SYNC_RECORD);
      eri_serialize_magic (th_rec->file, ERI_SIGNAL_MAGIC);
      eri_serialize_sig_act (th_rec->file, rec);
    }
}

void
eri_live_thread_recorder__rec_syscall_restart_out (
			struct eri_live_thread_recorder *th_rec,
			uint64_t out)
{
  if (! th_rec) return;

  submit_sync_async (th_rec);

  eri_serialize_mark (th_rec->file, ERI_SYSCALL_RESTART_OUT_RECORD);
  eri_serialize_uint64 (th_rec->file, out);
}

static void
syscall_start_record (struct eri_live_thread_recorder *th_rec,
		      uint16_t magic)
{
  submit_sync_async (th_rec);

  eri_log3 (th_rec->log, "%s\n", eri_record_magic_str (magic));

  eri_serialize_mark (th_rec->file, ERI_SYNC_RECORD);
  eri_serialize_magic (th_rec->file, magic);
}

static void
syscall_rec_getrandom (struct eri_live_thread_recorder *th_rec,
	struct eri_live_thread_recorder__syscall_getrandom_record *rec)
{
  eri_serialize_uint64 (th_rec->file, rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res))
    {
      eri_serialize_uint64 (th_rec->file, rec->len);
      eri_serialize_uint8_array (th_rec->file, rec->buf, rec->len);
    }

}

void
eri_live_thread_recorder__rec_syscall_geturandom (
		struct eri_live_thread_recorder *th_rec,
		uint8_t type, ...)
{
  if (! th_rec) return;

  va_list arg;
  va_start (arg, type);
  if (type == ERI_LIVE_THREAD_RECORDER__REC_SYSCALL_GETURANDOM_START)
    syscall_start_record (th_rec, ERI_SYSCALL_GETRANDOM_URANDOM_MAGIC);
  else if (type == ERI_LIVE_THREAD_RECORDER__REC_SYSCALL_GETURANDOM_BUF)
    {
      uint8_t *buf = va_arg (arg, void *);
      uint64_t len = va_arg (arg, uint64_t);

      eri_assert (len);
      eri_serialize_uint64 (th_rec->file, len);
      eri_serialize_uint8_array (th_rec->file, buf, len);
    }
  else if (type == ERI_LIVE_THREAD_RECORDER__REC_SYSCALL_GETURANDOM_END)
    {
      uint64_t res = va_arg (arg, uint64_t);
      eri_serialize_uint64 (th_rec->file, 0);
      eri_serialize_uint64 (th_rec->file, res);
    }
  else eri_assert_unreachable ();
  va_end (arg);
}

#define malloc_read_buf(total, group, buf_size) \
  ({ struct eri_live_thread_recorder_group *_group = group;		\
     uint64_t *_buf_size = buf_size;					\
     *_buf_size = eri_min (total,					\
	eri_max (_group->file_buf_size, _group->page_size) * 2);	\
     *_buf_size <= 1024							\
		? (*_buf_size ? __builtin_alloca (*_buf_size) : 0)	\
		: eri_assert_mtmalloc (_group->pool, *_buf_size); })

#define free_read_buf(group, buf, buf_size) \
  do { struct eri_live_thread_recorder_group *_group = group;		\
       void *_buf = buf;						\
       if ((buf_size) > 1024)						\
	 eri_assert_mtfree (_group->pool, _buf); } while (0)

static void
syscall_ser_buf (struct eri_live_thread_recorder *th_rec, uint8_t *dst,
		 uint64_t total)
{
  struct eri_entry *entry = th_rec->entry;
  struct eri_live_thread_recorder_group *group = th_rec->group;

  uint64_t buf_size;
  uint8_t *buf = malloc_read_buf (total, group, &buf_size);

  uint64_t off = 0;
  while (off < total)
    {
      uint64_t size = eri_min (buf_size, total - off);
      uint8_t *user = dst + off;
      if (! eri_entry__copy_from_user (entry, buf, user, size, 0))
	goto out;

      eri_serialize_uint64 (th_rec->file, size);
      eri_serialize_uint8_array (th_rec->file, buf, size);
      off += size;
    }

out:
  free_read_buf (group, buf, buf_size);
  eri_serialize_uint64 (th_rec->file, 0);
}

static void
syscall_rec_read (struct eri_live_thread_recorder *th_rec,
		struct eri_live_thread_recorder__syscall_read_record *rec)
{
  eri_serialize_syscall_res_io_record (th_rec->file, &rec->res);
  uint64_t res = rec->res.res.result;
  if (eri_syscall_is_error (res) || res == 0) return;

  syscall_ser_buf (th_rec, rec->buf, res);
}

static void
syscall_rec_readv (struct eri_live_thread_recorder *th_rec,
		struct eri_live_thread_recorder__syscall_readv_record *rec)
{
  eri_serialize_syscall_res_io_record (th_rec->file, &rec->res);
  uint64_t res = rec->res.res.result;
  if (eri_syscall_is_error (res) || res == 0) return;

  struct eri_entry *entry = th_rec->entry;
  uint64_t total = res;
  struct eri_live_thread_recorder_group *group = th_rec->group;

  uint64_t buf_size;
  uint8_t *buf = malloc_read_buf (total, group, &buf_size);

  struct eri_iovec *iov = rec->iov;
  while (iov->len == 0) ++iov;

  uint64_t off = 0, iov_off = 0;
  while (off < total)
    {
      uint64_t size = eri_min (buf_size, total - off);
      uint64_t o = 0;
      while (o < size)
	{
	  uint8_t *user = (uint8_t *) iov->base + iov_off;
	  uint64_t s = eri_min (iov->len - iov_off, size - o);
	  if (! eri_entry__copy_from_user (entry, buf + o, user, s, 0))
	    goto out;

	  o += s;
	  if ((iov_off += s) == iov->len)
	    {
	      iov_off = 0;
	      do ++iov; while (iov->len == 0);
	    }
	}

      eri_serialize_uint64 (th_rec->file, size);
      eri_serialize_uint8_array (th_rec->file, buf, size);
      off += size;
    }

out:
  free_read_buf (group, buf, buf_size);
  eri_serialize_uint64 (th_rec->file, 0);
}

static void
syscall_rec_mmap (struct eri_live_thread_recorder *th_rec,
		struct eri_live_thread_recorder__syscall_mmap_record *rec)
{
  eri_serialize_syscall_res_in_record (th_rec->file, &rec->res);
  if (eri_syscall_is_error (rec->res.result)) return;

  if (rec->len == 0)
    {
      eri_serialize_uint64 (th_rec->file, 0);
      return;
    }

  eri_serialize_uint8 (th_rec->file,
		       record_mmap_file (th_rec, rec->res.result, rec->len));
}

static void
syscall_rec_getcwd (struct eri_live_thread_recorder *th_rec,
		struct eri_live_thread_recorder__syscall_getcwd_record *rec)
{
  eri_serialize_syscall_res_in_record (th_rec->file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    {
      eri_serialize_uint64 (th_rec->file, rec->len);
      eri_serialize_uint8_array (th_rec->file, (void *) rec->buf, rec->len);
    }
}

static void
syscall_rec_select (struct eri_live_thread_recorder *th_rec,
		struct eri_live_thread_recorder__syscall_select_record *rec)
{
  eri_serialize_syscall_res_in_record (th_rec->file, &rec->res);

  uint8_t flags = eri_get_serial_select_flags (rec->readfds,
	    rec->writefds, rec->exceptfds, rec->psel, rec->timeout);
  eri_serialize_uint8 (th_rec->file, flags);

  if (eri_syscall_is_fault_or_ok (rec->res.result))
    {
      eri_serialize_uint32 (th_rec->file, rec->size);
      if (rec->readfds)
	eri_serialize_uint8_array (th_rec->file, rec->readfds, rec->size);
      if (rec->writefds)
	eri_serialize_uint8_array (th_rec->file, rec->writefds, rec->size);
      if (rec->exceptfds)
	eri_serialize_uint8_array (th_rec->file, rec->exceptfds, rec->size);
    }

  if (rec->timeout && rec->psel)
    eri_serialize_timespec (th_rec->file, rec->timeout);
  else if (rec->timeout)
    eri_serialize_timeval (th_rec->file, rec->timeout);
}

static void
syscall_rec_poll (struct eri_live_thread_recorder *th_rec,
		struct eri_live_thread_recorder__syscall_poll_record *rec)
{
  eri_serialize_syscall_res_in_record (th_rec->file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    {
      eri_serialize_uint64 (th_rec->file, rec->revents);

      uint64_t i, j = 0;
      for (i = 0; i < rec->nfds && j < rec->res.result; ++i)
	if (rec->fds[i].revents)
	  {
	    eri_serialize_uint64 (th_rec->file, i);
	    eri_serialize_int16 (th_rec->file, rec->fds[i].revents);
	    ++j;
	  }
    }

  eri_serialize_uint8 (th_rec->file, !! rec->tmo);
  if (rec->tmo) eri_serialize_timespec (th_rec->file, rec->tmo);
}

void
syscall_rec_epoll_wait (struct eri_live_thread_recorder *th_rec,
	struct eri_live_thread_recorder__syscall_epoll_wait_record *rec)
{
  eri_serialize_syscall_res_in_record (th_rec->file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.result))
    {
      uint64_t len = rec->res.result == ERI_EFAULT
		? 1 : eri_min (rec->res.result + 1, rec->max_events);
      uint64_t i;
      for (i = 0; i < len; ++i)
	{
	  struct eri_epoll_event event = { 0 };
	  uint8_t done = eri_entry__copy_obj_from_user (th_rec->entry,
					&event, rec->user_events + i, 0);
	  eri_serialize_uint8 (th_rec->file, done);
	  eri_serialize_epoll_event (th_rec->file, &event);

	  if (! done) break;
	}
    }
}

void
syscall_rec_recvfrom (struct eri_live_thread_recorder *th_rec,
	struct eri_live_thread_recorder__syscall_recvfrom_record *rec)
{
  eri_serialize_syscall_res_io_record (th_rec->file, &rec->res);
  if (eri_syscall_is_fault_or_ok (rec->res.res.result))
    {
      eri_serialize_uint64 (th_rec->file, rec->buf_res);
      if (eri_syscall_is_ok (rec->buf_res) && rec->buf_res)
	{
	  syscall_ser_buf (th_rec, rec->buf, rec->buf_res);
	  eri_serialize_uint32 (th_rec->file, rec->addrlen);
	  if (rec->addrlen)
	    eri_serialize_uint8_array (th_rec->file, (void *) rec->src_addr,
				       rec->addrlen);
	}
    }
}

void
eri_live_thread_recorder__rec_syscall (
		struct eri_live_thread_recorder *th_rec,
		uint16_t magic, void *rec)
{
  if (! th_rec) return;

  syscall_start_record (th_rec, magic);

  if (magic == ERI_SYSCALL_RESULT_MAGIC
      || magic == ERI_SYSCALL_IN_MAGIC || magic == ERI_SYSCALL_OUT_MAGIC
      || magic == ERI_SYSCALL_RT_SIGACTION_SET_MAGIC)
    eri_serialize_uint64 (th_rec->file, (uint64_t) rec);
  else if (magic == ERI_SYSCALL_RES_IN_MAGIC)
    eri_serialize_syscall_res_in_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_RES_IO_MAGIC)
    eri_serialize_syscall_res_io_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_CLONE_MAGIC)
    eri_serialize_syscall_clone_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_EXIT_MAGIC)
    eri_serialize_syscall_exit_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_RT_SIGACTION_MAGIC)
    {
      struct eri_sig_act *act = rec;
      eri_serialize_sigaction (th_rec->file, &act->act);
      eri_serialize_uint64 (th_rec->file, act->ver);
    }
  else if (magic == ERI_SYSCALL_RT_SIGPENDING_MAGIC)
    eri_serialize_syscall_rt_sigpending_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_RT_SIGTIMEDWAIT_MAGIC)
    eri_serialize_syscall_rt_sigtimedwait_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_STAT_MAGIC)
    eri_serialize_syscall_stat_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_UNAME_MAGIC)
    eri_serialize_syscall_uname_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_TIMES_MAGIC)
    eri_serialize_syscall_times_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_GETTIMEOFDAY_MAGIC)
    eri_serialize_syscall_gettimeofday_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_CLOCK_GETTIME_MAGIC)
    eri_serialize_syscall_clock_gettime_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_GETRLIMIT_MAGIC)
    eri_serialize_syscall_getrlimit_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_PRLIMIT64_MAGIC)
    eri_serialize_syscall_prlimit64_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_GETRUSAGE_MAGIC)
    eri_serialize_syscall_getrusage_record (th_rec->file, rec);
 else if (magic == ERI_SYSCALL_ACCEPT_MAGIC)
    eri_serialize_syscall_accept_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_GETSOCKNAME_MAGIC)
    eri_serialize_syscall_getsockname_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_USTAT_MAGIC)
    eri_serialize_syscall_ustat_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_STATFS_MAGIC)
    eri_serialize_syscall_statfs_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_PIPE_MAGIC)
    eri_serialize_syscall_pipe_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_SYSINFO_MAGIC)
    eri_serialize_syscall_sysinfo_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_FUTEX_MAGIC)
    eri_serialize_syscall_futex_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_FUTEX_REQUEUE_MAGIC)
    eri_serialize_syscall_futex_requeue_record (th_rec->file, rec);
  else if (magic == ERI_SYSCALL_GETRANDOM_RANDOM_MAGIC)
    syscall_rec_getrandom (th_rec, rec);
  else if (magic == ERI_SYSCALL_READ_MAGIC)
    syscall_rec_read (th_rec, rec);
  else if (magic == ERI_SYSCALL_READV_MAGIC)
    syscall_rec_readv (th_rec, rec);
  else if (magic == ERI_SYSCALL_MMAP_MAGIC)
    syscall_rec_mmap (th_rec, rec);
  else if (magic == ERI_SYSCALL_GETCWD_MAGIC)
    syscall_rec_getcwd (th_rec, rec);
  else if (magic == ERI_SYSCALL_SELECT_MAGIC)
    syscall_rec_select (th_rec, rec);
  else if (magic == ERI_SYSCALL_POLL_MAGIC)
    syscall_rec_poll (th_rec, rec);
  else if (magic == ERI_SYSCALL_EPOLL_WAIT_MAGIC)
    syscall_rec_epoll_wait (th_rec, rec);
  else if (magic == ERI_SYSCALL_RECVFROM_MAGIC)
    syscall_rec_recvfrom (th_rec, rec);
  else eri_assert_unreachable ();
}

void
eri_live_thread_recorder__rec_sync_async (
			struct eri_live_thread_recorder *th_rec, uint64_t cnt)
{
  if (! th_rec) return;

  submit_sync_async (th_rec);

  th_rec->pending_sync_async = 1;
  th_rec->sync_async_cnt = cnt;
}

void
eri_live_thread_recorder__rec_restart_sync_async (
			struct eri_live_thread_recorder *th_rec, uint64_t cnt)
{
  if (! th_rec) return;

  eri_assert (th_rec->pending_sync_async);

  if (th_rec->sync_async_cnt != cnt)
    write_sync_async (th_rec, th_rec->sync_async_cnt - cnt);

  th_rec->pending_sync_async = 0;
}

void
eri_live_thread_recorder__rec_atomic (
			struct eri_live_thread_recorder *th_rec,
			struct eri_atomic_record *rec)
{
  if (! th_rec) return;

  submit_sync_async (th_rec);

  eri_serialize_mark (th_rec->file, ERI_SYNC_RECORD);
  eri_serialize_magic (th_rec->file, ERI_ATOMIC_MAGIC);
  eri_serialize_atomic_record (th_rec->file, rec);
}
