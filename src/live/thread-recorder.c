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

  uint64_t mmap;
};

struct eri_live_thread_recorder_group *
eri_live_thread_recorder__create_group (struct eri_mtpool *pool,
				const char *path, uint64_t file_buf_size)
{
  eri_mkdir (path);
  struct eri_live_thread_recorder_group *group
	= eri_assert_mtmalloc_struct (pool, typeof (*group),
				      (path, eri_strlen (path) + 1));
  group->pool = pool;
  eri_strcpy ((void *) group->path, path);
  group->file_buf_size = file_buf_size;
  group->mmap = 0;
  return group;
}

void
eri_live_thread_recorder__destroy_group (
			struct eri_live_thread_recorder_group *group)
{
  eri_assert_mtfree (group->pool, group);
}

struct eri_live_thread_recorder
{
  struct eri_live_thread_recorder_group *group;

  struct eri_entry *entry;
  struct eri_buf_file *log;

  uint8_t pending_sync_async;
  uint64_t sync_async_cnt;

  eri_file_t file;
  uint8_t buf[0];
};

struct eri_live_thread_recorder *
eri_live_thread_recorder__create (
	struct eri_live_thread_recorder_group *group,
	struct eri_entry *entry, uint64_t id, struct eri_buf_file *log)
{
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
  submit_sync_async (th_rec);
  eri_assert_fclose (th_rec->file);
  eri_assert_mtfree (th_rec->group->pool, th_rec);
}

static void
record_smaps_entry (struct eri_live_thread_recorder *th_rec,
		    uint64_t map_start, uint64_t map_end, uint64_t rsp,
		    char *buf)
{
  const char *b = buf;
  const char *d = eri_strtok (b, '-');
  *(char *) d = '\0';
  uint64_t start = eri_assert_atoi (b, 16);

  d = eri_strtok (b = d + 1, ' ');
  *(char *) d = '\0';
  uint64_t end = eri_assert_atoi (b, 16);
  if (! (end <= map_start || start >= map_end))
    {
      eri_assert (start >= map_start && end <= map_end);
      return;
    }

  eri_assert (d[1] && d[2] && d[3] && d[4] && d[5] && d[6]);
  uint8_t prot = (d[1] != '-' ? ERI_PROT_READ : 0)
		  | (d[2] != '-' ? ERI_PROT_WRITE : 0)
		  | (d[3] != '-' ? ERI_PROT_EXEC : 0);
  eri_assert (d[4] == 'p'); /* XXX: handle error */

  eri_assert (d = eri_strtok (d + 6, ' '));
  eri_assert (d = eri_strtok (d + 1, ' '));
  eri_assert (d = eri_strtok (d + 1, ' '));
  while (*d && *d == ' ') ++d;

  const char *path = 0;
  eri_assert (*d);
  if (*d != '\n')
    {
      path = d;
      d = eri_strtok (d, '\n');
    }
  *(char *) d = '\0';

  if (path && (eri_strcmp (path, "[vvar]") == 0
	       || eri_strcmp (path, "[vdso]") == 0
	       || eri_strcmp (path, "[vsyscall]") == 0))
    return;

  uint8_t grows_done = 0;
  d = eri_strstr (d + 1, "VmFlags: ");
  eri_assert (d);
  for (d = d + eri_strlen ("VmFlags: "); *d && *d != '\n'; d += 3)
    {
      eri_assert (d[0] && d[1] && d[2]);
      if (d[0] == 'g' && d[1] == 'd')
	{
	  grows_done = 1;
	  break;
	}
    }

  eri_llog (th_rec->log, "%s %lx %lx %u %u\n",
	    path ? : "<>", start, end, prot, grows_done);

  uint8_t stack = path && eri_strcmp (path, "[stack]") == 0;
  eri_assert (! path || ! stack || (rsp >= start && rsp <= end));

  eri_file_t file = th_rec->file;
  struct eri_init_map_record rec = {
    start, end, prot, grows_done, !! path
  };
  eri_serialize_mark (file, ERI_INIT_MAP_RECORD);
  eri_serialize_init_map_record (file, &rec);

  if (path)
    {
      uint64_t data_start = stack ? rsp : start;
      eri_serialize_uint64 (file, data_start);
      eri_serialize_uint64 (file, end);
      /*
       * XXX: this should be the only place we read from user without
       * protection.
       */
      eri_serialize_uint8_array (file, (void *) data_start, end - data_start);
    }
}

struct proc_smaps_line_args
{
  struct eri_live_thread_recorder *th_rec;
  uint64_t start, end, rsp;

  uint32_t line_count;
  struct eri_buf buf;
};

static void
proc_smaps_line (const char *line, uint64_t len, void *args)
{
  struct proc_smaps_line_args *a = args;
  eri_assert_buf_append (&a->buf, line, len);
  if (++a->line_count % 20)
    {
      char nl = '\n';
      eri_assert_buf_append (&a->buf, &nl, 1);
    }
  else
    {
      char e = '\0';
      eri_assert_buf_append (&a->buf, &e, 1);
      record_smaps_entry (a->th_rec, a->start, a->end, a->rsp,
			  eri_buf_release (&a->buf));
    }
}

void
eri_live_thread_recorder__rec_init (
			struct eri_live_thread_recorder *th_rec,
			struct eri_init_record *rec)
{
  if (eri_global_enable_debug) eri_dump_maps ();

  eri_serialize_mark (th_rec->file, ERI_INIT_RECORD);
  eri_serialize_init_record (th_rec->file, rec);

  struct eri_buf buf;
  eri_assert_buf_mtpool_init (&buf, th_rec->group->pool, 256);

  struct proc_smaps_line_args line_args
	= { th_rec, rec->map_range.start, rec->map_range.end, rec->rsp };
  eri_assert_buf_mtpool_init (&line_args.buf, th_rec->group->pool, 1024);
  eri_assert_file_foreach_line ("/proc/self/smaps", &buf,
				proc_smaps_line, &line_args);
  eri_assert_buf_fini (&line_args.buf);
  eri_assert_buf_fini (&buf);
  eri_llog (th_rec->log, "leave rec_init\n");
}

void
eri_live_thread_recorder__rec_signal (
			struct eri_live_thread_recorder *th_rec,
			uint8_t async, void *rec)
{
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

static void
syscall_start_record (struct eri_live_thread_recorder *th_rec,
		      uint16_t magic)
{
  submit_sync_async (th_rec);

  eri_serialize_mark (th_rec->file, ERI_SYNC_RECORD);
  eri_serialize_magic (th_rec->file, magic);
}

void
eri_live_thread_recorder__rec_read (
		struct eri_live_thread_recorder *th_rec,
		struct eri_live_thread_recorder__rec_read_args *args)
{
  syscall_start_record (th_rec, ERI_SYSCALL_READ_MAGIC);
  eri_serialize_syscall_res_in_record (th_rec->file, &args->rec);
  uint64_t res = args->rec.result;
  if (eri_syscall_is_error (res) || res == 0) return;

  struct eri_entry *entry = th_rec->entry;

  uint64_t total = res;
  struct eri_live_thread_recorder_group *group = th_rec->group;

  uint64_t buf_size = eri_min (total, group->file_buf_size * 2);
  uint8_t *buf = buf_size <= 1024 ? __builtin_alloca (buf_size)
		: eri_assert_mtmalloc (group->pool, buf_size);
  uint64_t off = 0, iov_off = 0;
  struct eri_iovec *iov = args->dst;
  if (args->readv) while (iov->len == 0) ++iov;
  while (off < total)
    {
      uint64_t size = eri_min (buf_size, total - off);
      if (! args->readv)
	{
	  uint8_t *user = (uint8_t *) args->dst + off;
	  if (eri_entry__copy_from (entry, buf, user, size) != size)
	    goto out;
	}
      else
	{
	  uint64_t o = 0;
	  while (o < size)
	    {
	      uint8_t *user = (uint8_t *) iov->base + iov_off;
	      uint64_t s = eri_min (iov->len - iov_off, size - o);
	      if (eri_entry__copy_from (entry, buf + o, user, s) != s)
		goto out;

	      o += s;
	      if ((iov_off += s) == iov->len)
		{
		  iov_off = 0;
		  do ++iov; while (iov->len == 0);
		}
	    }
	}

      eri_serialize_uint64 (th_rec->file, size);
      eri_serialize_uint8_array (th_rec->file, buf, size);
      off += size;
    }

out:
  if (buf_size > 1024) eri_assert_mtfree (group->pool, buf);
  eri_serialize_uint64 (th_rec->file, 0);
}

void
eri_live_thread_recorder__rec_mmap (
		struct eri_live_thread_recorder *th_rec,
		struct eri_syscall_res_in_record *rec, uint64_t len)
{
  syscall_start_record (th_rec, ERI_SYSCALL_MMAP_MAGIC);
  eri_serialize_syscall_res_in_record (th_rec->file, rec);
  if (eri_syscall_is_error (rec->result)) return;

  if (len == 0)
    {
      eri_serialize_uint64 (th_rec->file, 0);
      return;
    }

  struct eri_live_thread_recorder_group *group = th_rec->group;
  uint64_t id = eri_atomic_inc_fetch (&group->mmap, 0);
  eri_serialize_uint64 (th_rec->file, id);

  char name[eri_build_path_len (group->path, "m", id)];
  eri_build_path (group->path, "m", id, name);
  int32_t fd = eri_assert_sys_open (name, 0);

  uint8_t *buf = (void *) rec->result;
  uint64_t c = 0;
  while (c < len)
    {
      uint64_t l = eri_syscall (write, fd, buf + c, len - c);
      if (l == ERI_EINTR) continue;
      if (l == ERI_EFAULT) break;
      eri_assert (! eri_syscall_is_error (l));
      c += l;
    }
  eri_serialize_uint8 (th_rec->file, c == len);

  eri_assert_syscall (close, fd);
}

void
eri_live_thread_recorder__rec_syscall (
		struct eri_live_thread_recorder *th_rec,
		uint16_t magic, void *rec)
{
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
  else if (magic == ERI_SYSCALL_EXIT_CLEAR_TID_MAGIC)
    eri_serialize_syscall_exit_clear_tid_record (th_rec->file, rec);
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
  else eri_assert_unreachable ();
}

void
eri_live_thread_recorder__rec_sync_async (
			struct eri_live_thread_recorder *th_rec, uint64_t cnt)
{
  submit_sync_async (th_rec);

  th_rec->pending_sync_async = 1;
  th_rec->sync_async_cnt = cnt;
}

void
eri_live_thread_recorder__rec_restart_sync_async (
			struct eri_live_thread_recorder *th_rec, uint64_t cnt)
{
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
  submit_sync_async (th_rec);

  eri_serialize_mark (th_rec->file, ERI_SYNC_RECORD);
  eri_serialize_magic (th_rec->file, ERI_ATOMIC_MAGIC);
  eri_serialize_atomic_record (th_rec->file, rec);
}
