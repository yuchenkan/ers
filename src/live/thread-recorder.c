#include <common.h>
#include <record.h>

#include <lib/malloc.h>
#include <lib/buf.h>
#include <lib/printf.h>

#include <live/thread-recorder.h>

#define PENDING_SYNC_ASYNC		1
#define PENDING_RESTART_SYNC_ASYNC	2

struct eri_live_thread_recorder
{
  struct eri_mtpool *pool;

  uint8_t pending_sync_async;
  uint64_t sync_async_cnt;
  uint64_t restart_sync_async_cnt;

  eri_file_t file;
  uint8_t buf[0];
};

struct eri_live_thread_recorder *
eri_live_thread_recorder__create (struct eri_mtpool *pool,
				  const char *path, uint64_t id,
				  uint64_t buf_size)
{
  struct eri_live_thread_recorder *rec
			= eri_assert_mtmalloc (pool, sizeof *rec + buf_size);
  rec->pool = pool;

  rec->pending_sync_async = 0;

  eri_mkdir (path);
  char name[eri_build_path_len (path, "t", id)];
  eri_build_path (path, "t", id, name);
  eri_assert_fopen (name, 0, &rec->file, rec->buf, buf_size);

  return rec;
}

static void
submit_sync_async (struct eri_live_thread_recorder *rec)
{
  if (! rec->pending_sync_async) return;

  if (rec->pending_sync_async == PENDING_RESTART_SYNC_ASYNC
      && rec->sync_async_cnt == rec->restart_sync_async_cnt)
    {
      rec->pending_sync_async = 0;
      return;
    }

  uint64_t steps = rec->pending_sync_async == PENDING_RESTART_SYNC_ASYNC
		? rec->sync_async_cnt - rec->restart_sync_async_cnt : 0;
  struct eri_marked_sync_async_record sync = {
    ERI_SYNC_RECORD, { ERI_SYNC_ASYNC_MAGIC, steps }
  };
  eri_assert_fwrite (rec->file, &sync, sizeof sync, 0);
}

void
eri_live_thread_recorder__destroy (struct eri_live_thread_recorder *rec)
{
  submit_sync_async (rec);
  eri_assert_fclose (rec->file);
  eri_assert_mtfree (rec->pool, rec);
}

static void
record_smaps_entry (struct eri_live_thread_recorder *rec,
		    uint64_t map_start, uint64_t map_end, uint64_t rsp,
		    char *buf)
{
  eri_debug ("\n");

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

  eri_debug ("%s %lx %lx %u %u\n",
	     path ? : "<>", start, end, prot, grows_done);

  uint8_t stack = path && eri_strcmp (path, "[stack]") == 0;
  eri_assert (! path || ! stack || (rsp >= start && rsp <= end));

  struct eri_marked_init_map_record init_map = {
    ERI_INIT_MAP_RECORD, { start, end, prot, grows_done, !! path }
  };
  eri_assert_fwrite (rec->file, &init_map, sizeof init_map, 0);

  if (path)
    {
      uint64_t data_start = stack ? rsp : start;
      struct eri_init_map_data_record data = { data_start, end };
      eri_assert_fwrite (rec->file, &data, sizeof data, 0);
      eri_assert_fwrite (rec->file, (void *) data_start, end - data_start, 0);
    }
  eri_debug ("leave\n");
}

struct proc_smaps_line_args
{
  struct eri_live_thread_recorder *rec;
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
      record_smaps_entry (a->rec, a->start, a->end, a->rsp,
			  eri_buf_release (&a->buf));
    }
}

void
eri_live_thread_recorder__rec_init (
			struct eri_live_thread_recorder *rec,
			struct eri_live_thread_recorder__rec_init_args *args)
{
  if (eri_global_enable_debug) eri_dump_maps ();

  struct eri_marked_init_record init = {
    ERI_INIT_RECORD,
    { 0, args->rdx, args->rsp, args->rip,
      args->sig_mask, args->start, args->end }
  };
  eri_assert_fwrite (rec->file, &init, sizeof init, 0);

  struct eri_buf buf;
  eri_assert_buf_mtpool_init (&buf, rec->pool, 256);

  struct proc_smaps_line_args line_args
			= { rec, args->start, args->end, args->rsp };
  eri_assert_buf_mtpool_init (&line_args.buf, rec->pool, 1024);
  eri_assert_file_foreach_line ("/proc/self/smaps", &buf,
				proc_smaps_line, &line_args);
  eri_assert_buf_fini (&line_args.buf);
  eri_assert_buf_fini (&buf);
  eri_debug ("leave rec_init\n");
}

void
eri_live_thread_recorder__rec_signal (
			struct eri_live_thread_recorder *rec,
			struct eri_siginfo *info)
{
  submit_sync_async (rec);
  /* TODO */
}

void
eri_live_thread_recorder__rec_syscall (
		struct eri_live_thread_recorder *rec,
		struct eri_live_thread_recorder__rec_syscall_args *args)
{
  submit_sync_async (rec);
  /* TODO */
}

void
eri_live_thread_recorder__rec_sync_async (
			struct eri_live_thread_recorder *rec, uint64_t cnt)
{
  if (rec->pending_sync_async != PENDING_RESTART_SYNC_ASYNC)
    submit_sync_async (rec);

  rec->pending_sync_async = PENDING_SYNC_ASYNC;
  rec->sync_async_cnt = cnt;
}

void
eri_live_thread_recorder__rec_restart_sync_async (
			struct eri_live_thread_recorder *rec, uint64_t cnt)
{
  eri_assert (rec->pending_sync_async == PENDING_SYNC_ASYNC);
  rec->pending_sync_async = PENDING_RESTART_SYNC_ASYNC;
  rec->restart_sync_async_cnt = cnt;
}

void
eri_live_thread_recorder__rec_atomic (
			struct eri_live_thread_recorder *rec,
			const uint64_t *ver)
{
  submit_sync_async (rec);
  /* TODO */
}

void
eri_live_thread_recorder__rec_atomic_load (
			struct eri_live_thread_recorder *rec,
			const uint64_t *ver, uint64_t val)
{
  submit_sync_async (rec);
  /* TODO */
}
