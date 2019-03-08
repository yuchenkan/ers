#include <common.h>
#include <lib/malloc.h>
#include <lib/printf.h>
#include <live/thread-recorder.h>

/* TODO */

struct eri_live_thread_recorder
{
  struct eri_mtpool *pool;
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

  eri_mkdir (path);
  char name[eri_build_path_len (path, "t", id)];
  eri_build_path (path, "t", id, name);
  eri_assert_fopen (name, 0, &rec->file, rec->buf, buf_size);

  return rec;
}

void
eri_live_thread_recorder__destroy (struct eri_live_thread_recorder *rec)
{
  eri_assert_fclose (rec->file);
  eri_assert_mtfree (rec->pool, rec);
}

void
eri_live_thread_recorder__rec_init_maps (
			struct eri_live_thread_recorder *rec,
			uint64_t start, uint64_t end)
{
}

void
eri_live_thread_recorder__rec_syscall (
		struct eri_live_thread_recorder *rec,
		struct eri_live_thread_recorder__rec_syscall_args *args)
{
}

void
eri_live_thread_recorder__rec_sync_async (
			struct eri_live_thread_recorder *rec)
{
}

void
eri_live_thread_recorder__rec_restart_sync_async (
			struct eri_live_thread_recorder *rec, uint64_t cnt)
{
}

void
eri_live_thread_recorder__rec_atomic (
			struct eri_live_thread_recorder *rec,
			const uint64_t *ver)
{
}

void
eri_live_thread_recorder__rec_atomic_load (
			struct eri_live_thread_recorder *rec,
			const uint64_t *ver, uint64_t val)
{
}
