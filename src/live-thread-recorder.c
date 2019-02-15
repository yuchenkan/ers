#include <live-thread-recorder.h>

#include <lib/malloc.h>

/* TODO */

struct eri_live_thread_recorder
{
};

struct eri_live_thread_recorder *
eri_live_thread_recorder_create (struct eri_mtpool *pool, uint64_t id)
{
  return 0;
}

void
eri_live_thread_recorder_destroy (struct eri_live_thread_recorder *rec)
{
}

void 
eri_live_thread_recorder_rec_sync_async (
			struct eri_live_thread_recorder *rec)
{
}

void
eri_live_thread_recorder_rec_restart_sync_async (
			struct eri_live_thread_recorder *rec, uint64_t cnt)
{
}

void
eri_live_thread_recorder_rec_atomic (
			struct eri_live_thread_recorder *rec,
			const uint64_t *ver)
{
}

void 
eri_live_thread_recorder_rec_atomic_load (
			struct eri_live_thread_recorder *rec,
			const uint64_t *ver, uint64_t val)
{
}
