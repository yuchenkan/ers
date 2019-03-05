#include <lib/malloc.h>
#include <live/thread-recorder.h>

/* TODO */

struct eri_live_thread_recorder
{
};

struct eri_live_thread_recorder *
eri_live_thread_recorder__create (struct eri_mtpool *pool, uint64_t id)
{
  return 0;
}

void
eri_live_thread_recorder__destroy (struct eri_live_thread_recorder *rec)
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
