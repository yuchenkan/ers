#ifndef ERI_LIVE_THREAD_RECORDER_H
#define ERI_LIVE_THREAD_RECORDER_H

#include <stdint.h>

struct eri_mtpool;
struct eri_siginfo;

struct eri_live_thread_recorder;

struct eri_live_thread_recorder *eri_live_thread_recorder__create (
		struct eri_mtpool *pool, const char *path, uint64_t id,
		uint64_t buf_size);
void eri_live_thread_recorder__destroy (
		struct eri_live_thread_recorder *rec);

void eri_live_thread_recorder__rec_init_maps (
		struct eri_live_thread_recorder *rec,
		uint64_t start, uint64_t end);

void eri_live_thread_recorder__rec_signal (
		struct eri_live_thread_recorder *rec,
		struct eri_siginfo *info);

struct eri_live_thread_recorder__rec_syscall_args
{
  uint64_t rax;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rdx;
  uint64_t r10;
  uint64_t r8;
  uint64_t r9;
};

void eri_live_thread_recorder__rec_syscall (
		struct eri_live_thread_recorder *rec,
		struct eri_live_thread_recorder__rec_syscall_args *args);

void eri_live_thread_recorder__rec_sync_async (
		struct eri_live_thread_recorder *rec);
void eri_live_thread_recorder__rec_restart_sync_async (
		struct eri_live_thread_recorder *rec, uint64_t cnt);

void eri_live_thread_recorder__rec_atomic (
		struct eri_live_thread_recorder *rec,
		const uint64_t *ver);
void eri_live_thread_recorder__rec_atomic_load (
		struct eri_live_thread_recorder *rec,
		const uint64_t *ver, uint64_t val);

#endif
