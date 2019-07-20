#ifndef ERI_LIVE_THREAD_RECORDER_H
#define ERI_LIVE_THREAD_RECORDER_H

#include <stdint.h>

#include <lib/printf.h>

struct eri_mtpool;
struct eri_init_record;
struct eri_atomic_record;
struct eri_buf_file;

struct eri_entry;
struct eri_live_thread_recorder_group;
struct eri_live_thread_recorder;

struct eri_live_thread_recorder_group *
	eri_live_thread_recorder__create_group (struct eri_mtpool *pool,
				const char *path, uint64_t file_buf_size);
void eri_live_thread_recorder__destroy_group (
		struct eri_live_thread_recorder_group *group);

struct eri_live_thread_recorder *eri_live_thread_recorder__create (
	struct eri_live_thread_recorder_group *group,
	struct eri_entry *entry, uint64_t id, eri_file_t log);
void eri_live_thread_recorder__destroy (
		struct eri_live_thread_recorder *th_rec);

void eri_live_thread_recorder__rec_init (
		struct eri_live_thread_recorder *th_rec,
		struct eri_init_record *rec);

void eri_live_thread_recorder__rec_signal (
		struct eri_live_thread_recorder *th_rec,
		uint8_t async, void *rec);

void eri_live_thread_recorder__rec_syscall_read (
		struct eri_live_thread_recorder *th_rec,
		struct eri_syscall_res_in_record *rec,
		uint8_t readv, void *dst);
void eri_live_thread_recorder__rec_syscall_mmap (
		struct eri_live_thread_recorder *th_rec,
		struct eri_syscall_res_in_record *rec, uint64_t len);
void eri_live_thread_recorder__rec_syscall_readlink (
	struct eri_live_thread_recorder *th_rec,
	struct eri_syscall_res_in_record *rec, char *buf, uint64_t len);
void eri_live_thread_recorder__rec_syscall (
		struct eri_live_thread_recorder *th_rec,
		uint16_t magic, void *rec);

void eri_live_thread_recorder__rec_sync_async (
		struct eri_live_thread_recorder *th_rec, uint64_t cnt);
void eri_live_thread_recorder__rec_restart_sync_async (
		struct eri_live_thread_recorder *th_rec, uint64_t cnt);

void eri_live_thread_recorder__rec_atomic (
		struct eri_live_thread_recorder *th_rec,
		struct eri_atomic_record *rec);

#endif
