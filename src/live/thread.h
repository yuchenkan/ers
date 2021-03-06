#ifndef ERI_LIVE_THREAD_H
#define ERI_LIVE_THREAD_H

#include <stdint.h>

#include <lib/printf.h>

struct eri_mtpool;
struct eri_siginfo;
struct eri_sigframe;

struct eri_live_rtld_args;
struct eri_sig_act;

struct eri_helper;
struct eri_live_signal_thread;

struct eri_live_thread;
struct eri_live_thread_group;

struct eri_live_thread__create_group_args
{
  struct eri_live_rtld_args *rtld_args;
  const char *log;
  uint64_t file_buf_size;
  int32_t user_pid;
  uint64_t *io;
};

struct eri_live_thread_group *eri_live_thread__create_group (
			struct eri_mtpool *pool,
			struct eri_live_thread__create_group_args *args);
void eri_live_thread__destroy_group (struct eri_live_thread_group *group);

uint8_t eri_live_thread__sig_digest_act (struct eri_live_thread *th,
			const struct eri_siginfo *info,
			struct eri_sig_act *act, uint8_t *force_masked);

struct eri_live_thread *eri_live_thread__create_main (
			struct eri_live_thread_group *group,
			struct eri_live_signal_thread *sig_th,
			struct eri_live_rtld_args *rtld_args,
			int32_t user_tid);
void eri_live_thread__clone_main (struct eri_live_thread *th);

struct eri_live_thread__create_args;
struct eri_live_thread *eri_live_thread__create (
			struct eri_live_signal_thread *sig_th,
			struct eri_live_thread__create_args *create_args);
void eri_live_thread__set_user_tid (struct eri_live_thread *th,
				    int32_t user_tid);
uint64_t eri_live_thread__clone (struct eri_live_thread *th);

void eri_live_thread__destroy (struct eri_live_thread *th);

void eri_live_thread__join (struct eri_live_thread *th);

void eri_live_thread__sig_handler (struct eri_live_thread *th,
		struct eri_sigframe *frame, struct eri_sig_act *act);

eri_file_t eri_live_thread__get_sig_log (const struct eri_live_thread *th);

int32_t eri_live_thread__get_pid (const struct eri_live_thread *th);
int32_t eri_live_thread__get_tid (const struct eri_live_thread *th);

#endif
