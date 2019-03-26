#ifndef ERI_LIVE_SIGNAL_THREAD_H
#define ERI_LIVE_SIGNAL_THREAD_H

#include <stdint.h>

#include <compiler.h>
#include <lib/syscall-common.h>

struct eri_mtpool;
struct eri_lock;

struct eri_live_rtld_args;
struct eri_live_sigaction;

struct eri_helper;
struct eri_live_thread;
struct eri_live_signal_thread;

#define ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP	ERI_NSIG

void eri_live_signal_thread__init_thread_sig_stack (
		struct eri_live_signal_thread *sig_th,
		uint8_t *stack, uint64_t stack_size);

eri_noreturn void eri_live_signal_thread__init_main (
		struct eri_live_rtld_args *rtld_args);

struct eri_live_signal_thread__clone_args
{
  void *args;
  uint64_t out;
  uint64_t result;
};

uint8_t eri_live_signal_thread__clone (
		struct eri_live_signal_thread *sig_th,
		struct eri_live_signal_thread__clone_args *args);

uint8_t eri_live_signal_thread__exit (
		struct eri_live_signal_thread *sig_th,
		uint8_t group, uint64_t status);

void eri_live_signal_thread__die (
		struct eri_live_signal_thread *sig_th);

struct eri_live_signal_thread__sig_action_args
{
  int32_t sig;
  const struct eri_sigaction *act;
  struct eri_sigaction *old_act;

  uint64_t ver;
};

uint8_t eri_live_signal_thread__sig_action (
		struct eri_live_signal_thread *sig_th,
		struct eri_live_signal_thread__sig_action_args *args);

uint8_t eri_live_signal_thread__sig_mask_async (
		struct eri_live_signal_thread *sig_th,
		const struct eri_sigset *mask);
uint8_t eri_live_signal_thread__sig_tmp_mask_async (
		struct eri_live_signal_thread *sig_th,
		const struct eri_sigset *mask);
uint8_t eri_live_signal_thread__sig_mask_all (
		struct eri_live_signal_thread *sig_th);
void eri_live_signal_thread__sig_reset (
		struct eri_live_signal_thread *sig_th,
		const struct eri_sigset *mask);
/*
 * Returns 0 if failed to mask_all, the existing signal and corresponding
 * digested sig_act are put in the info and act.
 * Otherwise, raw sig_act for the info is put in the act.
 */
void eri_live_signal_thread__sig_prepare_sync (
		struct eri_live_signal_thread *sig_th,
		struct eri_siginfo *info, struct eri_live_sigaction *act);

struct eri_live_signal_thread__sig_fd_read_args
{
  int32_t fd;
  int32_t nr;
  const uint64_t *a;

  struct eri_lock *mask_lock;
  const struct eri_sigset *mask;
  int32_t flags;

  uint64_t result;
};

uint8_t eri_live_signal_thread__sig_fd_read (
		struct eri_live_signal_thread *sig_th,
		struct eri_live_signal_thread__sig_fd_read_args *args);

uint64_t eri_live_signal_thread__syscall (
		struct eri_live_signal_thread *sig_th,
		struct eri_sys_syscall_args *args);

uint8_t eri_live_signal_thread__signaled (
		struct eri_live_signal_thread *sig_th);

const struct eri_sigset *eri_live_signal_thread__get_sig_mask (
		const struct eri_live_signal_thread *sig_th);

int32_t eri_live_signal_thread__get_pid (
		const struct eri_live_signal_thread *sig_th);
int32_t eri_live_signal_thread__get_tid (
		const struct eri_live_signal_thread *sig_th);

#endif
