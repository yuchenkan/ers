#ifndef ERI_LIVE_SIGNAL_THREAD_H
#define ERI_LIVE_SIGNAL_THREAD_H

#include <stdint.h>

#include <compiler.h>
#include <lib/syscall.h>

struct eri_mtpool;

struct eri_common_args;
struct eri_rtld_args;

struct eri_helper;
struct eri_live_thread;
struct eri_live_signal_thread;

#define ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP	ERI_NSIG

void eri_live_signal_thread_init_thread_sig_stack (
		struct eri_live_signal_thread *sig_th,
		uint8_t *stack, uint64_t stack_size);

noreturn void eri_live_signal_thread_init_main (
		struct eri_common_args *args,
		struct eri_rtld_args *rtld_args);

struct eri_live_signal_thread_clone_args
{
  void *args;
  int32_t tid;
  uint64_t result;
};

uint8_t eri_live_signal_thread_clone (
		struct eri_live_signal_thread *sig_th,
		struct eri_live_signal_thread_clone_args *args);

uint8_t eri_live_signal_thread_exit (
		struct eri_live_signal_thread *sig_th,
		uint8_t group, uint64_t status);

noreturn void eri_live_signal_thread_die (
		struct eri_live_signal_thread *sig_th);

uint8_t eri_live_signal_thread_sig_action (
		struct eri_live_signal_thread *sig_th,
		int32_t sig, const struct eri_sigaction *act,
		struct eri_sigaction *old_act);

uint8_t eri_live_signal_thread_sig_mask_async (
		struct eri_live_signal_thread *sig_th,
		const struct eri_sigset *mask);
uint8_t eri_live_signal_thread_sig_tmp_mask_async (
		struct eri_live_signal_thread *sig_th,
		const struct eri_sigset *mask);
uint8_t eri_live_signal_thread_sig_mask_all (
		struct eri_live_signal_thread *sig_th);
void eri_live_signal_thread_sig_reset (
		struct eri_live_signal_thread *sig_th,
		const struct eri_sigset *mask);
/*
 * Returns 0 if failed to mask_all, the existing signal and corresponding
 * digested sig_act are put in the info and act.
 * Otherwise, raw sig_act for the info is put in the act.
 */
void eri_live_signal_thread_sig_prepare_sync (
		struct eri_live_signal_thread *sig_th,
		struct eri_siginfo *info, struct eri_sigaction *act);

struct eri_live_signal_thread_sig_fd_read_args
{
  int32_t fd;
  int32_t nr;
  const uint64_t *a;

  int32_t *mask_lock;
  const struct eri_sigset *mask;
  int32_t flags;

  uint64_t result;
};

uint8_t eri_live_signal_thread_sig_fd_read (
		struct eri_live_signal_thread *sig_th,
		struct eri_live_signal_thread_sig_fd_read_args *args);

/*
 * Returns 1 if we have got signals. This is for kill-like syscalls.
 *
 * "If the signal causes a handler to be called, raise() will return only
 * after the signal handler has returned."
 */
uint8_t eri_live_signal_thread_syscall (
		struct eri_live_signal_thread *sig_th,
		struct eri_sys_syscall_args *args);

const struct eri_common_args *eri_live_signal_thread_get_args (
		const struct eri_live_signal_thread *sig_th);

struct eri_mtpool *eri_live_signal_thread_get_pool (
		struct eri_live_signal_thread *sig_th);

const struct eri_sigset *eri_live_signal_thread_get_sig_mask (
		const struct eri_live_signal_thread *sig_th);

int32_t eri_live_signal_thread_get_pid (
		const struct eri_live_signal_thread *sig_th);
int32_t eri_live_signal_thread_get_tid (
		const struct eri_live_signal_thread *sig_th);

#endif
