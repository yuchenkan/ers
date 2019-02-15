#ifndef ERI_LIVE_THREAD_H
#define ERI_LIVE_THREAD_H

#include <stdint.h>

#include <compiler.h>

struct eri_sigaction;
struct eri_siginfo;
struct eri_ucontext;
struct eri_sigframe;

struct eri_rtld_args;
struct eri_helper;
struct eri_live_thread;
struct eri_live_signal_thread;

uint8_t eri_live_thread_sig_digest_act (
		struct eri_live_thread *th, const struct eri_siginfo *info,
		struct eri_sigaction *act);

struct eri_live_thread *eri_live_thread_create_main (
				struct eri_live_signal_thread *sig_th,
				struct eri_rtld_args *rtld_args);
void eri_live_thread_clone_main (struct eri_live_thread *th);

struct eri_live_thread_create_args;
struct eri_live_thread *eri_live_thread_create (
				struct eri_live_signal_thread *sig_th,
				struct eri_live_thread_create_args *create_args);
uint64_t eri_live_thread_clone (struct eri_live_thread *th);

void eri_live_thread_destroy (struct eri_live_thread *th,
			      struct eri_helper *helper);

void eri_live_thread_join (struct eri_live_thread *th);

void eri_live_thread_sig_handler (
		struct eri_live_thread *th, struct eri_sigframe *frame,
		struct eri_sigaction *act);

int32_t eri_live_thread_get_pid (const struct eri_live_thread *th);
int32_t eri_live_thread_get_tid (const struct eri_live_thread *th);

#endif
