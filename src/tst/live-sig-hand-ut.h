#ifndef TST_LIVE_SIG_HAND_UT_H
#define TST_LIVE_SIG_HAND_UT_H

#include <stdint.h>

#include <common.h>
#include <lib/malloc.h>
#include <lib/syscall.h>

struct eri_live_thread;

struct eri_live_signal_thread
{
  struct eri_mtpool pool;
  struct eri_common_args args;

  struct eri_sigset mask;

  int32_t pid;
  int32_t tid;

  struct eri_live_thread *th;

  uint8_t sig_alt_stack_installed;
  uint8_t sig_reset;
};

#endif
