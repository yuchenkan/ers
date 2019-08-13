#ifndef TST_LIVE_TST_TST_SELECT_H
#define TST_LIVE_TST_TST_SELECT_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

#define TST_LIVE_SELECT_DEFINE_UTILS(name, nth, npipe) \
struct ERI_PASTE (name, _data)						\
{									\
  eri_aligned16 uint8_t stack[nth + 1][1024 * 1024];			\
  struct tst_live_clone_args pipe_args[nth];				\
  struct tst_live_clone_raise_args raise_args;				\
  int32_t pipes[nth][npipe][2];						\
  uint8_t done[nth][npipe];						\
};									\
									\
static void								\
ERI_PASTE (name, _write) (void *args)					\
{									\
  char buf = 0x12;							\
  int32_t (*pipes)[2] = args;						\
  uint64_t i;								\
  for (i = 0; i < npipe; ++i)						\
    tst_assert_syscall (write, pipes[i][1], &buf, 1);			\
}									\
									\
static void								\
ERI_PASTE (name, _read) (struct ERI_PASTE (name, _data) *d,		\
			 uint64_t th, uint64_t  idx)			\
{									\
  char buf;								\
  tst_assert_syscall (read, d->pipes[th][idx][0], &buf, 1);		\
  eri_assert (buf == 0x12);						\
  eri_assert (! d->done[th][idx]);					\
  d->done[th][idx] = 1;							\
}									\
									\
static void								\
ERI_PASTE (name, _init) (struct tst_rand *rand,				\
		struct ERI_PASTE (name, _data) *d,void *sig_handler)	\
{									\
  struct eri_sigaction act = {						\
    sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_RESTART,	\
    tst_assert_sys_sigreturn						\
  };									\
  tst_assert_sys_sigaction (ERI_SIGRTMIN, &act, 0);			\
									\
  uint64_t i, j;							\
  for (i = 0; i < nth; ++i)						\
    {									\
      for (j = 0; j < npipe; ++j)					\
	tst_assert_syscall (pipe2, d->pipes[i] + j,			\
			    ERI_O_DIRECT | ERI_O_NONBLOCK);		\
      d->pipe_args[i].top = tst_stack_top (d->stack[i]);		\
      d->pipe_args[i].delay = tst_rand (rand, 1024, 2048);		\
      d->pipe_args[i].fn = ERI_PASTE (name, _write);			\
      d->pipe_args[i].args = d->pipes[i];				\
    }									\
  d->raise_args.args.top = tst_stack_top (d->stack[nth]);		\
  d->raise_args.args.delay = tst_rand (rand, 256, 1024);		\
  d->raise_args.sig = ERI_SIGRTMIN;					\
  d->raise_args.count = 1;						\
}									\
									\
static void								\
ERI_PASTE (name, _fini) (struct ERI_PASTE (name, _data) *d)		\
{									\
  uint64_t i, j;							\
  for (i = 0; i < nth; ++i)						\
    for (j = 0; j < npipe; ++j)						\
	{								\
	  tst_assert_syscall (close, d->pipes[i][j][0]);		\
	  tst_assert_syscall (close, d->pipes[i][j][1]);		\
	}								\
}									\
									\
static void								\
ERI_PASTE (name, _clone) (struct ERI_PASTE (name, _data) *d)		\
{									\
  uint64_t i, j;							\
  for (i = 0; i < nth; ++i)						\
    {									\
      tst_assert_live_clone (d->pipe_args + i);				\
      for (j = 0; j < npipe; ++j) d->done[i][j] = 0;			\
    }									\
  tst_assert_live_clone_raise (&d->raise_args);				\
}									\
									\
static void								\
ERI_PASTE (name, _join) (struct ERI_PASTE (name, _data) *d)		\
{									\
  uint64_t i;								\
  for (i = 0; i < nth; ++i)						\
    tst_assert_sys_futex_wait (&d->pipe_args[i].alive, 1, 0);		\
  tst_assert_sys_futex_wait (&d->raise_args.args.alive, 1, 0);		\
}

#define TST_LIVE_SELECT_TIMEOUT(to, sub, d, ...) \
  do {									\
    typeof (to) _to = to;						\
    typeof (d) _d = d;							\
    _to->sec = 1;							\
    tst_assert_live_clone_raise (&_d->raise_args);			\
    uint64_t _res = tst_syscall (__VA_ARGS__);				\
    eri_assert (_res == 0 || _res == ERI_EINTR);			\
    eri_info (ERI_STR (sub) ": %lu\n", _to->sub);			\
    tst_check (_to->sub);						\
    tst_assert_sys_futex_wait (&_d->raise_args.args.alive, 1, 0);	\
  } while (0)

#endif
