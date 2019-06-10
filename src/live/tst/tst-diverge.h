#ifndef TST_LIVE_TST_TST_DIVERGE_H
#define TST_LIVE_TST_TST_DIVERGE_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

#define TST_LIVE_DIVERGE_DEFINE_TST(nth, fn_body, fn_args, seed, debug) \
static uint8_t diverge;							\
static struct tst_rand _rand;						\
static uint8_t _stack[nth][1024 * 1024];				\
									\
static void								\
_start (void *args) { fn_body; }					\
									\
eri_noreturn void							\
tst_live_start (void *_args, uint8_t _div)				\
{									\
  diverge = _div;							\
  eri_global_enable_debug = debug;					\
									\
  eri_info ("start\n");							\
  tst_rand_init (&_rand, seed);						\
									\
  uint8_t _i;								\
  for (_i = 0; _i < eri_length_of (_stack); ++_i)			\
    {									\
      struct tst_live_clone_args _args = {				\
	tst_stack_top (_stack[_i]), tst_rand (&_rand, 0, 32),		\
	_start, (fn_args) ? eri_itop ((fn_args) + _i) : 0		\
      };								\
      tst_assert_live_clone (&_args);					\
    }									\
									\
  tst_assert_sys_exit (0);						\
}

#endif
