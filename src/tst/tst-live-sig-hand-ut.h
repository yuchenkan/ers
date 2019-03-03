#ifndef TST_TST_LIVE_SIG_HAND_UT_H
#define TST_TST_LIVE_SIG_HAND_UT_H

#include <stdint.h>

#include <live-thread.h>

#include <lib/syscall.h>
#include <tst/tst-util.h>

struct tst_live_sig_hand_step
{
  void (*fix_ctx) (struct eri_mcontext *, void *);

  uint64_t enter;
  uint64_t leave;
  uint64_t repeat;

  uint64_t mem_size;

  uint8_t debug;
};

uint32_t tst_live_sig_hand_init_step (struct tst_live_sig_hand_step *step);

#define tst_live_sig_hand_signal(th, info, handler) \
  do {									\
    struct eri_siginfo *_info = info;					\
    _info->code = 0;							\
    struct eri_sigframe *_frame						\
	= tst_struct (_info, typeof (*_frame), info);			\
    struct eri_sigaction _act = {					\
      handler, ERI_SA_SIGINFO | ERI_SA_RESTORER, 0			\
    };									\
    eri_live_thread__sig_handler (th, _frame, &_act);			\
  } while (0)

#define TST_LIVE_SIG_HAND_DEFINE_INIT_STEP( \
				fix, ent, lev, rep, mem, cnt, dbg) \
uint32_t								\
tst_live_sig_hand_init_step (struct tst_live_sig_hand_step *step)	\
{									\
  step->fix_ctx = fix;							\
  step->enter = (uint64_t) (ent);					\
  step->leave = (uint64_t) (lev);					\
  step->repeat = (uint64_t) (rep);					\
  step->mem_size = mem;							\
  step->debug = dbg;							\
  return cnt;								\
}

#endif
