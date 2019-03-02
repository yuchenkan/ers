#ifndef TST_TST_LIVE_SIG_HAND_UT_H
#define TST_TST_LIVE_SIG_HAND_UT_H

#include <stdint.h>

#include <live-thread.h>

#include <lib/syscall.h>
#include <tst/tst-util.h>

noreturn void tst_live_sig_hand_start (void);

void tst_live_sig_hand_step (int32_t sig, struct eri_siginfo *info,
			     struct eri_ucontext *ctx);

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

#endif
