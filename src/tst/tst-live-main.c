#include <compiler.h>

#include <common.h>
#include <live-rtld.h>
#include <live-signal-thread.h>

static eri_aligned16 uint8_t stack[8 * 1024 * 1024];

eri_noreturn void tst_main (void **args);
eri_noreturn void tst_live_start (void);

eri_noreturn void
tst_main (void **args)
{
  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  void *top = stack + sizeof stack - 8;
  *(void **) top = args;

  extern uint8_t tst_live_map_start[];
  extern uint8_t tst_live_map_end[];
  extern uint8_t tst_live_buf_start[];
  extern uint8_t tst_live_buf_end[];

  struct eri_live_rtld_args rtld_args = {
    0, 0, (uint64_t) top, (uint64_t) tst_live_start,
    .page_size = 4096,
    .map_start = (uint64_t) tst_live_map_start,
    .map_end = (uint64_t) tst_live_map_end,
    .buf = (uint64_t) tst_live_buf_start,
    .buf_size = tst_live_buf_end - tst_live_buf_start
  };

  eri_live_signal_thread__init_main (&rtld_args);
}
