#include <compiler.h>

#include <live-signal-thread.h>
#include <rtld.h>
#include <common.h>

static uint8_t buf[256 * 1024 * 1024];
static aligned16 uint8_t stack[8 * 1024 * 1024];

noreturn void tst_main (void **args);
noreturn void tst_live_start (void);

noreturn void
tst_main (void **args)
{
  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  struct eri_common_args common_args = {
    0, 4096, 0, sizeof buf, 8 * 1024 * 1024, 0, (uint64_t) buf
  };

  void *top = stack + sizeof stack - 8;
  *(void **) top = args;

  extern uint8_t tst_live_map_start[];
  extern uint8_t tst_live_map_end[];

  struct eri_rtld_args rtld_args = {
    0, 0, (uint64_t) top, (uint64_t) tst_live_start,
    .map_start = (uint64_t) tst_live_map_start,
    .map_end = (uint64_t)tst_live_map_end
  };

  eri_live_signal_thread_init_main (&common_args, &rtld_args);
}
