#include <stdint.h>

#include <compiler.h>

#include <live-signal-thread.h>
#include <rtld.h>
#include <common.h>

static uint8_t buf[32 * 1024 * 1024];
static uint8_t stack[8 * 1024 * 1024];

noreturn void tst_main (void);
noreturn void tst_live_start (void);

noreturn void
tst_main (void)
{
  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  struct eri_common_args args = {
    0, 4096, 0, sizeof buf, 8 * 1024 * 1024, 0, (uint64_t) buf
  };

  struct eri_rtld_args rtld_args = {
    0, 0, (uint64_t) stack + sizeof stack - 8, (uint64_t) tst_live_start, 
  };

  eri_live_signal_thread_init_main (&args, &rtld_args);
}
