#include <lib/compiler.h>
#include <lib/elf.h>
#include <lib/syscall.h>

#include <live/rtld.h>
#include <live/signal-thread.h>

static eri_aligned16 uint8_t stack[8 * 1024 * 1024];

eri_noreturn void tst_live_start (void);

eri_noreturn void
tst_main (void **args)
{
  eri_sigset_t mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  void *top = stack + sizeof stack - 8;
  *(void **) top = args;

  extern uint8_t tst_main_map_start[];
  extern uint8_t tst_main_map_end[];
  extern uint8_t tst_main_buf_start[];
  extern uint8_t tst_main_buf_end[];

  struct eri_live_rtld_args rtld_args = {
    0, (uint64_t) top, (uint64_t) tst_live_start,
    .map_start = (uint64_t) tst_main_map_start,
    .map_end = (uint64_t) tst_main_map_end,
    .buf = (uint64_t) tst_main_buf_start,
    .buf_size = tst_main_buf_end - tst_main_buf_start,
    .envp = eri_get_envp_from_args (args)
  };

  eri_live_signal_thread__init_main (&rtld_args);
}
