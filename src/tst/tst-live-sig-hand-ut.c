#include <compiler.h>

#include <rtld.h>
#include <lib/malloc.h>
#include <lib/syscall.h>

#include <tst/live-sig-hand-ut.h>
#include <tst/tst-live-sig-hand-ut.h>

#include <tst/tst-syscall.h>

static aligned16 uint8_t buf[256 * 1024 * 1024];
static struct eri_live_signal_thread sig_th;

static aligned16 uint8_t stack[8 * 1024 * 1024];

uint32_t
tst_main (void)
{
  eri_assert_init_pool (&sig_th.pool.pool, buf, sizeof (buf));
  sig_th.args.buf = (uint64_t) buf;
  sig_th.args.buf_size = sizeof buf;
  sig_th.args.stack_size = 8 * 1024 * 1024;

  sig_th.pid = eri_assert_syscall (getpid);
  sig_th.tid = eri_assert_syscall (gettid);

  extern uint8_t tst_live_map_start[];
  extern uint8_t tst_live_map_end[];

  struct eri_rtld_args rtld_args = {
    .rsp = (uint64_t) tst_clone_top (stack),
    .rip = (uint64_t) tst_live_sig_hand_start,
    .map_start = (uint64_t) tst_live_map_start,
    .map_end = (uint64_t) tst_live_map_end
  };

  *(void **) rtld_args.rsp = &sig_th;

  struct eri_sigaction act = {
    tst_live_sig_hand_step,
    ERI_SA_SIGINFO | ERI_SA_ONSTACK | ERI_SA_RESTORER,
    eri_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  eri_assert_sys_sigaction (ERI_SIGTRAP, &act, 0);

  sig_th.th = eri_live_thread__create_main (&sig_th, &rtld_args);
  eri_live_thread__clone_main (sig_th.th);
  eri_live_thread__join (sig_th.th);
  eri_live_thread__destroy (sig_th.th, 0);

  eri_assert_fini_pool (&sig_th.pool.pool);
  return 0;
}
