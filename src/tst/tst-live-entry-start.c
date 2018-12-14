#include "live-entry.h"
#include "rtld.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/printf.h"

uint8_t sigtrap_triggered;

static void
sigtrap_act (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  sigtrap_triggered = 1;

  extern uint8_t tst_exit[];
  eri_assert (ctx->mctx.rip == (uint64_t) tst_exit);
  eri_assert (ctx->mctx.rax == 0);
  eri_assert (ctx->mctx.rbx == 0);
  eri_assert (ctx->mctx.rcx == 0);
  eri_assert (ctx->mctx.rdx == 0x12345678);
  eri_assert (ctx->mctx.rdi == 0);
  eri_assert (ctx->mctx.rsi == 0);
  eri_assert (*(uint64_t *) ctx->mctx.rsp == 0x12345678);
  eri_assert (*(uint64_t *) (ctx->mctx.rsp + 8) == 0x12345678);
#if 0
  uint64_t i;
  for (i = 1024; i > 0; i -= 8)
    eri_assert (*(uint64_t *) (ctx->mctx.rsp - i) == 0);
#endif
  eri_assert (ctx->mctx.rbp == 0);
  eri_assert (ctx->mctx.r8 == 0);
  eri_assert (ctx->mctx.r9 == 0);
  eri_assert (ctx->mctx.r10 == 0);
  eri_assert (ctx->mctx.r11 == 0);
  eri_assert (ctx->mctx.r12 == 0);
  eri_assert (ctx->mctx.r13 == 0);
  eri_assert (ctx->mctx.r14 == 0);
  eri_assert (ctx->mctx.r15 == 0);
  eri_assert (ctx->mctx.rflags == (0x203 | ERI_TRACE_FLAG_MASK));

  ctx->mctx.rflags = 0;
}

void
eri_live_start_sigaction (int32_t sig,
			  struct eri_live_entry_sigaction_info *info,
			  void *thread)
{
  info->rip = (uint64_t) sigtrap_act;
  info->mask_all = 0;
  eri_sigemptyset (&info->mask);
}

static struct eri_live_thread_entry entry;
static uint8_t stack[2 * 1024 * 1024];
static uint8_t sig_stack[ERI_LIVE_SIG_STACK_SIZE];

void
tst_rtld (uint64_t rsp, uint64_t rdx, uint64_t rip)
{
  eri_assert_printf ("rsp = %lx\n", rsp);

  struct eri_rtld rtld = { rdx, rsp - 8, rip };
  struct eri_sigset set;
  eri_sigfillset (&set);
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK, &set,
		      &rtld.sig_mask, ERI_SIG_SETSIZE);

  eri_live_init_thread_entry (&entry, 0, (uint64_t) stack + sizeof stack,
			      sizeof stack, sig_stack);

  struct eri_stack st = { sig_stack, 0, ERI_LIVE_SIG_STACK_SIZE };
  ERI_ASSERT_SYSCALL (sigaltstack, &st, 0);

  struct eri_sigaction sa = {
    eri_live_sigaction, ERI_SA_RESTORER | ERI_SA_SIGINFO | ERI_SA_ONSTACK,
    eri_sigreturn
  };
  eri_sigfillset (&sa.mask);
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  eri_live_entry_start (&entry, &rtld);
}
