#include "tst/tst-live-entry-common.h"

#include "lib/tst/tst-util.h"

#include "lib/lock.h"
#include "lib/syscall.h"
#include "lib/printf.h"

#include "live-entry.h"

static int32_t pid;
static int32_t tid;

static int32_t printf_lock;
static int32_t lock;

static uint8_t triggered;

static void
tst_child (void *data)
{
  eri_lock (&lock);
  while (! triggered)
    {
      TST_YIELD (32);
      eri_assert_lprintf (&printf_lock, "[tst_child] tgkill\n");
      ERI_ASSERT_SYSCALL (tgkill, pid, tid, ERI_SIGRTMIN);
      eri_lock (&lock);
    }

  eri_assert (triggered == 1);
  TST_YIELD (32);

  eri_assert_lprintf (&printf_lock, "[tst_child] tgkill again\n");
  ERI_ASSERT_SYSCALL (tgkill, pid, tid, ERI_SIGRTMIN);
  eri_lock (&lock);
  eri_assert (triggered == 2);
}

void
eri_live_get_sig_action (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *ctx, int32_t intr,
			 struct eri_live_entry_sig_action_info *act_info,
			 void *thread)
{
  eri_assert (act_info->type == ERI_LIVE_ENTRY_SIG_ACTION_UNKNOWN);

  eri_assert_lprintf (&printf_lock,
		      "[eri_live_get_sig_action] intr = %x\n", intr);

  act_info->type = ERI_LIVE_ENTRY_SIG_NO_ACTION;

  if (intr == __NR_poll)
    {
      eri_assert (++triggered == 1);
      eri_assert (ctx->mctx.rax == -ERI_EINTR);
      ctx->mctx.rax = __NR_restart_syscall;
      ctx->mctx.rip -= 2;
    }
  else if (intr == __NR_restart_syscall)
    {
      eri_assert (++triggered == 2);
      eri_assert (ctx->mctx.rax == -ERI_EINTR);
    }
  else eri_assert (intr == -1);

  eri_unlock (&lock);
}

void
eri_live_start_sig_action (int32_t sig, struct eri_stack *stack,
			   struct eri_live_entry_sig_action_info *info,
			   void *entry)
{
  info->rip = 0;
}

int8_t
eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
		  uint64_t a3, uint64_t a4, uint64_t a5,
		  uint64_t *rax, void *entry)
{
  return eri_live_entry_do_syscall (a0, a1, a2, a3, a4, a5,
				    rax, entry);
}

static uint8_t stack[1024 * 1024];
static uint8_t sig_stack[ERI_LIVE_SIG_STACK_SIZE];
static struct eri_live_thread_entry *entry;

static uint8_t child_stack[1024 * 1024];
static int32_t clear_tid;

uint64_t tst_poll (void);

uint64_t
tst_main (void)
{
  pid = ERI_ASSERT_SYSCALL_RES (getpid);
  tid = ERI_ASSERT_SYSCALL_RES (gettid);

  struct tst_rand rand;
  tst_rand_seed (&rand, pid);

  uint8_t entry_buf[ERI_LIVE_THREAD_ENTRY_SIZE];
  entry = tst_init_start_live_thread_entry (
			&rand, entry_buf, stack, sizeof stack, sig_stack);

  struct eri_sigaction sa = {
    eri_live_entry_sig_action,
    ERI_SA_RESTORER | ERI_SA_SIGINFO | ERI_SA_ONSTACK, eri_sigreturn
  };
  eri_sigfillset (&sa.mask);
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGRTMIN, &sa, 0, ERI_SIG_SETSIZE);

  tst_create_thread (child_stack + sizeof child_stack, &clear_tid,
		     tst_child, 0);

  eri_assert (tst_poll () == -ERI_EINTR);
  eri_assert (triggered == 2);

  eri_lock (&clear_tid);
  return 0;
}
