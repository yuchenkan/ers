#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "live.h"
#include "live-entry.h"
#include "common.h"

#include "lib/rbtree.h"
#include "lib/lock.h"
#include "lib/printf.h"
#include "lib/syscall.h"
#include "lib/malloc.h"

uint8_t tst_live_quit_allow_clone;
int32_t tst_live_quit_allow_group;

int32_t tst_live_quit_printf_lock;

void
tst_live_quit_set_thread (struct eri_live_thread_entry *entry)
{
  eri_assert_lprintf (&tst_live_quit_printf_lock,
		      "tid = %lu\n", ERI_ASSERT_SYSCALL_RES (gettid));
  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_FS, entry);
}

static void *
get_thread (void)
{
  void *thread;
  asm ("movq	%%fs:%c1, %q0"
       : "=r" (thread)
       : "i" (__builtin_offsetof (struct eri_live_thread_entry, thread)));
  return thread;
}

void
eri_live_init_thread_entry (struct eri_live_thread_entry *entry,
		void *thread, uint64_t stack_top, uint64_t stack_size,
		void *sig_stack)
{
  entry->top = stack_top;
  entry->stack_size = stack_size;
  entry->stack_size = stack_size;

  entry->thread = thread;
}

void
tst_live_quit_block_signals (uint8_t allow_quit)
{
  struct eri_sigset set;
  eri_sigfillset (&set);
  if (allow_quit)
    {
      eri_sigdelset (&set, ERI_SIGRTMIN);
      eri_sigdelset (&set, tst_live_quit_allow_group);
    }
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK,
		      &set, 0, ERI_SIG_SETSIZE);
}

void
eri_live_entry_sig_action (int32_t sig, struct eri_siginfo *info,
			   struct eri_ucontext *ctx)
{
  eri_assert (tst_live_quit_allow_group);

  void *thread = get_thread ();

  struct eri_live_entry_sig_action_info act_info = {
    ERI_LIVE_ENTRY_SIG_ACTION_UNKNOWN
  };
  eri_live_get_sig_action (sig, info, ctx, -1, &act_info, thread);

  eri_assert (act_info.type == ERI_LIVE_ENTRY_SIG_ACTION_INTERNAL);

  void (*act) (int32_t, struct eri_siginfo *, struct eri_ucontext *, void *)
	= (void *) act_info.act;
  act (sig, info, ctx, thread);

  eri_assert (0);
}

void tst_live_quit_init (uint64_t rsp) __attribute__ ((noreturn));

void
tst_live_quit_init (uint64_t rsp)
{
  eri_assert_printf ("rsp = %lx\n", rsp);

#define BUF_SIZE (64 * 1024 * 1024)
  static struct eri_common common = {
    0, 4096, 0, BUF_SIZE, 1024 * 1024, 32 * 1024
  };
  common.buf = (uint64_t) ERI_ASSERT_SYSCALL_RES (
			mmap, 0, BUF_SIZE, ERI_PROT_READ | ERI_PROT_WRITE,
			ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);

  struct eri_rtld rtld = { 0, rsp - 8 };

  tst_live_quit_block_signals (0);

  eri_live_init (&common, &rtld);
}

uint8_t
tst_live_quit_sig_pending (void)
{
  struct eri_sigset set;
  ERI_ASSERT_SYSCALL (rt_sigpending, &set, ERI_SIG_SETSIZE);
  return ! eri_sigset_empty (&set);
}

void
tst_live_quit_clone (uint8_t *stack, int32_t *ptid, int32_t *ctid,
		     void (*fn) (void *), void *data)
{
  *(uint64_t *) stack = (uint64_t) fn;
  *(uint64_t *) (stack + 8) = (uint64_t) data;

  uint64_t rax = __NR_clone;
  int8_t done = 0;
  while (done != 1)
    {
      tst_live_quit_block_signals (0);
      done = eri_live_syscall (ERI_SUPPORTED_CLONE_FLAGS,
		(uint64_t) stack + TST_LIVE_QUIT_STACK_SIZE,
		(uint64_t) ptid, (uint64_t) ctid, 0, 0,
		&rax, get_thread ());
      eri_assert_lprintf (&tst_live_quit_printf_lock, "done = %x\n", done);
      tst_live_quit_block_signals (1);
    }
}

void
tst_live_quit_clone_child (struct tst_live_quit_child *child,
			   void (*fn) (void *), void *data)
{
  tst_live_quit_clone (child->stack, &child->ptid, &child->ctid, fn, data);
}

uint8_t eri_tst_live_multi_threading (void *thread);

uint8_t
tst_live_quit_multi_threading (void)
{
  return eri_tst_live_multi_threading (get_thread ());
}

static void do_exit (int32_t nr, int32_t status) __attribute__ ((noreturn));

static void
do_exit (int32_t nr, int32_t status)
{
  uint64_t rax = nr;
  while (1)
    {
      tst_live_quit_block_signals (0);
      eri_assert (eri_live_syscall (status, 0, 0, 0, 0, 0, &rax,
				    get_thread ()) != 0);
      tst_live_quit_block_signals (1);
    }
}

void
tst_live_quit_exit (int32_t status)
{
  do_exit (__NR_exit, status);
}

void
tst_live_quit_exit_group (int32_t status)
{
  do_exit (__NR_exit_group, status);
}
