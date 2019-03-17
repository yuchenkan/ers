#include <compiler.h>
#include <common.h>

#include <helper.h>

#include <lib/lock.h>
#include <lib/syscall-common.h>
#include <lib/malloc.h>

struct eri_helper
{
  struct eri_mtpool *pool;

  int32_t pid;
  int32_t alive;

  int32_t event_pipe[2];
  eri_sig_handler_t hand;

  eri_aligned16 uint8_t stack[0];
};

struct event
{
  void (*fn) (void *);
  void *args;
  eri_sig_handler_t hand;
};

static eri_noreturn void
start (struct eri_helper *helper, uint64_t stack_size, int32_t ppid)
{
  eri_debug ("pid = %u, ppid = %u\n", helper->pid, ppid);
  if (ppid)
    {
      eri_assert_syscall (prctl, ERI_PR_SET_PDEATHSIG, ERI_SIGKILL);
      eri_assert (eri_assert_syscall (getppid) == ppid);
    }

  struct eri_stack stack = { (uint64_t) helper->stack, 0, stack_size };
  eri_assert_syscall (sigaltstack, &stack, 0);

  while (1)
    {
      struct event *event;
      eri_assert_syscall (read, helper->event_pipe[0],
			  &event, sizeof event);

      if (! event) break;

      void (*fn) (void *) = event->fn;
      void *args = event->args;
      eri_sig_handler_t hand = event->hand;
      eri_assert_mtfree (helper->pool, event);

      helper->hand = hand;
      fn (args);
      helper->hand = 0;
    }
  eri_debug ("exit\n");
  eri_assert_syscall (exit, 0);
  eri_assert_unreachable ();
}

struct eri_helper *
eri_helper__start (struct eri_mtpool *pool,
		   uint64_t stack_size, uint8_t selector, int32_t pid)
{
  eri_debug ("\n");
  struct eri_helper *helper
	= eri_assert_mtmalloc (pool, sizeof *helper + stack_size);
  helper->pool = pool;
  helper->alive = 1;

  eri_assert_syscall (pipe2, helper->event_pipe, ERI_O_DIRECT);
  helper->hand = 0;

  *(uint64_t *) helper->stack = (uint64_t) helper | selector;

  struct eri_sys_clone_args args = {
    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | (!! pid ? ERI_SIGCHLD : ERI_CLONE_THREAD),
    helper->stack + stack_size - 8,
    &helper->pid, &helper->alive, 0, start, helper,
    (void *) stack_size, (void *) (uint64_t) pid
  };
  eri_assert_sys_clone (&args);
  return helper;
}

void
eri_helper__exit (struct eri_helper *helper)
{
  struct event *event = 0;
  eri_assert_syscall (write, helper->event_pipe[1], &event, sizeof event);

  eri_assert_sys_futex_wait (&helper->alive, 1, 0);
  eri_assert_syscall (close, helper->event_pipe[0]);
  eri_assert_syscall (close, helper->event_pipe[1]);
  eri_assert_mtfree (helper->pool, helper);
}

void
eri_helper__invoke (struct eri_helper *helper, void (*fn) (void *),
		    void *args, eri_sig_handler_t hand)
{
  struct event *event = eri_assert_mtmalloc (helper->pool, sizeof *event);
  event->fn = fn;
  event->args = args;
  event->hand = hand;
  eri_assert_syscall (write, helper->event_pipe[1], &event, sizeof event);
}

static void
sig_unmask (void *args)
{
  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);
}

void
eri_helper__sig_unmask (struct eri_helper *helper)
{
  eri_helper__invoke (helper, sig_unmask, 0, 0);
}

uint8_t
eri_helper__select_sig_handler (uint8_t selector,
		struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  uint64_t s = *(uint64_t *) ctx->stack.sp;
  if (! (s & selector)) return 0;
  struct eri_helper *helper = (void *) (s & ~selector);

  if (! helper->hand) eri_assert (! eri_si_sync (info));
  else helper->hand (info->sig, info, ctx);
  return 1;
}

int32_t
eri_helper__get_pid (const struct eri_helper *helper)
{
  return helper->pid;
}
