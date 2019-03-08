#include <common.h>
#include <helper.h>

#include <lib/util.h>
#include <lib/lock.h>
#include <lib/atomic.h>
#include <lib/malloc.h>
#include <lib/syscall.h>

#include <live/rtld.h>
#include <live/thread.h>
#include <live/signal-thread.h>
#include <live/signal-thread-local.h>

struct sig_act
{
  struct eri_lock lock;
  struct eri_sigaction act;
};

struct watch
{
  int32_t alive;
  uint8_t stack[4096];
};

struct signal_thread_group
{
  struct eri_mtpool *pool;

  struct eri_common_args args;

  int32_t pid;

  struct sig_act sig_acts[ERI_NSIG - 1];
  struct eri_siginfo sig_sync_info;
  struct eri_siginfo sig_exit_group_info;

  uint8_t exit_group;
  int32_t exit_group_lock;

  uint32_t thread_count;
  struct eri_lock thread_lock;
  ERI_LST_LIST_FIELDS (thread)

  struct watch watch;
  struct eri_helper *helper;
};

ERI_DEFINE_LIST (static, thread, struct signal_thread_group,
		 struct eri_live_signal_thread)

#define SIG_EXIT_GROUP	ERI_SIGRTMIN
#define SIG_SIGNAL	(ERI_SIGRTMIN + 1)

static uint8_t
thread_sig_filter (struct signal_thread_group *group,
		   const struct eri_siginfo *info)
{
  eri_assert (! eri_si_sync (info));

  if (eri_si_from_kernel (info))
    {
      if (info->sig == ERI_SIGXCPU)
	eri_assert_syscall (kill, group->pid, ERI_SIGXCPU);

      return 0;
    }

  return info->code == ERI_SI_TKILL && info->kill.pid == group->pid;
}

static void
thread_sig_handler (struct eri_live_signal_thread *sig_th,
		    struct eri_sigframe *frame)
{
  struct eri_live_thread *th = sig_th->th;
  struct eri_siginfo *info = &frame->info;

  if (! eri_si_single_step (info) && eri_si_sync (info))
    eri_debug ("sig = %u, frame = %lx, rip = %lx\n",
	       info->sig, frame, frame->ctx.mctx.rip);

  if (eri_si_sync (info))
    {
      eri_live_thread__sig_handler (th, frame, 0);
      return;
    }

  if (! thread_sig_filter (sig_th->group, info)) return;

  *info = *sig_th->sig_info;
  eri_debug ("sig = %u, frame = %lx, rip = %lx\n",
	     info->sig, frame, frame->ctx.mctx.rip);
  eri_live_thread__sig_handler (th, frame, &sig_th->sig_act);
}

static void
sig_get_act (struct signal_thread_group *group, int32_t sig,
	     struct eri_sigaction *act)
{
  struct sig_act *sig_act = &group->sig_acts[sig - 1];
  eri_assert_lock (&sig_act->lock);
  *act = sig_act->act;
  eri_assert_unlock (&sig_act->lock);
}

void
sig_handler_frame (struct eri_sigframe *frame)
{
  struct eri_ucontext *ctx = &frame->ctx;

  struct eri_live_signal_thread *sig_th = *(void **) ctx->stack.sp;
  if (sig_th->sig_stack != (void *) ctx->stack.sp)
    {
      thread_sig_handler (sig_th, frame);
      return;
    }

  struct eri_live_thread *th = sig_th->th;
  struct eri_siginfo *info = &frame->info;

  eri_assert (! eri_si_sync (info));

  int32_t th_pid = eri_live_thread__get_pid (th);
  int32_t th_tid = eri_live_thread__get_tid (th);

  if (info->sig == ERI_SIGCHLD && eri_si_from_kernel (info)
      && (info->chld.pid == th_pid
	  || info->chld.pid == eri_helper__get_pid (sig_th->group->helper)))
    return;

  /* From sig_route_xcpu.  */
  if (info->code == ERI_SI_USER && info->kill.pid == th_pid)
    {
      eri_assert (info->sig == ERI_SIGXCPU);

      info->code = ERI_SI_KERNEL;
      info->kill.pid = 0;
      info->kill.uid = 0;
    }

  sig_get_act (sig_th->group, info->sig, &sig_th->sig_act);

  if (! eri_live_thread__sig_digest_act (th, info, &sig_th->sig_act))
    return;

  eri_debug ("sig = %u, frame = %lx, code = %u\n",
             info->sig, frame, info->code);
  sig_th->sig_info = info;
  eri_assert_syscall (tgkill, th_pid, th_tid, SIG_SIGNAL);

  if (sig_th->event_sig_restart
      && ctx->mctx.rip != sig_th->event_sig_reset_restart)
    ctx->mctx.rip = sig_th->event_sig_restart;

  eri_debug ("\n");
  eri_sig_fill_set (&ctx->sig_mask);
}

static struct signal_thread_group *
init_group_memory (struct eri_live_rtld_args *rtld_args)
{
  /* XXX: parameterize */
  const char *config = "ers_config";
  const char *path = "ers_data";
  uint64_t stack_size = 2 * 1024 * 1024;
  uint64_t file_buf_size = 64 * 1024;

  eri_assert_syscall (mmap, rtld_args->buf, rtld_args->buf_size,
		/* XXX: security */
		ERI_PROT_READ | ERI_PROT_WRITE | ERI_PROT_EXEC,
		ERI_MAP_FIXED | ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);

  struct eri_mtpool *pool = (void *) rtld_args->buf;
  eri_assert_init_mtpool (pool,
			  (void *) (rtld_args->buf + eri_size_of (*pool, 16)),
			  rtld_args->buf_size - eri_size_of (*pool, 16));

  struct signal_thread_group *group
	= eri_assert_malloc (&pool->pool, sizeof *group);

  group->pool = pool;

  group->args.config = config;
  group->args.path = path;

  group->args.page_size = rtld_args->page_size;
  group->args.stack_size = stack_size;
  group->args.file_buf_size = file_buf_size;

  return group;
}

static void
init_group_signal (struct signal_thread_group *group)
{
  int32_t sig;
  for (sig = 1; sig < ERI_NSIG; ++sig)
    {
      if (sig == ERI_SIGSTOP || sig == ERI_SIGKILL) continue;

      eri_init_lock (&group->sig_acts[sig - 1].lock, 0);
      struct eri_sigaction act = {
	sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK,
	eri_assert_sys_sigreturn
      };
      eri_sig_fill_set (&act.mask);
      eri_assert_sys_sigaction (sig, &act, &group->sig_acts[sig - 1].act);
    }
  group->sig_sync_info.sig = 0;
  group->sig_exit_group_info.sig = ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP;
}

static void
set_sig_mask (struct eri_live_signal_thread *sig_th,
	      const struct eri_sigset *mask)
{
  struct eri_sigset set = *mask;
  eri_sig_del_set (&set, ERI_SIGKILL);
  eri_sig_del_set (&set, ERI_SIGSTOP);
  sig_th->sig_mask = set;
}

static void
init_event (struct eri_live_signal_thread *sig_th, struct eri_sigset *mask)
{
  set_sig_mask (sig_th, mask);
  sig_th->sig_info = 0;
  sig_th->event_sig_restart = 0;

  eri_assert_syscall (pipe2, sig_th->event_pipe, ERI_O_DIRECT);
}

static void
fini_event (struct eri_live_signal_thread *sig_th)
{
  eri_assert_syscall (close, sig_th->event_pipe[0]);
  eri_assert_syscall (close, sig_th->event_pipe[1]);
}

static struct eri_live_signal_thread *
create (struct signal_thread_group *group)
{
  struct eri_live_signal_thread *sig_th
	= eri_assert_mtmalloc (group->pool, sizeof *sig_th);
  sig_th->group = group;
  sig_th->alive = 1;
  return sig_th;
}

static struct eri_live_signal_thread *
init_main (struct signal_thread_group *group,
	   struct eri_live_rtld_args *rtld_args)
{
  struct eri_live_signal_thread *sig_th = create (group);

  init_event (sig_th, &rtld_args->sig_mask);

  sig_th->th = eri_live_thread__create_main (sig_th, rtld_args);

  eri_debug ("sig_th %lx\n", sig_th);
  eri_assert_syscall (set_tid_address, &sig_th->alive);
  sig_th->tid = eri_assert_syscall (gettid);

  thread_lst_append (group, sig_th);
  return sig_th;
}

struct eri_live_signal_thread *
init_group (struct eri_live_rtld_args *rtld_args)
{
  struct signal_thread_group *group = init_group_memory (rtld_args);

  group->pid = eri_assert_syscall (getpid);

  init_group_signal (group);

  group->exit_group = 0;
  group->exit_group_lock = 0;

  group->thread_count = 1;
  eri_init_lock (&group->thread_lock, 0);
  ERI_LST_INIT_LIST (thread, group);

  return init_main (group, rtld_args);
}

void
eri_live_signal_thread__init_thread_sig_stack (
		struct eri_live_signal_thread *sig_th,
		uint8_t *stack, uint64_t stack_size)
{
  struct eri_stack st = { (uint64_t) stack, 0, stack_size };
  eri_assert_syscall (sigaltstack, &st, 0);

  *(void **) stack = sig_th;
}

static void
init_sig_stack (struct eri_live_signal_thread *sig_th)
{
  eri_live_signal_thread__init_thread_sig_stack (
	sig_th, sig_th->sig_stack, SIGNAL_THREAD_SIG_STACK_SIZE);
}

static eri_noreturn void event_loop (struct eri_live_signal_thread *sig_th);

static void
restore_sig_mask (struct eri_live_signal_thread *sig_th)
{
  eri_assert_sys_sigprocmask (&sig_th->sig_mask, 0);
}

static eri_noreturn void start_watch (
		struct eri_live_signal_thread *sig_th, struct eri_lock *lock);

static eri_noreturn void
start_watch (struct eri_live_signal_thread *sig_th, struct eri_lock *lock)
{
  eri_debug ("\n");

  struct signal_thread_group *group = sig_th->group;
  group->helper = eri_helper__start (group->pool, 256 * 1024, group->pid);
  int32_t pgid = eri_helper__get_pid (group->helper);
  eri_assert_syscall (setpgid, pgid, 0);

  eri_live_thread__clone_main (sig_th->th);
  int32_t th_pid = eri_live_thread__get_pid (sig_th->th);
  eri_assert_syscall (setpgid, th_pid, pgid);
  eri_assert_unlock (lock);

  struct eri_siginfo info;
  uint8_t i;
  for (i = 0; i < 2; ++i)
    {
      eri_debug ("watch wait\n");
      eri_assert_syscall (waitid, ERI_P_PGID, pgid, &info, ERI_WEXITED, 0);
      eri_assert ((info.chld.pid == th_pid || info.chld.pid == pgid)
		  && info.chld.status == 0);
    }
  eri_debug ("leave watch\n");
  eri_assert_sys_exit (0);
}

static void
watch (struct eri_live_signal_thread *sig_th)
{
  struct eri_lock lock = ERI_INIT_LOCK (1);
  struct watch *watch = &sig_th->group->watch;
  watch->alive = 1;
  struct eri_sys_clone_args args = {

    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_THREAD | ERI_CLONE_CHILD_CLEARTID,

    (void *) ((uint64_t) watch->stack + sizeof watch->stack - 8),
    0, &watch->alive, 0, start_watch, sig_th, &lock
  };

  eri_assert_sys_clone (&args);
  eri_assert_lock (&lock);
}

void
start_group (struct eri_live_signal_thread *sig_th)
{
  eri_debug ("\n");

  watch (sig_th);

  init_sig_stack (sig_th);

  restore_sig_mask (sig_th);

  event_loop (sig_th);
}

static uint8_t
try_hold_exit_group (int32_t *lock)
{
  uint8_t hold = eri_atomic_inc_fetch (lock) > 0;
  if (! hold) eri_atomic_dec (lock);
  eri_barrier ();
  return hold;
}

static void
unhold_exit_group (int32_t *lock)
{
  eri_barrier ();
  eri_atomic_dec (lock);
}

static uint8_t
try_lock_exit_group (struct signal_thread_group *group)
{
  if (eri_atomic_exchange (&group->exit_group, 1) == 1) return 0;

  while (! eri_atomic_compare_exchange (&group->exit_group_lock,
					0, -2147483647))
    eri_assert_syscall (sched_yield);

  eri_barrier ();
  return 1;
}

static void
append_to_group (struct eri_live_signal_thread *sig_th)
{
  struct signal_thread_group *group = sig_th->group;
  eri_assert_lock (&group->thread_lock);
  thread_lst_append (group, sig_th);
  eri_assert_unlock (&group->thread_lock);
}

static void
remove_from_group (struct eri_live_signal_thread *sig_th)
{
  struct signal_thread_group *group = sig_th->group;
  eri_assert_lock (&group->thread_lock);
  thread_lst_remove (group, sig_th);
  eri_assert_unlock (&group->thread_lock);
}

struct event_type
{
  uint32_t type;
  struct eri_lock lock;
};

#define INIT_EVENT_TYPE(type)	{ type, ERI_INIT_LOCK (1) }

static void
release_event (void *event)
{
  eri_assert_unlock (&((struct event_type *) event)->lock);
}

static void
wait_event (struct event_type *event)
{
  eri_assert_lock (&event->lock);
}

static void
queue_event (struct eri_live_signal_thread *sig_th, void *event)
{
  eri_assert_syscall (write, sig_th->event_pipe[1], &event, sizeof event);
}

static void
proc_event (struct eri_live_signal_thread *sig_th, void *event)
{
  queue_event (sig_th, event);
  wait_event (event);
}

#define CLONE_EVENT			1
#define EXIT_EVENT			2
#define DIE_EVENT			3
#define SIG_ACTION_EVENT		4
#define SIG_MASK_ASYNC_EVENT		5
#define SIG_TMP_MASK_ASYNC_EVENT	6
#define SIG_MASK_ALL_EVENT		7
#define SIG_RESET_EVENT			8
#define SIG_RESTORE_MASK_EVENT		9
#define SIG_FD_EVENT			10
#define SIG_FD_READ_EVENT		11
#define SYSCALL_EVENT			12

#define SIG_EXIT_GROUP_EVENT		32

struct clone_event;
static void clone (struct eri_live_signal_thread *sig_th,
		   struct clone_event *event);

struct exit_event;
static void exit (struct eri_live_signal_thread *sig_th,
		  struct exit_event *event);

struct sig_action_event;
static void sig_action (struct eri_live_signal_thread *sig_th,
			struct sig_action_event *event);

struct sig_mask_event
{
  struct event_type type;
  const struct eri_sigset *mask;

  uint8_t done;
};

static uint8_t
sig_mask_all_async (struct eri_live_signal_thread *sig_th)
{
  struct eri_sigset mask;
  eri_sig_fill_set (&mask);

  return sig_mask_async (sig_th, &mask);
}

static uint8_t
sig_mask_all (struct eri_live_signal_thread *sig_th,
	      struct eri_siginfo *info)
{
  if (sig_th->sig_info || ! sig_mask_all_async (sig_th)) return 0;
  sig_th->sig_info = info;
  return 1;
}

static void signal_exit_group (struct eri_live_signal_thread *sig_th);

struct sig_fd_read_event;
static void sig_fd_read (struct eri_live_signal_thread *sig_th,
			 struct sig_fd_read_event *event);

struct syscall_event
{
  struct event_type type;
  struct eri_sys_syscall_args *args;
};

static eri_noreturn void
event_loop (struct eri_live_signal_thread *sig_th)
{
  eri_debug ("\n");
  struct signal_thread_group *group = sig_th->group;

  uint8_t pending_exit_group = 0;
  while (1)
    {
      void *event_type;
      uint64_t res = eri_syscall (read, sig_th->event_pipe[0],
				  &event_type, sizeof event_type);
      if (res == ERI_EINTR) continue;
      eri_assert (! eri_syscall_is_error (res));

      uint32_t type = ((struct event_type *) event_type)->type;
      eri_debug ("%u\n", type);
      if (type == CLONE_EVENT)
	clone (sig_th, event_type);
      else if (type == EXIT_EVENT)
	exit (sig_th, event_type);
      else if (type == DIE_EVENT)
	{
	  eri_live_thread__join (sig_th->th);
	  eri_assert_sys_thread_die (&sig_th->alive);
	}
      else if (type == SIG_ACTION_EVENT)
	sig_action (sig_th, event_type);
      else if (type == SIG_MASK_ASYNC_EVENT)
	{
	  struct sig_mask_event *event = event_type;
	  if ((event->done = sig_mask_async (sig_th, event->mask)))
	    set_sig_mask (sig_th, event->mask);
	}
      else if (type == SIG_TMP_MASK_ASYNC_EVENT)
	{
	  struct sig_mask_event *event = event_type;
	  event->done = sig_mask_async (sig_th, event->mask);
	}
      else if (type == SIG_MASK_ALL_EVENT)
	{
	  struct sig_mask_event *event = event_type;
	  event->done = sig_mask_all (sig_th, &group->sig_sync_info);
	}
      else if (type == SIG_RESET_EVENT)
	{
	  eri_assert (sig_th->sig_info);
	  struct sig_mask_event *event = event_type;

	  if (pending_exit_group)
	    {
	      release_event (event_type);
	      sig_th->sig_info = &group->sig_exit_group_info;
	      signal_exit_group (sig_th);
	    }
	  else
	    {
	      sig_th->sig_info = 0;
	      if (event->mask) set_sig_mask (sig_th, event->mask);
	      release_event (event_type);
	      restore_sig_mask (sig_th);
	    }
	}
      else if (type == SIG_FD_READ_EVENT)
	sig_fd_read (sig_th, event_type);
      else if (type == SYSCALL_EVENT)
	{
	  struct syscall_event *event = event_type;
	  eri_sys_syscall (event->args);
	}
      else if (type == SIG_EXIT_GROUP_EVENT)
	{
	  if (sig_mask_all (sig_th, &group->sig_exit_group_info))
	    signal_exit_group (sig_th);
	  else pending_exit_group = 1;
	}
      else eri_assert (0);

      if (type != CLONE_EVENT && type != SIG_RESET_EVENT)
	release_event (event_type);
    }
}

struct clone_event {
  struct event_type type;
  struct eri_live_signal_thread__clone_args *args;

  struct eri_lock clone_thread_return;
  struct eri_lock clone_start_call;
  struct eri_lock clone_start_return;
  struct eri_lock clone_done;

  struct eri_live_signal_thread *sig_cth;
};

static eri_noreturn void start (struct eri_live_signal_thread *sig_th,
				struct clone_event *event);

static eri_noreturn void
start (struct eri_live_signal_thread *sig_th, struct clone_event *event)
{
  eri_debug ("\n");

  init_sig_stack (sig_th);

  eri_assert_lock (&event->clone_start_call);
  if (eri_syscall_is_error (event->args->result))
    {
      eri_assert_syscall (set_tid_address, &event->clone_start_return.lock);
      eri_assert_sys_exit (0);
    }

  restore_sig_mask (sig_th);
  eri_assert_unlock (&event->clone_start_return);

  append_to_group (sig_th);
  unhold_exit_group (&sig_th->group->exit_group_lock);

  event_loop (sig_th);
}

static void
clone (struct eri_live_signal_thread *sig_th, struct clone_event *event)
{
  if (! sig_mask_all_async (sig_th)) goto signaled;

  struct signal_thread_group *group = sig_th->group;

  if (! try_hold_exit_group (&group->exit_group_lock)) goto signaled;

  struct eri_live_signal_thread__clone_args *args = event->args;

  struct eri_live_signal_thread *sig_cth = event->sig_cth = create (group);

  init_event (sig_cth, &sig_th->sig_mask);

  sig_cth->th = eri_live_thread__create (sig_cth, args->args);

  eri_atomic_inc (&group->thread_count);

  struct eri_sys_clone_args sig_cth_args = {
    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_THREAD | ERI_CLONE_PARENT_SETTID
    | ERI_CLONE_CHILD_CLEARTID,
    sig_cth->stack + SIGNAL_THREAD_STACK_SIZE - 8,
    &sig_cth->tid, &sig_cth->alive, 0, start, sig_cth, event
  };

  eri_debug ("clone %lx %lx %lx\n", event, sig_cth, sig_cth_args.stack);
  args->result = eri_sys_clone (&sig_cth_args);
  uint8_t error_sig_clone = eri_syscall_is_error (args->result);

  release_event (event);
  eri_assert_lock (&event->clone_thread_return);

  if (! error_sig_clone)
    {
      eri_assert_unlock (&event->clone_start_call);
      eri_assert_lock (&event->clone_start_return);
    }

  if (eri_syscall_is_error (args->result))
    {
      eri_atomic_dec (&group->thread_count);

      eri_live_thread__destroy (sig_cth->th, 0);

      fini_event (sig_cth);
      eri_assert_mtfree (group->pool, sig_cth);
      unhold_exit_group (&group->exit_group_lock);
    }

  restore_sig_mask (sig_th);
  eri_debug ("clone done %lx %lu\n", event, args->result);
  eri_assert_unlock (&event->clone_done);
  return;

signaled:
  event->args->result = 0;
  release_event (event);
}

uint8_t
eri_live_signal_thread__clone (struct eri_live_signal_thread *sig_th,
			       struct eri_live_signal_thread__clone_args *args)
{
  struct clone_event event = {
    INIT_EVENT_TYPE (CLONE_EVENT), args,
    ERI_INIT_LOCK (1), ERI_INIT_LOCK (1), ERI_INIT_LOCK (1), ERI_INIT_LOCK (1)
  };
  proc_event (sig_th, &event);

  if (args->result == 0) return 0;

  if (! eri_syscall_is_error (args->result))
    {
      args->tid = args->result;
      args->result = eri_live_thread__clone (event.sig_cth->th);
    }

  eri_assert_unlock (&event.clone_thread_return);
  eri_assert_lock (&event.clone_done);

  return 1;
}

struct exit_event
{
  struct event_type type;
  uint8_t group;
  uint64_t status;

  uint8_t done;
};

static void
join (struct eri_live_signal_thread *sig_th)
{
  eri_assert_sys_futex_wait (&sig_th->alive, 1, 0);
}

static void
cleanup (void *args)
{
  struct eri_live_signal_thread *sig_th = args;
  join (sig_th);

  eri_assert_mtfree (sig_th->group->pool, sig_th);
}

static void
inform_exit_group (struct eri_live_signal_thread *sig_th)
{
  struct signal_thread_group *group = sig_th->group;

  struct eri_live_signal_thread *it;
  ERI_LST_FOREACH (thread, group, it)
    if (it != sig_th)
      {
	struct event_type event
		= INIT_EVENT_TYPE (SIG_EXIT_GROUP_EVENT);
	proc_event (it, &event);
      }
}

static void
exit (struct eri_live_signal_thread *sig_th, struct exit_event *event)
{
  if (! sig_mask_all_async (sig_th)) return;

  struct signal_thread_group *group = sig_th->group;
  uint64_t status = event->status;
  struct eri_live_thread *th = sig_th->th;

  if (! event->group
      && eri_atomic_dec_fetch (&group->thread_count))
    {
      if (! try_hold_exit_group (&group->exit_group_lock)) return;

      event->done = 1;
      release_event (event);
      eri_live_thread__join (th);

      eri_live_thread__destroy (th, group->helper);
      remove_from_group (sig_th);

      fini_event (sig_th);
      eri_helper__invoke (group->helper, cleanup, sig_th, 0);

      unhold_exit_group (&group->exit_group_lock);

      eri_debug ("exit %lx\n", sig_th);
      eri_assert_sys_exit (status);
    }

  eri_debug ("exit group %u\n", event->group);

  if (event->group)
    {
      if (! try_lock_exit_group (group)) return;

      inform_exit_group (sig_th);

      struct eri_live_signal_thread *it, *nit;

      eri_debug ("exit thread group\n");
      ERI_LST_FOREACH_SAFE (thread, group, it, nit)
	if (it != sig_th)
	  {
	    join (it);
	    eri_live_thread__destroy (it->th, 0);
	    thread_lst_remove (group, it);
	    eri_assert_mtfree (group->pool, it);
	  }
    }
  else eri_assert (try_lock_exit_group (group));

  eri_debug ("exit last thread\n");

  event->done = 1;
  release_event (event);
  eri_live_thread__join (th);

  eri_live_thread__destroy (th, 0);

  eri_debug ("exit helper\n");
  eri_helper__exit (group->helper);
  eri_assert_sys_futex_wait (&group->watch.alive, 1, 0);

  eri_debug ("destroy\n");

  struct eri_pool *pool = &group->pool->pool;
  eri_preserve (pool);

  eri_assert_free (pool, sig_th);

  eri_assert_free (pool, group);
  eri_assert_fini_pool (pool);

  eri_assert_sys_exit_group (status);
}

uint8_t
eri_live_signal_thread__exit (struct eri_live_signal_thread *sig_th,
			      uint8_t group, uint64_t status)
{
  eri_debug ("status = %lu\n", status);
  struct exit_event event = { INIT_EVENT_TYPE (EXIT_EVENT), group, status };
  proc_event (sig_th, &event);
  return event.done;
}

static void
signal_exit_group (struct eri_live_signal_thread *sig_th)
{
  struct eri_live_thread *th = sig_th->th;
  eri_assert_syscall (tgkill, eri_live_thread__get_pid (th),
		      eri_live_thread__get_tid (th), SIG_EXIT_GROUP);
}

void
eri_live_signal_thread__die (struct eri_live_signal_thread *sig_th)
{
  struct event_type event = INIT_EVENT_TYPE (DIE_EVENT);
  queue_event (sig_th, &event);
}

struct sig_action_event
{
  struct event_type type;

  int32_t sig;
  const struct eri_sigaction *act;
  struct eri_sigaction *old_act;

  uint8_t done;
};

static void
sig_action (struct eri_live_signal_thread *sig_th,
	    struct sig_action_event *event)
{
  struct eri_sigset mask = sig_th->sig_mask;
  eri_sig_add_set (&mask, event->sig);

  if (! sig_mask_async (sig_th, &mask)) return;

  struct sig_act *sig_act = &sig_th->group->sig_acts[event->sig - 1];
  eri_assert_lock (&sig_act->lock);

  if (event->old_act) *event->old_act = sig_act->act;
  sig_act->act = *event->act;

  eri_assert_unlock (&sig_act->lock);

  event->done = 1;
  restore_sig_mask (sig_th);
}

uint8_t
eri_live_signal_thread__sig_action (struct eri_live_signal_thread *sig_th,
				    int32_t sig, const struct eri_sigaction *act,
				    struct eri_sigaction *old_act)
{
  if (! act)
    {
      sig_get_act (sig_th->group, sig, old_act);
      return 1;
    }

  struct sig_action_event event
		= { INIT_EVENT_TYPE (SIG_ACTION_EVENT), sig, act, old_act };
  proc_event (sig_th, &event);
  return event.done;
}

static uint8_t
thread_do_sig_mask (struct eri_live_signal_thread *sig_th,
		    uint32_t type, const struct eri_sigset *mask)
{
  struct sig_mask_event event = { INIT_EVENT_TYPE (type), mask };
  proc_event (sig_th, &event);
  return event.done;
}

uint8_t
eri_live_signal_thread__sig_mask_async (
			struct eri_live_signal_thread *sig_th,
			const struct eri_sigset *mask)
{
  return thread_do_sig_mask (sig_th, SIG_MASK_ASYNC_EVENT, mask);
}

uint8_t
eri_live_signal_thread__sig_tmp_mask_async (
			struct eri_live_signal_thread *sig_th,
			const struct eri_sigset *mask)
{
  return thread_do_sig_mask (sig_th, SIG_TMP_MASK_ASYNC_EVENT, mask);
}

uint8_t
eri_live_signal_thread__sig_mask_all (
			struct eri_live_signal_thread *sig_th)
{
  return thread_do_sig_mask (sig_th, SIG_MASK_ALL_EVENT, 0);
}

void
eri_live_signal_thread__sig_reset (
			struct eri_live_signal_thread *sig_th,
			const struct eri_sigset *mask)
{
  thread_do_sig_mask (sig_th, SIG_RESET_EVENT, mask);
}

void
eri_live_signal_thread__sig_prepare_sync (
			struct eri_live_signal_thread *sig_th,
			struct eri_siginfo *info, struct eri_sigaction *act)
{
  if (eri_live_signal_thread__sig_mask_all (sig_th))
    {
      sig_get_act (sig_th->group, info->sig, act);
      return;
    }

  /* XXX: May lost SIGTRAP here.  */
  struct eri_sigset set;
  eri_sig_fill_set (&set);
  do
    eri_assert_syscall (rt_sigtimedwait, &set, info, 0, ERI_SIG_SETSIZE);
  while (! thread_sig_filter (sig_th->group, info));

  *info = *sig_th->sig_info;
  *act = sig_th->sig_act;
}

struct sig_fd_read_event
{
  struct event_type type;
  struct eri_live_signal_thread__sig_fd_read_args *args;

  uint8_t done;
};

static void
sig_fd_read (struct eri_live_signal_thread *sig_th,
	     struct sig_fd_read_event *event)
{
  struct eri_live_signal_thread__sig_fd_read_args *args = event->args;
  int32_t fd = args->fd;
  int32_t nr = args->nr;
  const uint64_t *a = args->a;
  if (args->flags & ERI_SFD_NONBLOCK)
    {
      event->done = 1;
      args->result = eri_syscall_nr (nr, fd, a[0], a[1], a[2], a[3], a[4]);
      return;
    }

  if (! sig_mask_all_async (sig_th)) return;

  struct eri_pollfd fds[] = {
    { fd, ERI_POLLIN },
    { sig_th->event_pipe[0], ERI_POLLIN }
  };

  do
    {
      event->done = 1;

      struct eri_sigset mask = sig_th->sig_mask;
      eri_assert_lock (args->mask_lock);
      eri_sig_union_set (&mask, args->mask);
      eri_assert_unlock (args->mask_lock);

      args->result = eri_syscall (ppoll, fds, 2, 0, &mask, ERI_SIG_SETSIZE);
      if (args->result != ERI_EINTR)
	{
	  eri_assert (! eri_syscall_is_error (args->result));

	  if (fds[1].revents & ERI_POLLIN)
	    args->result = ERI_EINTR;
	}

      if (args->result != ERI_EINTR)
	args->result = eri_syscall_nr (nr, fd, a[0], a[1], a[2], a[3], a[4]);
    }
  while (args->result == ERI_EAGAIN);

  if (args->result != ERI_EINTR) restore_sig_mask (sig_th);
}

uint8_t
eri_live_signal_thread__sig_fd_read (
			struct eri_live_signal_thread *sig_th,
			struct eri_live_signal_thread__sig_fd_read_args *args)
{
  struct sig_fd_read_event event
		= { INIT_EVENT_TYPE (SIG_FD_READ_EVENT), args };
  proc_event (sig_th, &event);
  return event.done;
}

void
eri_live_signal_thread__syscall (
			struct eri_live_signal_thread *sig_th,
			struct eri_sys_syscall_args *args)
{
  struct syscall_event event = { INIT_EVENT_TYPE (SYSCALL_EVENT), args };
  proc_event (sig_th, &event);
}

uint8_t
eri_live_signal_thread__signaled (
			struct eri_live_signal_thread *sig_th)
{
  return !! eri_atomic_load (&sig_th->sig_info);
}

const struct eri_common_args *
eri_live_signal_thread__get_args (const struct eri_live_signal_thread *sig_th)
{
  return &sig_th->group->args;
}

struct eri_mtpool *
eri_live_signal_thread__get_pool (struct eri_live_signal_thread *sig_th)
{
  return sig_th->group->pool;
}

const struct eri_sigset *
eri_live_signal_thread__get_sig_mask (
			const struct eri_live_signal_thread *sig_th)
{
  return &sig_th->sig_mask;
}

int32_t
eri_live_signal_thread__get_pid (const struct eri_live_signal_thread *sig_th)
{
  return sig_th->group->pid;
}

int32_t
eri_live_signal_thread__get_tid (const struct eri_live_signal_thread *sig_th)
{
  return sig_th->tid;
}
