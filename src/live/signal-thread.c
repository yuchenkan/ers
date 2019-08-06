#include <lib/util.h>
#include <lib/lock.h>
#include <lib/atomic.h>
#include <lib/malloc.h>
#include <lib/syscall.h>

#include <common/debug.h>
#include <common/common.h>
#include <common/entry.h>
#include <common/helper.h>

#include <live/common.h>
#include <live/rtld.h>
#include <live/thread.h>
#include <live/signal-thread.h>
#include <live/signal-thread-local.h>

#define HELPER_STACK_SIZE	(256 * 1024)
#define WATCH_STACK_SIZE	8192

struct watch
{
  int32_t alive;
  uint8_t stack[WATCH_STACK_SIZE];
};

struct sig_act
{
  eri_lock_t lock;
  struct eri_sigaction act;
  uint64_t ver;
};

struct signal_thread_group
{
  struct eri_mtpool *pool;

  uint64_t file_buf_size;
  const char *log;

  uint64_t th_id;

  int32_t pid;

  struct sig_act sig_acts[ERI_NSIG - 1];
  struct eri_siginfo sig_sync_info;
  struct eri_siginfo sig_exit_group_info;

  uint8_t exit_group;
  int32_t exit_group_lock;

  uint32_t thread_count;
  eri_lock_t thread_lock;
  ERI_RBT_TREE_FIELDS (thread, struct eri_live_signal_thread)

  struct watch watch;
  struct eri_helper *helper;
  uint8_t exit_helper;

  uint64_t io;

  struct eri_live_thread_group *thread_group;
};

ERI_DEFINE_RBTREE (static, thread, struct signal_thread_group,
		   struct eri_live_signal_thread, int32_t, eri_less_than)

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

  eri_file_t log = eri_live_thread__get_sig_log (th);
  if (! eri_si_single_step (info) && eri_si_sync (info))
    eri_log (log, "sig = %u, frame = %lx, rip = %lx\n",
	     info->sig, frame, frame->ctx.mctx.rip);

  if (eri_si_sync (info))
    {
      eri_live_thread__sig_handler (th, frame, 0);
      return;
    }

  if (! thread_sig_filter (sig_th->group, info)) return;

  *info = *sig_th->sig_info;
  eri_log (log, "sig = %u, frame = %lx, rip = %lx\n",
	   info->sig, frame, frame->ctx.mctx.rip);
  eri_live_thread__sig_handler (th, frame, &sig_th->sig_act);
}

static void
sig_get_act (struct signal_thread_group *group, int32_t sig,
	     struct eri_sig_act *act)
{
  struct sig_act *sig_act = group->sig_acts + sig - 1;
  eri_assert_lock (&sig_act->lock);
  act->act = sig_act->act;
  act->ver = sig_act->ver;
  eri_assert_unlock (&sig_act->lock);
}

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  struct eri_live_signal_thread *sig_th = *(void **) ctx->stack.sp;
  struct eri_sigframe *frame = eri_struct_of (info, typeof (*frame), info);
  if (sig_th->sig_stack != (void *) ctx->stack.sp)
    {
      thread_sig_handler (sig_th, frame);
      return;
    }

  struct eri_live_thread *th = sig_th->th;

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

  if (! eri_live_thread__sig_digest_act (th, info, &sig_th->sig_act, 0))
    return;

  eri_log (sig_th->sig_log.file, "sig = %u, frame = %lx, code = %u\n",
	   info->sig, frame, info->code);
  sig_th->sig_info = info;
  eri_assert_syscall (tgkill, th_pid, th_tid, SIG_SIGNAL);

  if (sig_th->event_sig_restart
      && ctx->mctx.rip != sig_th->event_sig_reset_restart)
    ctx->mctx.rip = sig_th->event_sig_restart;

  eri_log (sig_th->sig_log.file, "\n");
  eri_sig_fill_set (&ctx->sig_mask);
}

static struct signal_thread_group *
create_group (struct eri_live_rtld_args *rtld_args)
{
  const char *log = 0;
  uint64_t file_buf_size = 64 * 1024;
  if (rtld_args->envp)
    {
      char **p;
      for (p = rtld_args->envp; *p; ++p)
	(void) (eri_get_arg_int (*p, "ERS_FILE_BUF_SIZE=", &file_buf_size, 10)
	|| eri_get_arg_str (*p, "ERI_LOG=", (void *) &log)
	|| eri_get_arg_int (*p, "ERI_DEBUG=", &eri_global_enable_debug, 10)
	|| eri_get_arg_int (*p, "ERI_LOG_NO_SEQ=", &eri_log_no_seq, 10));

      if (eri_global_enable_debug && ! log) log = "eri-live-log";
    }

  struct eri_mtpool *pool = eri_init_mtpool_from_buf (
				rtld_args->buf, rtld_args->buf_size, 1);
  struct signal_thread_group *group
			= eri_assert_malloc (&pool->pool, sizeof *group);
  group->pool = pool;
  group->file_buf_size = file_buf_size;

  group->log = eri_live_alloc_abs_path (pool, log);
  if (log)
    {
      eri_mkdir (log);
      eri_strcpy ((void *) group->log, log);
    }

  group->th_id = 0;
  group->pid = eri_assert_syscall (getpid);
  group->exit_helper = 0;
  group->io = 0;

  struct eri_live_thread__create_group_args args = {
    rtld_args, group->log, file_buf_size, group->pid, &group->io
  };
  group->thread_group = eri_live_thread__create_group (pool, &args);
  return group;
}

static void
init_group_signal (struct signal_thread_group *group)
{
  int32_t sig;
  for (sig = 1; sig < ERI_NSIG; ++sig)
    {
      if (! eri_sig_catchable (sig)) continue;

      struct sig_act *sig_act = group->sig_acts + sig - 1;
      sig_act->lock = 0;

      struct eri_sigaction act = {
	sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK,
	eri_assert_sys_sigreturn
      };
      eri_sig_fill_set (&act.mask);
      eri_assert_sys_sigaction (sig, &act, &sig_act->act);

      sig_act->ver = 0;
    }

  group->sig_sync_info.sig = 0;
  group->sig_exit_group_info.sig = ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP;
}

static void
set_sig_mask (struct eri_live_signal_thread *sig_th,
	      const eri_sigset_t *mask)
{
  eri_set_sig_mask (&sig_th->sig_mask, mask);
}

static void
init_event (struct eri_live_signal_thread *sig_th, eri_sigset_t *mask)
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

static void
open_log (struct eri_live_signal_thread *sig_th, struct eri_buf_file *log,
	  const char *name)
{
  struct signal_thread_group *group = sig_th->group;
  eri_open_log (group->pool, log, group->log, name, sig_th->id,
		eri_enabled_debug () ? 0 : group->file_buf_size);
}

static struct eri_live_signal_thread *
create (struct signal_thread_group *group)
{
  struct eri_live_signal_thread *sig_th
	= eri_assert_mtmalloc (group->pool, sizeof *sig_th);
  sig_th->group = group;
  sig_th->id = eri_atomic_fetch_inc (&group->th_id, 0);
  open_log (sig_th, &sig_th->log, "s");
  open_log (sig_th, &sig_th->sig_log, "ss");
  sig_th->alive = 1;
  return sig_th;
}

static void
destroy (struct eri_live_signal_thread *sig_th)
{
  struct eri_mtpool *pool = sig_th->group->pool;
  eri_close_log (pool, &sig_th->log);
  eri_close_log (pool, &sig_th->sig_log);
  eri_assert_mtfree (pool, sig_th);
}

static struct eri_live_signal_thread *
init_main (struct signal_thread_group *group,
	   struct eri_live_rtld_args *rtld_args)
{
  struct eri_live_signal_thread *sig_th = create (group);

  init_event (sig_th, &rtld_args->sig_mask);

  eri_log (sig_th->log.file, "sig_th %lx\n", sig_th);
  eri_assert_syscall (set_tid_address, &sig_th->alive);
  sig_th->tid = eri_assert_syscall (gettid);

  sig_th->th = eri_live_thread__create_main (group->thread_group,
					     sig_th, rtld_args, sig_th->tid);

  thread_rbt_insert (group, sig_th);
  return sig_th;
}

struct eri_live_signal_thread *
init_group (struct eri_live_rtld_args *rtld_args)
{
  struct signal_thread_group *group = create_group (rtld_args);

  init_group_signal (group);

  group->exit_group = 0;
  group->exit_group_lock = 0;

  group->thread_count = 1;
  group->thread_lock = 0;
  ERI_RBT_INIT_TREE (thread, group);

  return init_main (group, rtld_args);
}

void
eri_live_signal_thread__init_thread_sig_stack (
		struct eri_live_signal_thread *sig_th,
		uint8_t *stack, uint64_t stack_size)
{
  struct eri_stack st = {
    (uint64_t) stack, ERI_SS_AUTODISARM, stack_size
  };
  eri_assert_syscall (sigaltstack, &st, 0);

  *(void **) stack = sig_th;
}

static void
init_sig_stack (struct eri_live_signal_thread *sig_th)
{
  eri_live_signal_thread__init_thread_sig_stack (
	sig_th, sig_th->sig_stack, SIGNAL_THREAD_SIG_STACK_SIZE);
}

static void
restore_sig_mask (struct eri_live_signal_thread *sig_th)
{
  eri_assert_sys_sigprocmask (&sig_th->sig_mask, 0);
}

static eri_noreturn void
start_watch (struct eri_live_signal_thread *sig_th, eri_lock_t *lock)
{
  eri_debug ("\n");

  struct signal_thread_group *group = sig_th->group;
  group->helper = eri_helper__start (group->pool,
				     HELPER_STACK_SIZE, group->pid);
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
      if (info.chld.pid == th_pid
	  && ! eri_atomic_load (&group->exit_helper, 0))
	eri_xassert (! "group->exit_helper", eri_info);
    }
  eri_debug ("leave watch\n");
  eri_assert_sys_exit (0);
}

static void
watch (struct eri_live_signal_thread *sig_th)
{
  eri_lock_t lock = 1;
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

static eri_noreturn void event_loop (struct eri_live_signal_thread *sig_th);

void
start_group (struct eri_live_signal_thread *sig_th)
{
  eri_log (sig_th->log.file, "\n");

  watch (sig_th);

  init_sig_stack (sig_th);

  restore_sig_mask (sig_th);

  event_loop (sig_th);
}

static uint8_t
try_hold_exit_group (int32_t *lock)
{
  uint8_t hold = eri_atomic_inc_fetch (lock, 1) > 0;
  if (! hold) eri_atomic_dec (lock, 0);
  return hold;
}

static void
unhold_exit_group (int32_t *lock)
{
  eri_atomic_dec (lock, 1);
}

static uint8_t
try_lock_exit_group (struct signal_thread_group *group)
{
  if (eri_atomic_exchange (&group->exit_group, 1, 1) == 1) return 0;

  while (eri_atomic_compare_exchange (&group->exit_group_lock,
				      1, ERI_INT_MIN, 1) != 1)
    eri_assert_syscall (sched_yield);
  return 1;
}

static void
append_to_group (struct eri_live_signal_thread *sig_th)
{
  struct signal_thread_group *group = sig_th->group;
  eri_assert_lock (&group->thread_lock);
  thread_rbt_insert (group, sig_th);
  eri_assert_unlock (&group->thread_lock);
}

static void
remove_from_group (struct eri_live_signal_thread *sig_th)
{
  struct signal_thread_group *group = sig_th->group;
  eri_assert_lock (&group->thread_lock);
  thread_rbt_remove (group, sig_th);
  eri_assert_unlock (&group->thread_lock);
}

struct event_type
{
  uint32_t type;
  eri_lock_t lock;
};

#define INIT_EVENT_TYPE(type)	{ type, 1 }

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

#define SIG_EXIT_GROUP_EVENT		64

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
  const eri_sigset_t *mask;

  uint8_t done;
};

static uint8_t
sig_mask_all_async (struct eri_live_signal_thread *sig_th)
{
  eri_sigset_t mask;
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
  eri_log (sig_th->log.file, "\n");
  struct signal_thread_group *group = sig_th->group;

  uint8_t pending_exit_group = 0;
  while (1)
    {
      void *event_type;
      uint64_t res = eri_syscall (read, sig_th->event_pipe[0],
				  &event_type, sizeof event_type);
      if (res == ERI_EINTR) continue;
      eri_assert (eri_syscall_is_ok (res));

      uint32_t type = ((struct event_type *) event_type)->type;
      eri_log (sig_th->log.file, "%u\n", type);
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
      else eri_assert_unreachable ();

      /* These events have more than one place release_event.  */
      if (type != CLONE_EVENT && type != SIG_RESET_EVENT)
	release_event (event_type);
    }
}

struct clone_event {
  struct event_type type;
  struct eri_live_signal_thread__clone_args *args;

  eri_lock_t clone_thread_return;
  eri_lock_t clone_start_call;
  eri_lock_t clone_start_return;
  eri_lock_t clone_done;

  struct eri_live_signal_thread *sig_cth;
};

static eri_noreturn void
start (struct eri_live_signal_thread *sig_th, struct clone_event *event)
{
  eri_log (sig_th->log.file, "\n");

  init_sig_stack (sig_th);

  eri_assert_lock (&event->clone_start_call);
  if (eri_syscall_is_error (event->args->result))
    {
      eri_assert_syscall (set_tid_address, &event->clone_start_return);
      eri_assert_sys_exit (0);
    }

  restore_sig_mask (sig_th);
  append_to_group (sig_th);
  eri_assert_unlock (&event->clone_start_return);

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

  args->out = eri_live_out (&group->io);
  struct eri_live_signal_thread *sig_cth = event->sig_cth = create (group);

  init_event (sig_cth, &sig_th->sig_mask);

  sig_cth->th = eri_live_thread__create (sig_cth, args->args);

  eri_atomic_inc (&group->thread_count, 1);

  struct eri_sys_clone_args sig_cth_args = {
    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_THREAD | ERI_CLONE_PARENT_SETTID
    | ERI_CLONE_CHILD_CLEARTID,
    sig_cth->stack + SIGNAL_THREAD_STACK_SIZE - 8,
    &sig_cth->tid, &sig_cth->alive, 0, start, sig_cth, event
  };

  eri_log (sig_th->log.file, "clone %lx %lx %lx\n",
	   event, sig_cth, sig_cth_args.stack);
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
      eri_atomic_dec (&group->thread_count, 1);

      eri_live_thread__destroy (sig_cth->th);

      fini_event (sig_cth);
      destroy (sig_cth);
      unhold_exit_group (&group->exit_group_lock);
    }
  else eri_live_thread__set_user_tid (sig_cth->th, sig_cth->tid);

  restore_sig_mask (sig_th);
  eri_log (sig_th->log.file, "clone done %lx %lu\n", event, args->result);
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
    INIT_EVENT_TYPE (CLONE_EVENT), args, 1, 1, 1, 1
  };
  proc_event (sig_th, &event);

  if (args->result == 0) return 0;

  if (eri_syscall_is_ok (args->result))
    {
      uint64_t res = eri_live_thread__clone (event.sig_cth->th);
      if (eri_syscall_is_error (res)) args->result = res;
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
  destroy (sig_th);
}

static void
inform_exit_group (struct eri_live_signal_thread *sig_th)
{
  struct signal_thread_group *group = sig_th->group;

  struct eri_live_signal_thread *it;
  ERI_RBT_FOREACH (thread, group, it)
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
  if (! try_hold_exit_group (&group->exit_group_lock)) return;

  if (event->group && ! try_lock_exit_group (group))
    {
      unhold_exit_group (&group->exit_group_lock);
      return;
    }

  uint64_t status = event->status;
  struct eri_live_thread *th = sig_th->th;

  eri_log (sig_th->log.file, "status = %lu\n", status);

  if (! event->group
      && eri_atomic_dec_fetch (&group->thread_count, 1))
    {
      event->done = 1;
      release_event (event);
      eri_live_thread__join (th);

      remove_from_group (sig_th);

      eri_live_thread__destroy (th);

      fini_event (sig_th);
      eri_helper__invoke (group->helper, cleanup, sig_th);

      unhold_exit_group (&group->exit_group_lock);

      eri_log (sig_th->log.file, "exit %lx\n", sig_th);
      eri_assert_sys_exit (status);
    }
  else if (! event->group) eri_assert (try_lock_exit_group (group));
  else
    {
      eri_log (sig_th->log.file, "exit group\n");
      inform_exit_group (sig_th);

      struct eri_live_signal_thread *it, *nit;

      eri_log (sig_th->log.file, "exit thread group\n");

      ERI_RBT_FOREACH (thread, group, it)
	if (it != sig_th) join (it);

      ERI_RBT_FOREACH_SAFE (thread, group, it, nit)
	if (it != sig_th)
	  {
	    eri_live_thread__destroy (it->th);
	    thread_rbt_remove (group, it);
	    destroy (it);
	  }
    }

  eri_log (sig_th->log.file, "exit last thread\n");

  eri_atomic_store (&group->exit_helper, 1, 0);
  event->done = 1;
  release_event (event);
  eri_live_thread__join (th);

  eri_live_thread__destroy (th);
  eri_live_thread__destroy_group (group->thread_group);

  eri_log (sig_th->log.file, "exit helper\n");
  eri_helper__exit (group->helper);
  eri_assert_sys_futex_wait (&group->watch.alive, 1, 0);

  eri_log (sig_th->log.file, "destroy\n");

  struct eri_pool *pool = &group->pool->pool;
  eri_preserve (pool);

  destroy (sig_th);

  if (group->log) eri_assert_free (pool, (void *) group->log);
  eri_assert_free (pool, group);
  if (pool->used) eri_info ("%lu\n", pool->used);
  eri_assert_fini_pool (pool);

  eri_assert_sys_exit_group (status);
}

uint8_t
eri_live_signal_thread__exit (struct eri_live_signal_thread *sig_th,
			      uint8_t group, uint64_t status)
{
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
  struct eri_live_signal_thread__sig_action_args *args;

  uint8_t done;
};

static void
sig_action (struct eri_live_signal_thread *sig_th,
	    struct sig_action_event *event)
{
  eri_sigset_t mask = sig_th->sig_mask;
  struct eri_live_signal_thread__sig_action_args *args = event->args;
  eri_sig_add_set (&mask, args->sig);

  if (! sig_mask_async (sig_th, &mask)) return;

  struct sig_act *sig_act = sig_th->group->sig_acts + args->sig - 1;
  eri_assert_lock (&sig_act->lock);

  if (args->old_act) *args->old_act = sig_act->act;
  sig_act->act = *args->act;
  args->ver = sig_act->ver++;

  eri_assert_unlock (&sig_act->lock);

  event->done = 1;
  restore_sig_mask (sig_th);
}

uint8_t
eri_live_signal_thread__sig_action (struct eri_live_signal_thread *sig_th,
			struct eri_live_signal_thread__sig_action_args *args)
{
  if (! args->act)
    {
      struct eri_sig_act act;
      sig_get_act (sig_th->group, args->sig, &act);
      *args->old_act = act.act;
      args->ver = act.ver;
      return 1;
    }

  struct sig_action_event event
		= { INIT_EVENT_TYPE (SIG_ACTION_EVENT), args };
  proc_event (sig_th, &event);
  return event.done;
}

static uint8_t
thread_do_sig_mask (struct eri_live_signal_thread *sig_th,
		    uint32_t type, const eri_sigset_t *mask)
{
  struct sig_mask_event event = { INIT_EVENT_TYPE (type), mask };
  proc_event (sig_th, &event);
  return event.done;
}

uint8_t
eri_live_signal_thread__sig_mask_async (
			struct eri_live_signal_thread *sig_th,
			const eri_sigset_t *mask)
{
  return thread_do_sig_mask (sig_th, SIG_MASK_ASYNC_EVENT, mask);
}

uint8_t
eri_live_signal_thread__sig_tmp_mask_async (
			struct eri_live_signal_thread *sig_th,
			const eri_sigset_t *mask)
{
  return thread_do_sig_mask (sig_th, SIG_TMP_MASK_ASYNC_EVENT, mask);
}

uint8_t
eri_live_signal_thread__sig_mask_all (struct eri_live_signal_thread *sig_th)
{
  return thread_do_sig_mask (sig_th, SIG_MASK_ALL_EVENT, 0);
}

void
eri_live_signal_thread__sig_reset (struct eri_live_signal_thread *sig_th,
				   const eri_sigset_t *mask)
{
  thread_do_sig_mask (sig_th, SIG_RESET_EVENT, mask);
}

void
eri_live_signal_thread__sig_prepare (struct eri_live_signal_thread *sig_th,
			struct eri_siginfo *info, struct eri_sig_act *act)
{
  if (eri_live_signal_thread__sig_mask_all (sig_th))
    {
      sig_get_act (sig_th->group, info->sig, act);
      return;
    }

  /* XXX: May lost SIGTRAP here.  */
  eri_sigset_t set;
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
  struct eri_sys_syscall_args *sys_args = args->args;

  eri_sys_syscall (sys_args);
  if ((args->flags & ERI_SFD_NONBLOCK) || sys_args->result != ERI_EAGAIN)
    {
      event->done = 1;
      return;
    }

  if (! sig_mask_all_async (sig_th)) return;

  int32_t fd = sys_args->a[0];
  struct eri_pollfd fds[] = {
    { fd, ERI_POLLIN },
    { sig_th->event_pipe[0], ERI_POLLIN }
  };

  event->done = 1;

  do
    {
      eri_sigset_t mask = sig_th->sig_mask;
      eri_assert_lock (args->mask_lock);
      eri_sig_or_set (&mask, args->mask);
      eri_assert_unlock (args->mask_lock);

      sys_args->result = eri_syscall (ppoll, fds, 2, 0, &mask, ERI_SIG_SETSIZE);
      if (sys_args->result != ERI_EINTR)
	{
	  eri_assert (eri_syscall_is_ok (sys_args->result));

	  if (fds[1].revents & ERI_POLLIN) sys_args->result = ERI_EINTR;
	}

      if (sys_args->result == ERI_EINTR) break;

      eri_sys_syscall (sys_args);
    }
  while (sys_args->result == ERI_EAGAIN);

  if (sys_args->result != ERI_EINTR) restore_sig_mask (sig_th);
}

uint8_t
eri_live_signal_thread__sig_fd_read (struct eri_live_signal_thread *sig_th,
			struct eri_live_signal_thread__sig_fd_read_args *args)
{
  struct sig_fd_read_event event
		= { INIT_EVENT_TYPE (SIG_FD_READ_EVENT), args };
  proc_event (sig_th, &event);
  return event.done;
}

uint64_t
eri_live_signal_thread__syscall (struct eri_live_signal_thread *sig_th,
				 struct eri_sys_syscall_args *args)
{
  struct syscall_event event = { INIT_EVENT_TYPE (SYSCALL_EVENT), args };
  proc_event (sig_th, &event);
  return args->result;
}

uint8_t
eri_live_signal_thread__signaled (struct eri_live_signal_thread *sig_th)
{
  return !! eri_atomic_load (&sig_th->sig_info, 0);
}

const eri_sigset_t *
eri_live_signal_thread__get_sig_mask (
			const struct eri_live_signal_thread *sig_th)
{
  return &sig_th->sig_mask;
}

uint64_t
eri_live_signal_thread__get_id (const struct eri_live_signal_thread *sig_th)
{
  return sig_th->id;
}

int32_t
eri_live_signal_thread__map_tid (struct eri_live_signal_thread *sig_th,
				 int32_t tid)
{
  struct signal_thread_group *group = sig_th->group;
  eri_assert_lock (&group->thread_lock);
  struct eri_live_signal_thread *it;
  ERI_RBT_FOREACH (thread, group, it)
    if (it->tid == tid)
      {
	tid = eri_live_thread__get_tid (it->th);
	break;
      }
  eri_assert_unlock (&group->thread_lock);
  return tid;
}
