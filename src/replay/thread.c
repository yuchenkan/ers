/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/list.h>
#include <lib/atomic.h>
#include <lib/malloc.h>
#include <lib/printf.h>
#include <lib/syscall.h>

#include <common/debug.h>
#include <common/entry.h>
#include <common/common.h>
#include <common/serial.h>
#include <common/helper.h>

#include <replay/rtld.h>
#include <replay/thread.h>

#include <replay/analyzer.h>

#ifndef eri_enable_analyzer
# define eri_enable_analyzer	0
#endif

#define HELPER_STACK_SIZE	(256 * 1024)

struct version_waiter
{
  eri_lock_t lock;
  uint64_t ver;
  uint8_t dead_locked;
  ERI_LST_NODE_FIELDS (version_waiter)
};

struct version
{
  eri_lock_t lock;
  uint64_t ver;

  ERI_LST_NODE_FIELDS (version)
  ERI_LST_LIST_FIELDS (version_waiter)
};

struct version_activity
{
  uint64_t count;

  eri_lock_t lock;
  ERI_LST_LIST_FIELDS (version)
};

ERI_DEFINE_LIST (static, version_waiter,
		 struct version, struct version_waiter)
ERI_DEFINE_LIST (static, version, struct version_activity, struct version)

static void
version_init (struct version *ver)
{
  ver->lock = 0;
  ver->ver = 0;
  ERI_LST_INIT_LIST (version_waiter, ver);
}

static void
version_activity_init (struct version_activity *act)
{
  act->count = 1;
  act->lock = 0;
  ERI_LST_INIT_LIST (version, act);
}

static void
version_activity_inc (struct version_activity *act)
{
  eri_atomic_inc (&act->count, 1);
}

static void
version_activity_dec (struct version_activity *act)
{
  if (eri_atomic_dec_fetch (&act->count, 1)) return;

  struct version *v;
  struct version_waiter *w, *nw;
  ERI_LST_FOREACH (version, act, v)
    ERI_LST_FOREACH_SAFE (version_waiter, v, w, nw)
      {
	w->dead_locked = 1;
	eri_assert_unlock (&w->lock);
      }
}

struct thread_group
{
  struct eri_mtpool *pool;

  struct eri_range map_range;
  uint64_t base;
  uint64_t page_size;

  const char *path;
  const char *log;

  uint64_t stack_size;
  uint64_t file_buf_size;

  void *analyzer_group;
  struct eri_helper *helper;

  int32_t pid;

  struct version sig_acts[ERI_NSIG];

  struct version *atomic_table;
  uint64_t atomic_table_size;

  eri_lock_t exit_lock;
  uint64_t thread_count;

  int32_t user_pid;

  struct version io;

  uint64_t brk;
  struct version mm;

  struct version_activity ver_act;
};

#define THREAD_SIG_STACK_SIZE	(2 * 4096)

struct thread
{
  struct thread_group *group;
  struct eri_buf_file log;

  struct eri_entry *entry;
  uint8_t sync_async_trace;
  uint64_t sync_async_trace_steps;

  void *analyzer;

  eri_file_t file;
  uint8_t *file_buf;
  uint64_t marks;

  int32_t tid;
  int32_t alive;
  eri_lock_t start_lock;

  int32_t *clear_user_tid;
  int32_t user_tid;

  eri_sigset_t sig_mask;
  struct eri_stack sig_alt_stack;

  eri_aligned16 uint8_t sig_stack[THREAD_SIG_STACK_SIZE];
  eri_aligned16 uint8_t stack[0];
};

static uint64_t
page_size (struct thread *th) { return th->group->page_size; }

static uint8_t
version_do_wait (struct thread *th, struct version *ver, uint64_t exp)
{
  if (eri_atomic_load (&ver->ver, 0) >= exp) return 1;

  eri_assert_lock (&ver->lock);
  if (ver->ver >= exp)
    {
      eri_assert_unlock (&ver->lock);
      return 1;
    }

  struct version_activity *act = &th->group->ver_act;

  struct version_waiter waiter = { 1, exp, 0 };

  version_waiter_lst_append (ver, &waiter);
  if (version_waiter_lst_get_size (ver) == 1)
    {
      eri_assert_lock (&act->lock);
      version_lst_append (act, ver);
      eri_assert_unlock (&act->lock);
    }
  /* After insertion so to mark dead lock in the same way.  */
  version_activity_dec (act);
  eri_assert_unlock (&ver->lock);

  eri_assert_lock (&waiter.lock);
  uint8_t dead_locked = waiter.dead_locked;
  if (dead_locked)
    eri_log_info (th->log.file, "dead lock detected\n");
  return ! dead_locked;
}

static uint8_t
version_wait (struct thread *th, struct version *ver, uint64_t exp)
{
  uint8_t res = version_do_wait (th, ver, exp);
  if (res && eri_enable_analyzer)
    eri_analyzer__race_after (th->analyzer, (uint64_t) ver, exp);
  return res;
}

static void
version_update (struct thread *th, struct version *ver)
{
  /* Marking happens-before before happens-after is awoken.  */
  if (eri_enable_analyzer)
    eri_analyzer__race_before (th->analyzer, (uint64_t) ver, ver->ver + 1);

  struct version_activity *act = &th->group->ver_act;

  eri_assert_lock (&ver->lock);
  eri_atomic_inc (&ver->ver, 0);
  struct version_waiter *w, *nw;
  ERI_LST_FOREACH_SAFE (version_waiter, ver, w, nw)
    if (ver->ver == w->ver)
      {
	version_waiter_lst_remove (ver, w);
	if (version_waiter_lst_get_size (ver) == 0)
	  {
	    eri_assert_lock (&act->lock);
	    version_lst_remove (act, ver);
	    eri_assert_unlock (&act->lock);
	  }

	version_activity_inc (act);
	eri_assert_unlock (&w->lock);
      }
  eri_assert_unlock (&ver->lock);
}

static uint8_t
version_wait_update (struct thread *th, struct version *ver, uint64_t exp)
{
  if (! version_wait (th, ver, exp)) return 0;
  version_update (th, ver);
  return 1;
}

#define try_unserialize(what, _th, ...) \
  ({ struct thread *__th = _th;						\
     uint8_t __res = ERI_PASTE (eri_try_unserialize_, what) (		\
					__th->file, __VA_ARGS__);	\
     if (! __res)							\
       eri_log_info (__th->log.file,					\
		     "failed to unserialize " ERI_STR (what) "\n");	\
     __res; })

#define check_magic(th, m) \
  ({ struct thread *_th = th;						\
     uint16_t _n, _m = m;						\
     uint8_t _res = try_unserialize (magic, _th, &_n);			\
     if (_res && _n != _m)						\
       eri_log_info (_th->log.file,					\
		"unexpected magic detected: %s, expecting: %s\n",	\
		eri_record_magic_str (_n), eri_record_magic_str (_m));	\
     else if (_res)							\
       eri_log (_th->log.file, "magic: %s\n",				\
		eri_record_magic_str (_n));				\
     _res && _n == _m; })

static uint8_t
io_in (struct thread *th, uint64_t ver)
{
  return version_wait (th, &th->group->io, ver);
}

static uint8_t
io_out (struct thread *th, uint64_t ver)
{
  return version_wait_update (th, &th->group->io, ver);
}

static void sig_handler (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *ctx);
static eri_noreturn void error (struct thread *th);

static struct thread_group *
create_group (const struct eri_replay_rtld_args *rtld_args)
{
  struct eri_mtpool *pool = eri_init_mtpool_from_buf (
				rtld_args->buf, rtld_args->buf_size, 1);
  struct thread_group *group
			= eri_assert_malloc (&pool->pool, sizeof *group);
  group->pool = pool;

  group->map_range = rtld_args->map_range;
  group->base = rtld_args->base;
  group->page_size = rtld_args->page_size;
  group->path = eri_assert_malloc (&pool->pool,
				   eri_strlen (rtld_args->path) + 1);
  eri_strcpy ((void *) group->path, rtld_args->path);
  group->log = rtld_args->log ? eri_assert_malloc (&pool->pool,
			eri_strlen (rtld_args->log) + 1) : 0;
  if (rtld_args->log)
    {
      eri_mkdir (rtld_args->log);
      eri_strcpy ((void *) group->log, rtld_args->log);
    }

  group->stack_size = rtld_args->stack_size;
  group->file_buf_size = rtld_args->file_buf_size;

  group->pid = eri_assert_syscall (getpid);

  if (eri_enable_analyzer)
    {
      /* XXX: parameterize */
      struct eri_analyzer_group__create_args args = {
        group->pool, &group->map_range, group->log, group->page_size,
	group->file_buf_size, 64, 1024 * 1024, group->pid, error
      };
      group->analyzer_group = eri_analyzer_group__create (&args);
    }

  int32_t sig;
  for (sig = 1; sig < ERI_NSIG; ++sig)
    {
      if (! eri_sig_catchable (sig)) continue;

      struct eri_sigaction act = {
	sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK,
	eri_assert_sys_sigreturn
      };
      eri_sig_fill_set (&act.mask);
      eri_assert_sys_sigaction (sig, &act, 0);

      version_init (group->sig_acts + sig - 1);
    }

  group->exit_lock = 0;
  group->thread_count = 1;

  version_init (&group->io);
  version_init (&group->mm);
  version_activity_init (&group->ver_act);
  return group;
}

static void
destroy_group (struct thread_group *group)
{
  struct eri_pool *pool = &group->pool->pool;
  eri_assert_free (pool, group->atomic_table);
  if (eri_enable_analyzer)
    eri_analyzer_group__destroy (group->analyzer_group);
  if (group->log) eri_assert_free (pool, (void *) group->log);
  eri_assert_free (pool, (void *) group->path);
  eri_assert_free (pool, group);
  eri_assert_fini_pool (pool);
}

static eri_noreturn void
analysis (struct eri_entry *entry)
{
  struct thread *th = eri_entry__get_th (entry);
  eri_analyzer__enter (th->analyzer, eri_entry__get_regs (entry));
}

static eri_noreturn void main_entry (struct eri_entry *entry);
static eri_noreturn void sig_action (struct eri_entry *entry);

static struct thread *
create (struct thread_group *group, struct thread *pth,
	uint64_t id, int32_t *clear_user_tid)
{
  char name[eri_build_path_len (group->path, "t", id)];
  eri_build_path (group->path, "t", id, name);

  uint64_t file_buf_size = group->file_buf_size;
  eri_file_t file;
  void *file_buf = eri_assert_mtmalloc (group->pool, file_buf_size);
  if (eri_fopen (name, 1, &file, file_buf, file_buf_size) != 0)
    {
      eri_assert_mtfree (group->pool, file_buf);
      return 0;
    }

  struct thread *th = eri_assert_mtmalloc (group->pool,
				sizeof *th + group->stack_size);

  uint8_t *stack = th->stack + group->stack_size;

  th->group = group;
  eri_open_log (group->pool, &th->log, group->log, "l", id,
		eri_enabled_debug () ? 0 : file_buf_size);

  struct eri_entry__create_args args = {
    group->pool, &group->map_range, th, stack,
    main_entry, sig_action, eri_enable_analyzer ? analysis : 0
  };
  th->entry = eri_entry__create (&args);
  th->sync_async_trace = 0;

  if (eri_enable_analyzer)
    {
      struct eri_analyzer__create_args args = {
	group->analyzer_group, pth ? pth->analyzer : 0, id, th->entry, th
      };
      th->analyzer = eri_analyzer__create (&args);
    }

  th->file_buf = file_buf;
  th->file = file;
  th->marks = 0;

  th->alive = 1;
  th->start_lock = !! pth;
  th->clear_user_tid = clear_user_tid;

  *(void **) th->sig_stack = th;
  return th;
}

static void
destroy (struct thread *th)
{
  struct eri_mtpool *pool = th->group->pool;
  eri_close_log (pool, &th->log);
  eri_assert_fclose (th->file);

  eri_assert_mtfree (pool, th->file_buf);
  if (eri_enable_analyzer) eri_analyzer__destroy (th->analyzer);
  eri_entry__destroy (th->entry);
  eri_assert_mtfree (pool, th);
}

static void
cleanup (void *args)
{
  struct thread *th = args;
  eri_assert_sys_futex_wait (&th->alive, 1, 0);
  if (eri_enabled_debug ()) eri_log (th->log.file, "destroy\n");
  destroy (th);
}

static eri_noreturn void
exit (struct thread *th)
{
  eri_log (th->log.file, "\n");
  struct thread_group *group = th->group;
  version_activity_dec (&group->ver_act);
  eri_assert_lock (&group->exit_lock);
  if (eri_atomic_dec_fetch (&group->thread_count, 1))
    {
      eri_helper__invoke (group->helper, cleanup, th);
      eri_assert_unlock (&group->exit_lock);
      if (eri_enabled_debug ()) eri_log (th->log.file, "exit\n");
      eri_assert_sys_exit (0);
    }

  eri_assert_unlock (&group->exit_lock);

  if (eri_enabled_debug ()) eri_log (th->log.file, "exit helper\n");
  eri_helper__exit (group->helper);

  if (eri_enabled_debug ()) eri_log (th->log.file, "final exit\n");
  eri_preserve (&group->pool->pool);

  destroy (th);
  destroy_group (group);
  eri_assert_sys_exit (0);
}

#define diverged(th) \
  do {									\
    struct thread *_th = th;						\
    eri_log_info (_th->log.file, "diverged\n");				\
    if (! eri_enable_analyzer) eri_assert_unreachable ();		\
    exit (_th);								\
  } while (0)

static eri_noreturn void
error (struct thread *th)
{
  diverged (th);
}

static uint8_t
try_unserialize_mark (struct thread *th, uint8_t *mark)
{
  if (! try_unserialize (mark, th, mark)
      || *mark >= ERI_RECORD_MARK_NUM) return 0;
  eri_log (th->log.file, "%lu %s\n",
	   th->marks++, eri_record_mark_str (*mark));
  return 1;
}

static uint8_t
unserialize_mark (struct thread *th)
{
  uint8_t mark;
  eri_lassert (th->log.file, try_unserialize_mark (th, &mark));
  return mark;
}

static uint8_t
fetch_mark (struct thread *th)
{
  uint8_t mark;
  if (! try_unserialize_mark (th, &mark)) diverged (th);
  return mark;
}

static void
set_async_signal (struct thread *th)
{
  eri_assert_syscall (tgkill, th->group->pid, th->tid, ERI_SIGRTMIN);
}

static uint64_t
test_fetch_mark (struct thread *th, uint8_t mark)
{
  while (mark == ERI_SYSCALL_RESTART_OUT_RECORD)
    {
      uint64_t out;
      if (! try_unserialize (uint64, th, &out) || ! io_out (th, out))
	diverged (th);
      mark = fetch_mark (th);
    }
  return mark;
}

static void
test_next_async_signal (struct thread *th, uint8_t mark)
{
  if (test_fetch_mark (th, mark) == ERI_ASYNC_RECORD) set_async_signal (th);
}

static eri_noreturn void
start (struct thread *th, uint8_t next)
{
  struct eri_stack st = {
    (uint64_t) th->sig_stack, ERI_SS_AUTODISARM, THREAD_SIG_STACK_SIZE
  };
  eri_assert_syscall (sigaltstack, &st, 0);

  eri_assert_lock (&th->start_lock);

  if (eri_enable_analyzer) eri_analyzer__set_tid (th->analyzer, th->tid);

  eri_sigset_t mask;
  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_GS, th->entry);

  test_next_async_signal (th, next != (uint8_t) -1 ? next : fetch_mark (th));
  eri_entry__leave (th->entry);
}

static void
init_unmap (const struct eri_smaps_map *map, void *args)
{
  eri_assert_syscall (munmap, map->range.start,
		      map->range.end - map->range.start);
}

static int32_t
open_mmap_file (const char *path, uint64_t id)
{
  char name[eri_build_path_len (path, "m", id)];
  eri_build_path (path, "m", id, name);
  uint64_t fd = eri_sys_open (name, 1);
  return eri_syscall_is_error (fd) ? -1 : fd;
}

static void
update_mm_prot (struct thread *th, uint64_t start,
		uint64_t len, int32_t prot)
{
  if (eri_enable_analyzer)
    {
      struct eri_range range = { start, start + len };
      eri_analyzer__update_mm_prot (th->analyzer, range,
				prot & (ERI_PROT_READ | ERI_PROT_WRITE));
    }
}

static eri_noreturn void
start_main (struct thread *th)
{
  eri_assert (unserialize_mark (th) == ERI_INIT_RECORD);
  struct eri_init_record rec;
  eri_unserialize_init_record (th->file, &rec);
  eri_xassert (rec.ver == 0, eri_info);

  struct thread_group *group = th->group;
  eri_xassert (rec.page_size == group->page_size, eri_info);

  eri_log (th->log.file, "rec.rip: %lx, rec.rsp: %lx\n", rec.rip, rec.rsp);

  struct eri_registers *regs = eri_entry__get_regs (th->entry);
  regs->rip = rec.rip;
  regs->rsp = rec.rsp;
  regs->rdx = rec.rdx;

  th->sig_mask = rec.sig_mask;
  th->sig_alt_stack = rec.sig_alt_stack;

  uint64_t atomic_table_size = rec.atomic_table_size;
  group->atomic_table = eri_assert_malloc (&group->pool->pool,
			sizeof *group->atomic_table * atomic_table_size);
  uint64_t i;
  for (i = 0; i < atomic_table_size; ++i)
    version_init (group->atomic_table + i);
  group->atomic_table_size = atomic_table_size;

  th->user_tid = rec.user_pid;
  group->user_pid = rec.user_pid;
  group->brk = rec.brk;

  eri_init_foreach_map (group->pool, &group->map_range, init_unmap, 0);

  uint8_t next;
  while ((next = unserialize_mark (th)) == ERI_INIT_MAP_RECORD)
    {
      struct eri_init_map_record rec;
      eri_unserialize_init_map_record (th->file, &rec);
      eri_log (th->log.file, "rec.start: %lx, rec.end: %lx, rec.prot: %u\n",
	       rec.start, rec.end, rec.prot);
      uint64_t len = rec.end - rec.start;
      if (rec.type == ERI_INIT_MAP_FILE)
	{
	  uint64_t id = eri_unserialize_uint64 (th->file);
	  int32_t fd = open_mmap_file (th->group->path, id);
	  eri_lassert (th->log.file, fd != -1);
	  eri_assert_syscall (mmap, rec.start, len, rec.prot,
			      ERI_MAP_FIXED | ERI_MAP_PRIVATE, fd, 0);
	  eri_assert_syscall (close, fd);
	}
      else
	{
	  eri_assert_syscall (mmap, rec.start, len, rec.prot,
		ERI_MAP_FIXED | ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
	  if (rec.type == ERI_INIT_MAP_STACK)
	    {
	      eri_lassert (th->log.file, rec.prot & ERI_PROT_WRITE);
	      uint64_t start = eri_unserialize_uint64 (th->file);
	      eri_unserialize_uint8_array (th->file, (void *) start,
					   rec.end - start);
	    }
	  else
	    eri_lassert (th->log.file, rec.type == ERI_INIT_MAP_EMPTY);
	}

      update_mm_prot (th, rec.start, len, rec.prot);
    }

  group->helper = eri_helper__start (group->pool, HELPER_STACK_SIZE, 0);

  eri_assert_syscall (set_tid_address, &th->alive);
  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_FS, 0);
  // eri_debug_stop ();
  start (th, next);
}

eri_noreturn void
eri_replay_start (struct eri_replay_rtld_args *rtld_args)
{
  eri_global_enable_debug = rtld_args->debug;
  eri_log_no_seq = rtld_args->log_no_seq;
  eri_debug ("%lx, %lx, %u, base = %lx\n",
	     rtld_args->map_range.start, rtld_args->buf, rtld_args->buf_size,
	     rtld_args->base);
  if (eri_global_enable_debug && ! rtld_args->log)
    rtld_args->log = eri_enable_analyzer
			? "eri-analysis-log" : "eri-replay-log";
  struct thread_group *group = create_group (rtld_args);
  struct thread *th = create (group, 0, 0, 0);
  eri_xassert (th, eri_info);
  struct eri_entry *entry = th->entry;

  struct eri_registers *regs = eri_entry__get_regs (entry);
  eri_memset (regs, 0, sizeof *regs);
  regs->rdi = rtld_args->diverge;

  th->tid = group->pid;
  eri_jump (eri_entry__get_stack (entry) - 8, start_main, th, 0, 0);
}

static void
fetch_test_async_signal (struct thread *th)
{
  test_next_async_signal (th, fetch_mark (th));
}

static void
update_access (struct thread *th, struct eri_access *acc, uint64_t n)
{
  if (! eri_enable_analyzer) return;

  uint64_t i;
  for (i = 0; i < n; ++i)
    if (acc[i].type != ERI_ACCESS_NONE)
      eri_analyzer__update_access (th->analyzer, acc + i);
}

#define _call_with_user_access(proc, th, acc, n) \
  ({ typeof (proc) _res = proc;						\
     update_access (th, acc, n); _res; })
#define call_with_user_access(th, n, proc, ...) \
  ({ uint64_t _n = n;							\
     struct eri_access _acc[_n];					\
     _call_with_user_access ((proc) (__VA_ARGS__, _acc), th, _acc, _n); })

static uint8_t
copy_to_user (struct thread *th, void *dst, const void *src, uint64_t size)
{
  return call_with_user_access (th, 1,
		eri_entry__copy_to_user, th->entry, dst, src, size);
}

#define copy_obj_to_user(th, dst, src) \
  ({ typeof (dst) _dst = dst;						\
    copy_to_user (th, _dst, src, sizeof *_dst); })
#define copy_obj_to_user_or_fault(th, dst, src) \
  (copy_obj_to_user (th, dst, src) ? 0 : ERI_EFAULT)

static uint8_t
copy_to_user_opt (struct thread *th, void *dst,
		  const void *src, uint64_t size)
{
  return dst ? copy_to_user (th, dst, src, size) : 1;
}

static eri_unused uint8_t
copy_from_user (struct thread *th, void *dst, const void *src, uint64_t size)
{
  return call_with_user_access (th, 1,
		eri_entry__copy_from_user, th->entry, dst, src, size);
}

#define set_read(th, acc, mem, size) \
  eri_set_read (acc, (uint64_t) (mem), size,				\
		eri_entry__get_start ((th)->entry))
#define set_write(th, acc, mem, size) \
  eri_set_write (acc, (uint64_t) (mem), size,				\
		 eri_entry__get_start ((th)->entry))
#define set_read_write(th, acc, mem, size) \
  eri_set_read_write (acc, (uint64_t) (mem), size,			\
		      eri_entry__get_start ((th)->entry))

#define copy_obj_from_user(th, dst, src) \
  ({ typeof (dst) _dst = dst;						\
    copy_from_user (th, _dst, src, sizeof *_dst); })
#define copy_obj_from_user_or_fault(th, dst, src) \
  (copy_obj_from_user (th, dst, src) ? 0 : ERI_EFAULT)

#define READ	1
#define WRITE	2

static uint8_t
access_user (struct thread *th, void *mem, uint64_t size, uint8_t type)
{
  eri_assert (size);

  struct eri_entry *entry = th->entry;
  struct eri_access acc[] = {
    { .type = ERI_ACCESS_NONE }, { .type = ERI_ACCESS_NONE }
  };

  uint64_t done = size;
  if (! eri_entry__test_access (entry, mem, &done)) goto out;

  uint8_t *c;
  for (c = mem; c < (uint8_t *) mem + size; ++c)
    /*
     * Here write permission implies read (as in mmap), but this is not
     * consistent with the analysis, where read / write is considered
     * seperately.
     */
    asm ("" : : "r" (type & WRITE
		? eri_atomic_add_fetch (c, 0, 0) : *c) : "memory");

  eri_entry__reset_test_access (entry);
out:
  if (type & READ)
    set_read (th, acc, mem, eri_min (done + 1, size));
  if (type & WRITE)
    set_write (th, acc + 1, mem, eri_min (done + 1, size));
  update_access (th, acc, eri_length_of (acc));
  return done == size;
}

#define read_user(th, src, size) \
  access_user (th, (void *) (src), size, READ)
#define write_user(th, dst, size) \
  access_user (th, (void *) (dst), size, WRITE)
#define read_write_user(th, mem, size) \
  access_user (th, (void *) mem, size, READ | WRITE)

#define read_user_obj(th, obj) \
  ({ typeof (obj) _obj = obj;						\
     read_user (th, _obj, sizeof *_obj); })

static uint8_t
read_user_opt (struct thread *th, const void *src, uint64_t size)
{
  return src ? read_user (th, src, size) : 1;
}

#define read_user_obj_opt(th, obj) \
  ({ typeof (obj) _obj = obj;						\
     read_user_opt (th, _obj, sizeof *_obj); })

static uint8_t
read_str_from_user (struct thread *th, const char *str, uint64_t *len)
{
  uint64_t max = *len;
  eri_assert (max);

  struct eri_entry *entry = th->entry;
  struct eri_access acc;
  uint64_t done;

  if (! eri_entry__test_access (entry, str, &done))
    {
      set_read (th, &acc, str, done + 1);
      update_access (th, &acc, 1);
      return 0;
    }

  uint64_t i;
  for (i = 0; i < max && str[i]; ++i) continue;
  eri_entry__reset_test_access (entry);

  if (len) *len = i;
  set_read (th, &acc, str, eri_min (i + 1, max));
  update_access (th, &acc, 1);
  return 1;
}

static uint8_t
do_atomic_wait (struct thread *th, uint64_t aligned, uint64_t ver)
{
  struct thread_group *group = th->group;
  uint64_t idx = eri_atomic_hash (aligned, group->atomic_table_size);
  return version_wait (th, group->atomic_table + idx, ver);
}

static uint8_t
atomic_wait (struct thread *th,
	     uint64_t mem, uint8_t size, struct eri_pair ver)
{
  return do_atomic_wait (th, eri_atomic_aligned (mem), ver.first)
	 && (! eri_atomic_cross_aligned (mem, size) ? 1 : do_atomic_wait (th,
			eri_atomic_aligned2 (mem, size), ver.second));
}

static void
do_atomic_update (struct thread *th, uint64_t aligned)
{
  struct thread_group *group = th->group;
  uint64_t idx = eri_atomic_hash (aligned, group->atomic_table_size);
  version_update (th, group->atomic_table + idx);
}

static void
atomic_update (struct thread *th, uint64_t mem, uint8_t size)
{
  do_atomic_update (th, eri_atomic_aligned (mem));
  if (eri_atomic_cross_aligned (mem, size))
    do_atomic_update (th, eri_atomic_aligned2 (mem, size));
}

static uint8_t
atomic_access_user (struct thread *th, void *mem,
		    uint8_t size, uint16_t code)
{
  switch (code)
    {
    case ERI_OP_ATOMIC_LOAD: return read_user (th, mem, size);
    case ERI_OP_ATOMIC_STORE: return write_user (th, mem, size);
    default: return read_write_user (th, mem, size);
    }
}

static uint8_t
do_atomic (struct thread *th, uint16_t code, void *mem, uint8_t size,
	   uint64_t val, const struct eri_atomic_record *rec, void *old,
	   uint64_t *rflags)
{
  if (! rec->ok) return ! atomic_access_user (th, mem, size, code);

  struct eri_entry *entry = th->entry;

  if (! atomic_wait (th, (uint64_t) mem, size, rec->ver)) return 0;

  struct eri_access acc[2] = { 0 };
  if (code == ERI_OP_ATOMIC_LOAD) set_read (th, acc, mem, size);
  else if (code == ERI_OP_ATOMIC_STORE) set_write (th, acc, mem, size);
  else set_read_write (th, acc, mem, size);
  update_access (th, acc, eri_length_of (acc));

  if (! eri_entry__test_access (entry, mem, 0)) return 0;

  eri_lassert (th->log.file,
	       eri_atomic (code, mem, size, val, old, rflags));

  eri_entry__reset_test_access (entry);

  atomic_update (th, (uint64_t) mem, size);
  return 1;
}

static uint8_t
syscall_copy_to_user (struct thread *th, uint64_t res, void *dst,
		      const void *src, uint64_t size, uint8_t opt)
{
  return eri_syscall_is_non_fault_error (res) || (opt && ! dst)
	 || (copy_to_user (th, dst, src, size) == (res != ERI_EFAULT));
}

#define syscall_copy_obj_to_user(th, res, dst, src) \
  ({ typeof (dst) _dst = dst;						\
     syscall_copy_to_user (th, res, _dst, src, sizeof *_dst, 0); })
#define syscall_copy_obj_to_user_opt(th, res, dst, src) \
  ({ typeof (dst) _dst = dst;						\
     syscall_copy_to_user (th, res, _dst, src, sizeof *_dst, 1); })

static uint64_t
syscall_read_user_path (struct thread *th, const char *user_path)
{
  uint64_t len = ERI_PATH_MAX;
  return read_str_from_user (th, user_path, &len)
	? (len == ERI_PATH_MAX ? ERI_ENAMETOOLONG : 0) : ERI_EFAULT;
}

static uint8_t
syscall_wipe (struct thread *th,
	      void *buf, uint64_t size, uint8_t wipe)
{
  if (size == 0) return 1;

  struct eri_entry *entry = th->entry;
  struct eri_access acc;

  uint64_t done;
  if (! eri_entry__test_access (entry, buf, &done))
    {
      set_write (th, &acc, buf, done + 1);
      update_access (th, &acc, 1);
      return 0;
    }

  if (wipe) eri_memset (buf, 0, size);
  else
    {
      uint64_t i;
      for (i = 0; i < size; ++i)
	asm ("" : : "r" (((uint8_t *) buf)[i]) : "memory");
    }

  eri_entry__reset_test_access (entry);

  set_write (th, &acc, buf, size);
  update_access (th, &acc, 1);
  return 1;
}

static uint8_t
syscall_wipe_iovec (struct thread *th,
		    struct eri_iovec *iov, uint64_t cnt, uint8_t wipe)
{
  uint64_t i;
  for (i = 0; i < cnt; ++i)
    if (! syscall_wipe (th, iov->base, iov->len, wipe)) return 0;
  return 1;
}

#define SYSCALL_PARAMS \
  struct thread *th, struct eri_entry *entry, struct eri_registers *regs
#define SYSCALL_ARGS	th, entry, regs

#define DEFINE_SYSCALL(name) \
static eri_noreturn void						\
ERI_PASTE (syscall_, name) (SYSCALL_PARAMS)

static eri_noreturn void
syscall_leave (struct thread *th, uint8_t next, uint64_t res)
{
  if (next) fetch_test_async_signal (th);
  eri_entry__syscall_leave (th->entry, res);
}

static void
syscall_leave_if_error (struct thread *th, uint8_t next, uint64_t res)
{
  if (eri_syscall_is_error (res)) syscall_leave (th, next, res);
}

#define SYSCALL_TO_IMPL(name) \
DEFINE_SYSCALL (name) { syscall_leave (th, 0, ERI_ENOSYS); }

static eri_unused uint64_t
syscall_fetch_result (struct thread *th)
{
  uint64_t res;
  if (! check_magic (th, ERI_SYSCALL_RESULT_MAGIC)
      || ! try_unserialize (uint64, th, &res)) diverged (th);
  return res;
}

static uint64_t
syscall_fetch_in (struct thread *th)
{
  uint64_t in;
  if (! check_magic (th, ERI_SYSCALL_IN_MAGIC)
      || ! try_unserialize (uint64, th, &in)) diverged (th);
  return in;
}

static eri_unused void
syscall_fetch_out (struct thread *th)
{
  uint64_t out;
  if (! check_magic (th, ERI_SYSCALL_OUT_MAGIC)
      || ! try_unserialize (uint64, th, &out)
      || ! io_out (th, out)) diverged (th);
}

static struct eri_syscall_res_in_record
syscall_do_fetch_res_in (struct thread *th, uint16_t magic)
{
  struct eri_syscall_res_in_record rec;
  if (! check_magic (th, magic)
      || ! try_unserialize (syscall_res_in_record, th, &rec))
    diverged (th);
  return rec;
}

static struct eri_syscall_res_in_record
syscall_fetch_res_in (struct thread *th)
{
  return syscall_do_fetch_res_in (th, ERI_SYSCALL_RES_IN_MAGIC);
}

static struct eri_syscall_res_in_record
syscall_fetch_res_io (struct thread *th)
{
  struct eri_syscall_res_io_record rec;
  if (! check_magic (th, ERI_SYSCALL_RES_IO_MAGIC)
      || ! try_unserialize (syscall_res_io_record, th, &rec)
      || ! io_out (th, rec.out)) diverged (th);

  return rec.res;
}

static eri_noreturn void
syscall_do_no_sys (struct thread *th)
{
  syscall_leave (th, 0, ERI_ENOSYS);
}

static eri_noreturn void
syscall_do_res_in (struct thread *th)
{
  struct eri_syscall_res_in_record rec = syscall_fetch_res_in (th);
  if (! io_in (th, rec.in)) diverged (th);
  syscall_leave (th, 1, rec.result);
}

static eri_noreturn void
syscall_do_res_io (struct thread *th)
{
  struct eri_syscall_res_in_record rec = syscall_fetch_res_io (th);
  if (! io_in (th, rec.in)) diverged (th);
  syscall_leave (th, 1, rec.result);
}

DEFINE_SYSCALL (clone)
{
  struct eri_syscall_clone_record rec;
  if (! check_magic (th, ERI_SYSCALL_CLONE_MAGIC)
      || ! try_unserialize (syscall_clone_record, th, &rec)
      || ! io_out (th, rec.out))
    diverged (th);

  uint64_t res = rec.result;
  if (eri_syscall_is_error (res)) syscall_leave (th, 1, res);

  int32_t flags = regs->rdi;
  int32_t *user_ptid = (void *) regs->rdx;
  int32_t *user_ctid = (void *) regs->r10;

  if (flags & ERI_CLONE_PARENT_SETTID)
    (void) copy_obj_to_user (th, user_ptid, &res);
  if (flags & ERI_CLONE_CHILD_SETTID)
    (void) copy_obj_to_user (th, user_ctid, &res);

  int32_t *clear_user_tid = flags & ERI_CLONE_CHILD_CLEARTID ? user_ctid : 0;
  struct thread *cth = create (th->group, th, rec.id, clear_user_tid);
  if (! cth) diverged (th);

  eri_atomic_inc (&th->group->thread_count, 1);
  version_activity_inc (&th->group->ver_act);

  struct eri_entry *centry = cth->entry;
  struct eri_registers *cregs = eri_entry__get_regs (centry);
  *cregs = *regs;
  cregs->rsp = regs->rsi;
  cregs->rax = 0;
  cregs->rcx = cregs->rip;
  cregs->r11 = cregs->rflags;

  cth->user_tid = res;
  cth->sig_mask = th->sig_mask;
  cth->sig_alt_stack = th->sig_alt_stack;

  eri_sigset_t mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  void *new_tls = (void *) regs->r8;
  struct eri_sys_clone_args args = {
    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_THREAD
    | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | (new_tls ? ERI_CLONE_SETTLS : 0),

    eri_entry__get_stack (centry) - 8,
    &cth->tid, &cth->alive, new_tls, start, cth, eri_itop (-1)
  };

  eri_assert_sys_clone (&args);
  eri_assert_unlock (&cth->start_lock);

  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);
  syscall_leave (th, 1, res);
}

SYSCALL_TO_IMPL (unshare)
SYSCALL_TO_IMPL (kcmp)
SYSCALL_TO_IMPL (fork)
SYSCALL_TO_IMPL (vfork)
SYSCALL_TO_IMPL (setns)

DEFINE_SYSCALL (set_tid_address)
{
  th->clear_user_tid = (void *) regs->rdi;
  syscall_leave (th, 0, 0);
}

static eri_noreturn void
check_exit (struct thread *th)
{
  uint8_t err;
  if (eri_unserialize_uint8_or_eof (th->file, &err))
    {
      eri_log_info (th->log.file, "not eof %u\n", err);
      diverged (th);
    }
  exit (th);
}

static eri_noreturn void
syscall_do_exit (SYSCALL_PARAMS)
{
  struct eri_syscall_exit_record rec;
  if (! check_magic (th, ERI_SYSCALL_EXIT_MAGIC)
      || ! try_unserialize (syscall_exit_record, th, &rec))
    diverged (th);

  uint8_t exit_group = (int32_t) regs->rax == __NR_exit_group;

  if (exit_group) goto out;

  if (! do_atomic (th, ERI_OP_ATOMIC_STORE, th->clear_user_tid,
		   sizeof (int32_t), 0, &rec.clear_tid, 0, 0))
    diverged (th);

out:
  if (! io_out (th, rec.out)) diverged (th);
  check_exit (th);
}

DEFINE_SYSCALL (exit) { syscall_do_exit (SYSCALL_ARGS); }
DEFINE_SYSCALL (exit_group) { syscall_do_exit (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (wait4)
SYSCALL_TO_IMPL (waitid)

SYSCALL_TO_IMPL (execve)
SYSCALL_TO_IMPL (execveat)
SYSCALL_TO_IMPL (ptrace)
SYSCALL_TO_IMPL (syslog)
SYSCALL_TO_IMPL (seccomp)

DEFINE_SYSCALL (uname)
{
  struct eri_utsname *user_utsname = (void *) regs->rdi;

  struct eri_syscall_uname_record rec;
  eri_memset (&rec.utsname, 0, sizeof rec.utsname);

  if (! check_magic (th, ERI_SYSCALL_UNAME_MAGIC)
      || ! try_unserialize (syscall_uname_record, th, &rec)
      || eri_syscall_is_non_fault_error (rec.res.result)) diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_obj_to_user (th, res, user_utsname, &rec.utsname)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

SYSCALL_TO_IMPL (sysinfo)
SYSCALL_TO_IMPL (getcpu)

DEFINE_SYSCALL (getrandom)
{
  uint64_t user_buf, len;
  uint32_t flags;

  syscall_leave_if_error (th, 0,
	eri_entry__syscall_get_getrandom (entry, &user_buf, &len, &flags));

  uint64_t res;
  if (flags & ERI_GRND_RANDOM)
    {
      if (! check_magic (th, ERI_SYSCALL_GETRANDOM_RANDOM_MAGIC)
	  || ! try_unserialize (uint64, th, &res)) diverged (th);
      if (eri_syscall_is_fault_or_ok (res))
	{
	  uint64_t l;
	  if (! try_unserialize (uint64, th, &l) || l > len) diverged (th);

	  uint8_t buf[l];
	  if (! try_unserialize (uint8_array, th, buf, l)
	      || ! syscall_copy_to_user (th, res, (void *) user_buf, buf, l, 0))
	    diverged (th);
	}
    }
  else
    {
      if (! check_magic (th, ERI_SYSCALL_GETRANDOM_URANDOM_MAGIC))
	diverged (th);

      uint8_t fault = 0;
      uint64_t c = 0;
      while (1)
	{
	  uint64_t l;
	  if (! try_unserialize (uint64, th, &l)) diverged (th);

	  if (l == 0) break;

	  if (fault
	      || l > ERI_SYSCALL_GETRANDOM_URANDOM_BUF_SIZE
	      || c + l > len) diverged (th);

	  uint8_t buf[l];
	  if (! try_unserialize (uint8_array, th, buf, l)) diverged (th);

	  if (copy_to_user (th, (uint8_t *) user_buf + c, buf, l))
	    c += l;
	  else fault = 1;
	}

      if (! try_unserialize (uint64, th, &res)
	  || fault != (res == ERI_EFAULT)) diverged (th);
    }

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (setuid) { syscall_do_res_io (th); }
DEFINE_SYSCALL (getuid) { syscall_do_res_in (th); }
DEFINE_SYSCALL (setgid) { syscall_do_res_io (th); }
DEFINE_SYSCALL (getgid) { syscall_do_res_in (th); }
DEFINE_SYSCALL (geteuid) { syscall_do_res_in (th); }
DEFINE_SYSCALL (getegid) { syscall_do_res_in (th); }

DEFINE_SYSCALL (gettid) { syscall_leave (th, 0, th->user_tid); }
DEFINE_SYSCALL (getpid) { syscall_leave (th, 0, th->group->user_pid); }

DEFINE_SYSCALL (getppid) { syscall_do_res_in (th); }

DEFINE_SYSCALL (setreuid) { syscall_do_res_io (th); }
DEFINE_SYSCALL (setregid) { syscall_do_res_io (th); }

DEFINE_SYSCALL (setresuid) { syscall_do_res_io (th); }
DEFINE_SYSCALL (getresuid) { syscall_do_res_in (th); }
DEFINE_SYSCALL (setresgid) { syscall_do_res_io (th); }
DEFINE_SYSCALL (getresgid) { syscall_do_res_in (th); }

DEFINE_SYSCALL (setfsuid) { syscall_do_res_io (th); }
DEFINE_SYSCALL (setfsgid) { syscall_do_res_io (th); }

SYSCALL_TO_IMPL (setgroups)
SYSCALL_TO_IMPL (getgroups)

DEFINE_SYSCALL (setsid) { syscall_do_res_io (th); }
DEFINE_SYSCALL (getsid) { syscall_do_res_in (th); }

DEFINE_SYSCALL (setpgid) { syscall_do_res_io (th); }
DEFINE_SYSCALL (getpgid) { syscall_do_res_in (th); }
DEFINE_SYSCALL (getpgrp) { syscall_do_res_in (th); }

DEFINE_SYSCALL (time)
{
  int64_t *user_tloc = (void *) regs->rdi;
  struct eri_syscall_res_in_record rec = syscall_fetch_res_in (th);

  uint64_t res = rec.result;
  if (! syscall_copy_obj_to_user_opt (th, res, user_tloc, &res)
      || ! io_in (th, rec.in)) diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (times)
{
  struct eri_tms *user_buf = (void *) regs->rdi;

  struct eri_syscall_times_record rec;

  if (! check_magic (th, ERI_SYSCALL_TIMES_MAGIC)
      || ! try_unserialize (syscall_times_record, th, &rec))
    diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_obj_to_user_opt (th, res, user_buf, &rec.tms)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (settimeofday)
{
  const struct eri_timeval *user_tv = (void *) regs->rdi;

  if (! read_user_obj (th, user_tv)) syscall_leave (th, 0, ERI_EFAULT);
  syscall_do_res_io (th);
}

DEFINE_SYSCALL (gettimeofday)
{
  struct eri_timeval *user_tv = (void *) regs->rdi;

  struct eri_syscall_gettimeofday_record rec;

  if (! check_magic (th, ERI_SYSCALL_GETTIMEOFDAY_MAGIC)
      || ! try_unserialize (syscall_gettimeofday_record, th, &rec))
    diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_obj_to_user_opt (th, res, user_tv, &rec.time)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (clock_settime)
{
  int32_t id = regs->rdi;
  const struct eri_timespec *user_time = (void *) regs->rsi;

  syscall_leave_if_error (th, 0, eri_syscall_check_clock_id (id));
  if (! read_user_obj (th, user_time)) syscall_leave (th, 0, ERI_EFAULT);
  syscall_do_res_io (th);
}

static eri_noreturn void
syscall_do_clock_gettime (SYSCALL_PARAMS)
{
  uint8_t time = (int32_t) regs->rax == __NR_clock_getres;
  int32_t id = regs->rdi;
  struct eri_timespec *user_time = (void *) regs->rsi;

  syscall_leave_if_error (th, 0, eri_syscall_check_clock_id (id));

  struct eri_syscall_clock_gettime_record rec;

  if (! check_magic (th, ERI_SYSCALL_CLOCK_GETTIME_MAGIC)
      || ! try_unserialize (syscall_clock_gettime_record, th, &rec))
    diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_to_user (th, res, user_time,
			      &rec.time, sizeof *user_time, ! time)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (clock_gettime) { syscall_do_clock_gettime (SYSCALL_ARGS); }
DEFINE_SYSCALL (clock_getres) { syscall_do_clock_gettime (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (nanosleep)
SYSCALL_TO_IMPL (clock_nanosleep)

static eri_noreturn void
syscall_do_adjtimex (SYSCALL_PARAMS)
{
  uint8_t clock = (int32_t) regs->rax == __NR_clock_adjtime;
  struct eri_timex *user_buf = (void *) (clock ? regs->rsi : regs->rdi);

  if (clock)
    syscall_leave_if_error (th, 0, eri_syscall_check_clock_id (regs->rdi));

  if (! read_user_obj (th, user_buf)) syscall_leave (th, 0, ERI_EFAULT);

  syscall_do_res_io (th);
}

DEFINE_SYSCALL (adjtimex) { syscall_do_adjtimex (SYSCALL_ARGS); }
DEFINE_SYSCALL (clock_adjtime) { syscall_do_adjtimex (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (alarm)
SYSCALL_TO_IMPL (setitimer)
SYSCALL_TO_IMPL (getitimer)

SYSCALL_TO_IMPL (timer_create)
SYSCALL_TO_IMPL (timer_settime)
SYSCALL_TO_IMPL (timer_gettime)
SYSCALL_TO_IMPL (timer_getoverrun)
SYSCALL_TO_IMPL (timer_delete)

DEFINE_SYSCALL (setrlimit)
{
  int32_t resource = regs->rdi;
  const struct eri_rlimit *user_rlimit = (void *) regs->rsi;

  syscall_leave_if_error (th, 0,
		eri_syscall_check_prlimit64_resource (resource));

  if (! read_user_obj (th, user_rlimit)) syscall_leave (th, 0, ERI_EFAULT);

  syscall_do_res_in (th);
}

DEFINE_SYSCALL (getrlimit)
{
  int32_t resource = regs->rdi;
  struct eri_rlimit *user_rlimit = (void *) regs->rsi;

  syscall_leave_if_error (th, 0,
		eri_syscall_check_prlimit64_resource (resource));

  struct eri_syscall_getrlimit_record rec;
  if (! check_magic (th, ERI_SYSCALL_GETRLIMIT_MAGIC)
      || ! try_unserialize (syscall_getrlimit_record, th, &rec))
    diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_obj_to_user (th, res, user_rlimit, &rec.rlimit)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (prlimit64)
{
  int32_t resource = regs->rsi;
  const struct eri_rlimit *user_new_rlimit = (void *) regs->rdx;
  struct eri_rlimit *user_old_rlimit = (void *) regs->r10;

  syscall_leave_if_error (th, 0,
		eri_syscall_check_prlimit64_resource (resource));

  if (! read_user_obj_opt (th, user_new_rlimit))
    syscall_leave (th, 0, ERI_EFAULT);

  struct eri_syscall_prlimit64_record rec;
  if (! check_magic (th, ERI_SYSCALL_PRLIMIT64_MAGIC)
      || ! try_unserialize (syscall_prlimit64_record, th, &rec)
      || ! io_out (th, rec.out))
    diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_obj_to_user_opt (th, res, user_old_rlimit, &rec.rlimit)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (getrusage)
{
  int32_t who = regs->rdi;
  struct eri_rusage *user_rusage = (void *) regs->rsi;

  syscall_leave_if_error (th, 0,
		eri_syscall_check_getrusage_who (who));

  struct eri_syscall_getrusage_record rec;
  if (! check_magic (th, ERI_SYSCALL_GETRUSAGE_MAGIC)
      || ! try_unserialize (syscall_getrusage_record, th, &rec))
    diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_obj_to_user (th, res, user_rusage, &rec.rusage)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

SYSCALL_TO_IMPL (capset)
SYSCALL_TO_IMPL (capget)

SYSCALL_TO_IMPL (personality)
SYSCALL_TO_IMPL (prctl)

DEFINE_SYSCALL (arch_prctl)
{
  syscall_leave (th, 0, eri_entry__syscall (entry));
}

SYSCALL_TO_IMPL (quotactl)
SYSCALL_TO_IMPL (acct)

DEFINE_SYSCALL (setpriority)
{
  int32_t which = regs->rdi;
  syscall_leave_if_error (th, 0, eri_syscall_priority_check_which (which));
  syscall_do_res_io (th);
}

DEFINE_SYSCALL (getpriority)
{
  int32_t which = regs->rdi;
  syscall_leave_if_error (th, 0, eri_syscall_priority_check_which (which));
  syscall_do_res_in (th);
}

DEFINE_SYSCALL (sched_yield) { syscall_leave (th, 0, 0); }

SYSCALL_TO_IMPL (sched_setparam)
SYSCALL_TO_IMPL (sched_getparam)
SYSCALL_TO_IMPL (sched_setscheduler)
SYSCALL_TO_IMPL (sched_getscheduler)
SYSCALL_TO_IMPL (sched_get_priority_max)
SYSCALL_TO_IMPL (sched_get_priority_min)
SYSCALL_TO_IMPL (sched_rr_get_interval)
SYSCALL_TO_IMPL (sched_setaffinity)
SYSCALL_TO_IMPL (sched_getaffinity)
SYSCALL_TO_IMPL (sched_setattr)
SYSCALL_TO_IMPL (sched_getattr)

SYSCALL_TO_IMPL (ioprio_set)
SYSCALL_TO_IMPL (ioprio_get)

DEFINE_SYSCALL (rt_sigprocmask)
{
  eri_sigset_t mask;
  eri_sigset_t old_mask = th->sig_mask;
  syscall_leave_if_error (th, 0, call_with_user_access (th, 1,
	eri_entry__syscall_get_rt_sigprocmask, entry, &old_mask, &mask));
  if (eri_entry__syscall_rt_sigprocmask_mask (entry))
    eri_set_sig_mask (&th->sig_mask, &mask);
  syscall_leave (th, 0, call_with_user_access (th, 1,
	eri_entry__syscall_set_rt_sigprocmask, entry, &old_mask));
}

DEFINE_SYSCALL (rt_sigaction)
{
  int32_t sig = regs->rdi;
  struct eri_sigaction *user_act = (void *) regs->rsi;
  struct eri_sigaction *user_old_act = (void *) regs->rdx;

  if (! eri_sig_catchable (sig)) syscall_leave (th, 0, ERI_EINVAL);

  if (! user_act && ! user_old_act) syscall_leave (th, 0, 0);

  if (! read_user_obj (th, user_act)) syscall_leave (th, 0, ERI_EFAULT);

  uint64_t res = 0;
  uint64_t act_ver;
  if (user_old_act)
    {
      struct eri_sigaction act = { 0 };
      if (! check_magic (th, ERI_SYSCALL_RT_SIGACTION_MAGIC)
	  || ! try_unserialize (sigaction, th, &act)
	  || ! try_unserialize (uint64, th, &act_ver))
	diverged (th);

      res = copy_obj_to_user_or_fault (th, user_old_act, &act);
    }
  else if (! check_magic (th, ERI_SYSCALL_RT_SIGACTION_SET_MAGIC)
	   || ! try_unserialize (uint64, th, &act_ver))
    diverged (th);

  struct thread_group *group = th->group;
  if ((user_act || eri_syscall_is_ok (res))
      && ! version_wait (th, group->sig_acts + sig - 1, act_ver))
    diverged (th);
  if (user_act) version_update (th, group->sig_acts + sig - 1);
  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (sigaltstack)
{
  syscall_leave (th, 0, call_with_user_access (th,
	ERI_ENTRY__MAX_SYSCALL_SIGALTSTACK_USER_ACCESSES,
	eri_entry__syscall_sigaltstack, entry, &th->sig_alt_stack));
}

DEFINE_SYSCALL (rt_sigreturn)
{
  struct eri_stack st = {
    (uint64_t) th->sig_stack, ERI_SS_AUTODISARM, THREAD_SIG_STACK_SIZE
  };
  if (! call_with_user_access (th,
	ERI_ENTRY__MAX_SYSCALL_RT_SIGRETURN_USER_ACCESSES,
	eri_entry__syscall_rt_sigreturn, entry, &st, &th->sig_mask))
    check_exit (th);
  th->sig_alt_stack = st;
  eri_entry__leave (entry);
}

DEFINE_SYSCALL (rt_sigpending)
{
  syscall_leave_if_error (th, 0,
	eri_entry__syscall_validate_rt_sigpending (entry));

  struct eri_syscall_rt_sigpending_record rec;
  if (! check_magic (th, ERI_SYSCALL_RT_SIGPENDING_MAGIC)
      || ! try_unserialize (syscall_rt_sigpending_record, th, &rec)
      || copy_to_user (th, (void *) regs->rdi, &rec.set, ERI_SIG_SETSIZE)
		!= (rec.res.result != ERI_EFAULT)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, rec.res.result);
}

static eri_noreturn void
syscall_do_pause (struct thread *th)
{
  if (! io_in (th, syscall_fetch_in (th))) diverged (th);
  syscall_leave (th, 1, ERI_EINTR);
}

DEFINE_SYSCALL (pause) { syscall_do_pause (th); }

DEFINE_SYSCALL (rt_sigsuspend)
{
  eri_sigset_t *user_mask = (void *) regs->rdi;
  uint64_t size = regs->rsi;

  if (size != ERI_SIG_SETSIZE) syscall_leave (th, 0, ERI_EINVAL);

  if (! read_user_obj (th, user_mask)) syscall_leave (th, 0, ERI_EFAULT);

  syscall_do_pause (th);
}

DEFINE_SYSCALL (rt_sigtimedwait)
{
  eri_sigset_t *user_set = (void *) regs->rdi;
  struct eri_siginfo *user_info = (void *) regs->rsi;
  struct eri_timespec *user_timeout = (void *) regs->rdx;
  uint64_t size = regs->r10;

  if (size != ERI_SIG_SETSIZE) syscall_leave (th, 0, ERI_EINVAL);

  if (! read_user_obj (th, user_set)
      || ! read_user_obj_opt (th, user_timeout))
    syscall_leave (th, 0, ERI_EFAULT);

  struct eri_syscall_rt_sigtimedwait_record rec;
  if (user_info) eri_memset (&rec.info, 0, sizeof rec.info);
  if (! check_magic (th, ERI_SYSCALL_RT_SIGTIMEDWAIT_MAGIC)
      || ! try_unserialize (syscall_rt_sigtimedwait_record, th, &rec))
    diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_obj_to_user_opt (th, res, user_info, &rec.info)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (kill) { syscall_do_res_io (th); }
DEFINE_SYSCALL (tkill) { syscall_do_res_io (th); }
DEFINE_SYSCALL (tgkill) { syscall_do_res_io (th); }

static eri_noreturn void
syscall_do_rt_sigqueueinfo (SYSCALL_PARAMS)
{
  struct eri_syscall_res_in_record rec = syscall_fetch_res_io (th);

  struct eri_siginfo *user_info = (void *) (regs->rax
			== __NR_rt_sigqueueinfo ? regs->rdx : regs->r10);
  if (read_user_obj (th, user_info) != (rec.result != ERI_EFAULT)
      || ! io_in (th, rec.in)) diverged (th);
  syscall_leave (th, 1, rec.result);
}

DEFINE_SYSCALL (rt_sigqueueinfo)
{
  syscall_do_rt_sigqueueinfo (SYSCALL_ARGS);
}

DEFINE_SYSCALL (rt_tgsigqueueinfo)
{
  syscall_do_rt_sigqueueinfo (SYSCALL_ARGS);
}

DEFINE_SYSCALL (restart_syscall) { syscall_do_no_sys (th); }

DEFINE_SYSCALL (socket) { syscall_do_res_io (th); }

static uint64_t
syscall_read_user_addr (struct thread *th,
			const struct eri_sockaddr *user_addr, uint32_t len)
{
  if (len > sizeof (struct eri_sockaddr_storage))
    return ERI_EINVAL;
  return len && ! read_user (th, user_addr, len) ? ERI_EFAULT : 0;
}

DEFINE_SYSCALL (connect)
{
  const struct eri_sockaddr *user_addr = (void *) regs->rsi;
  uint32_t addrlen = regs->rdx;

  syscall_leave_if_error (th, 0,
			  syscall_read_user_addr (th, user_addr, addrlen));
  syscall_do_res_io (th);
}

static uint8_t
syscall_copy_addr_to_user (struct thread *th, uint64_t res,
	struct eri_sockaddr *user_addr, uint32_t *user_addrlen,
	const struct eri_sockaddr_storage *addr, uint32_t addrlen,
	uint8_t opt)
{
  if (eri_syscall_is_non_fault_error (res)) return 1;

  if (syscall_copy_to_user (th, res, user_addr, addr, addrlen, opt)
      && syscall_copy_to_user (th, res,
			user_addr || ! opt ? user_addrlen : 0, &addrlen,
			sizeof *user_addrlen, opt))
    return eri_syscall_is_ok (res);

  return res == ERI_EFAULT;
}

static eri_noreturn void
syscall_do_accept (SYSCALL_PARAMS)
{
  struct eri_sockaddr *user_addr = (void *) regs->rsi;
  uint32_t *user_addrlen = (void *) regs->rdx;

  struct eri_syscall_accept_record rec;

  if (! check_magic (th, ERI_SYSCALL_ACCEPT_MAGIC)
      || ! try_unserialize (syscall_accept_record, th, &rec)
      || ! io_out (th, rec.out)) diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_addr_to_user (th, res, user_addr, user_addrlen,
				   &rec.addr, rec.addrlen, 1))
    diverged (th);

  if (! io_in (th, rec.res.in)) diverged (th);
  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (accept) { syscall_do_accept (SYSCALL_ARGS); }
DEFINE_SYSCALL (accept4) { syscall_do_accept (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (sendto)
SYSCALL_TO_IMPL (recvfrom)
SYSCALL_TO_IMPL (sendmsg)
SYSCALL_TO_IMPL (sendmmsg)
SYSCALL_TO_IMPL (recvmsg)
SYSCALL_TO_IMPL (recvmmsg)

DEFINE_SYSCALL (shutdown) { syscall_do_res_io (th); }

DEFINE_SYSCALL (bind)
{
  const struct eri_sockaddr *user_addr = (void *) regs->rsi;
  uint32_t addrlen = regs->rdx;

  syscall_leave_if_error (th, 0,
			  syscall_read_user_addr (th, user_addr, addrlen));
  syscall_do_res_io (th);
}

DEFINE_SYSCALL (listen) { syscall_do_res_io (th); }

static eri_noreturn void
syscall_do_getsockname (SYSCALL_PARAMS)
{
  struct eri_sockaddr *user_addr = (void *) regs->rsi;
  uint32_t *user_addrlen = (void *) regs->rdx;

  if (! read_user_obj (th, user_addrlen)) syscall_leave (th, 0, ERI_EFAULT);

  struct eri_syscall_getsockname_record rec;
  if (! check_magic (th, ERI_SYSCALL_GETSOCKNAME_MAGIC)
      || ! try_unserialize (syscall_getsockname_record, th, &rec))
    diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_addr_to_user (th, res, user_addr, user_addrlen,
				   &rec.addr, rec.addrlen, 0))
    diverged (th);

  if (! io_in (th, rec.res.in)) diverged (th);
  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (getsockname) { syscall_do_getsockname (SYSCALL_ARGS); }
DEFINE_SYSCALL (getpeername) { syscall_do_getsockname (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (socketpair)
SYSCALL_TO_IMPL (setsockopt)
SYSCALL_TO_IMPL (getsockopt)

SYSCALL_TO_IMPL (sethostname)
SYSCALL_TO_IMPL (setdomainname)

SYSCALL_TO_IMPL (bpf)

SYSCALL_TO_IMPL (memfd_create)

SYSCALL_TO_IMPL (timerfd_create)
SYSCALL_TO_IMPL (timerfd_settime)
SYSCALL_TO_IMPL (timerfd_gettime)

SYSCALL_TO_IMPL (eventfd)
SYSCALL_TO_IMPL (eventfd2)

static eri_noreturn void
syscall_do_signalfd (SYSCALL_PARAMS)
{
  eri_sigset_t *user_mask = (void *) regs->rsi;

  int32_t flags;
  syscall_leave_if_error (th, 0,
		eri_entry__syscall_get_signalfd (entry, &flags));
  if (! read_user_obj (th, user_mask)) syscall_leave (th, 0, ERI_EINVAL);

  syscall_do_res_io (th);
}

DEFINE_SYSCALL (signalfd) { syscall_do_signalfd (SYSCALL_ARGS); }
DEFINE_SYSCALL (signalfd4) { syscall_do_signalfd (SYSCALL_ARGS); }

static eri_noreturn void
syscall_do_pipe (SYSCALL_PARAMS)
{
  int32_t *user_pipefd = (void *) regs->rdi;

  struct eri_syscall_pipe_record rec;
  if (! check_magic (th, ERI_SYSCALL_PIPE_MAGIC)
      || ! try_unserialize (syscall_pipe_record, th, &rec)
      || ! io_out (th, rec.out)) diverged (th);

  uint64_t res = rec.res.result;
  if (! syscall_copy_to_user (th, res, user_pipefd, &rec.pipe,
			      sizeof rec.pipe, 0))
    diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (pipe) { syscall_do_pipe (SYSCALL_ARGS); }
DEFINE_SYSCALL (pipe2) { syscall_do_pipe (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (inotify_init)
SYSCALL_TO_IMPL (inotify_init1)
SYSCALL_TO_IMPL (inotify_add_watch)
SYSCALL_TO_IMPL (inotify_rm_watch)

SYSCALL_TO_IMPL (fanotify_init)
SYSCALL_TO_IMPL (fanotify_mark)

SYSCALL_TO_IMPL (userfaultfd)
SYSCALL_TO_IMPL (perf_event_open)

static eri_noreturn void
syscall_do_open (SYSCALL_PARAMS)
{
  int32_t nr = regs->rax;
  uint8_t at = nr == __NR_openat || nr == __NR_unlinkat
	       || nr == __NR_faccessat || nr == __NR_fchmodat
	       || nr == __NR_mkdirat || nr == __NR_mknodat
	       || nr == __NR_fchownat;
  uint8_t io = nr != __NR_access && nr != __NR_faccessat;

  const char *user_path = (void *) (at ? regs->rsi : regs->rdi);
  
  syscall_leave_if_error (th, 0, syscall_read_user_path (th, user_path));
  if (io) syscall_do_res_io (th);
  else syscall_do_res_in (th);
}

DEFINE_SYSCALL (open) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (openat) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (creat) { syscall_do_open (SYSCALL_ARGS); }

DEFINE_SYSCALL (close) { syscall_do_res_io (th); }
DEFINE_SYSCALL (dup) { syscall_do_res_io (th); }
DEFINE_SYSCALL (dup2) { syscall_do_res_io (th); }
DEFINE_SYSCALL (dup3) { syscall_do_res_io (th); }

SYSCALL_TO_IMPL (name_to_handle_at)
SYSCALL_TO_IMPL (open_by_handle_at)

DEFINE_SYSCALL (fcntl)
{
  int32_t cmd = regs->rsi;
  if (cmd == ERI_F_DUPFD || cmd == ERI_F_DUPFD_CLOEXEC
      || cmd == ERI_F_GETFL || cmd == ERI_F_SETFL)
    syscall_do_res_io (th);

  syscall_leave (th, 0, ERI_ENOSYS);
}

SYSCALL_TO_IMPL (flock)
SYSCALL_TO_IMPL (fadvise64)

SYSCALL_TO_IMPL (truncate)
SYSCALL_TO_IMPL (ftruncate)

static eri_noreturn void
syscall_do_select (SYSCALL_PARAMS)
{
  uint8_t psel = (int32_t) regs->rax == __NR_pselect6;

  uint32_t nfds = regs->rdi;
  uint8_t *user_readfds = (void *) regs->rsi;
  uint8_t *user_writefds = (void *) regs->rdx;
  uint8_t *user_exceptfds = (void *) regs->r10;
  void *user_timeout = (void *) regs->r8;
  eri_sigset_t *user_sig = psel ? (void *) regs->r9 : 0;

  if (nfds > ERI_FD_SETSIZE) syscall_leave (th, 0, ERI_EINVAL);

  uint32_t size = eri_syscall_fd_set_bytes (nfds);
  if (! read_user_opt (th, user_readfds, size)
      || ! read_user_opt (th, user_writefds, size)
      || ! read_user_opt (th, user_exceptfds, size))
    syscall_leave (th, 0, ERI_EFAULT);

  if (! (psel ? read_user_obj_opt (th, (struct eri_timespec *) user_timeout)
	      : read_user_obj_opt (th, (struct eri_timeval *) user_timeout)))
    syscall_leave (th, 0, ERI_EFAULT);

  if (user_sig)
    {
      uint64_t sig_set_size;
      if (! read_user_obj (th, user_sig)
	  || ! copy_obj_from_user (th, &sig_set_size, user_sig + 1))
	syscall_leave (th, 0, ERI_EFAULT);

      if (sig_set_size != ERI_SIG_SETSIZE)
	syscall_leave (th, 0, ERI_EINVAL);
    }

  struct eri_syscall_res_in_record rec;
  if (! check_magic (th, ERI_SYSCALL_SELECT_MAGIC)
      || ! try_unserialize (syscall_res_in_record, th, &rec)) diverged (th);

  uint8_t flags = eri_get_serial_select_flags (user_readfds, user_writefds,
					       user_exceptfds, psel, 0);

  uint8_t rec_flags;
  if (! try_unserialize (uint8, th, &rec_flags)
      || (rec_flags ^ flags) & ~(psel ? ERI_SYSCALL_SELECT_TIMESPEC
				      : ERI_SYSCALL_SELECT_TIMEVAL))
    diverged (th);

  if (eri_syscall_is_fault_or_ok (rec.result))
    {
      uint32_t rec_size;
      if (! try_unserialize (uint32, th, &rec_size) || rec_size != size)
	diverged (th);

      uint8_t *readfds = user_readfds ? __builtin_alloca (size) : 0;
      uint8_t *writefds = user_writefds ? __builtin_alloca (size) : 0;
      uint8_t *exceptfds = user_exceptfds ? __builtin_alloca (size) : 0;

      if ((readfds && ! try_unserialize (uint8_array, th, readfds, size))
	  || (writefds && ! try_unserialize (uint8_array, th, writefds, size))
	  || (exceptfds && ! try_unserialize (uint8_array, th, exceptfds, size)))
	diverged (th);

      if ((copy_to_user_opt (th, user_readfds, readfds, size)
	   && copy_to_user_opt (th, user_writefds, writefds, size)
	   && copy_to_user_opt (th, user_exceptfds, exceptfds, size))
			!= (rec.result != ERI_EFAULT))
	diverged (th);
    }

  uint8_t timeout = !! (rec_flags & (psel ? ERI_SYSCALL_SELECT_TIMESPEC
					  : ERI_SYSCALL_SELECT_TIMEVAL));
  if (timeout && ! user_timeout) diverged (th);

  struct eri_timeval timeval;
  struct eri_timespec timespec;
  if (timeout && ! (psel ? try_unserialize (timespec, th, &timespec)
			 : try_unserialize (timeval, th, &timeval)))
    diverged (th);

  if (timeout)
    {
      if (psel)
	copy_obj_to_user (th, (struct eri_timespec *) user_timeout,
			  &timespec);
      else
	copy_obj_to_user (th, (struct eri_timeval *) user_timeout,
			  &timeval);
    }

  if (! io_in (th, rec.in)) diverged (th);
  syscall_leave (th, 1, rec.result);
}

DEFINE_SYSCALL (select) { syscall_do_select (SYSCALL_ARGS); }
DEFINE_SYSCALL (pselect6) { syscall_do_select (SYSCALL_ARGS); }

static uint8_t
syscall_poll_revents (struct thread *th, struct eri_pollfd *user_fds,
		      uint64_t nfds, uint64_t revents)
{
  int16_t z = 0;

  uint64_t i, j = 0, o = 0;
  for (i = 0; i < revents; ++i)
    {
      uint64_t idx;
      int16_t r;
      if (! try_unserialize (uint64, th, &idx)
	  || ! try_unserialize (int16, th, &r)) diverged (th);

      if (idx + 1 <= o || idx >= nfds) diverged (th);
      o = idx + 1;

      while (j < idx)
	if (! copy_obj_to_user (th, &user_fds[j++].revents, &z))
	  return 0;

      if (! copy_obj_to_user (th, &user_fds[j++].revents, &r))
	return 0;
    }

  while (j < nfds)
    if (! copy_obj_to_user (th, &user_fds[j++].revents, &z))
      return 0;

  return 1;
}

static eri_noreturn void
syscall_do_poll (SYSCALL_PARAMS)
{
  uint8_t ppol = (int32_t) regs->rax == __NR_ppoll;

  struct eri_pollfd *user_fds = (void *) regs->rdi;
  uint64_t nfds = regs->rsi;
  struct eri_timespec *user_tmo = ppol ? (void *) regs->rdx : 0;
  const eri_sigset_t *user_sig = ppol ? (void *) regs->r10 : 0;
  uint64_t sig_set_size = user_sig ? regs->r8 : 0;

  if (nfds > 1024 * 1024) syscall_leave (th, 0, ERI_EINVAL);

  if ((nfds && ! read_user (th, user_fds, sizeof *user_fds * nfds))
      || ! read_user_obj_opt (th, user_tmo))
    syscall_leave (th, 0, ERI_EFAULT);

  if (user_sig)
    {
      if (! read_user_obj (th, user_sig))
	syscall_leave (th, 0, ERI_EFAULT);
      if (sig_set_size != ERI_SIG_SETSIZE)
	syscall_leave (th, 0, ERI_EINVAL);
    }

  struct eri_syscall_res_in_record rec;
  if (! check_magic (th, ERI_SYSCALL_POLL_MAGIC)
      || ! try_unserialize (syscall_res_in_record, th, &rec)) diverged (th);

  if (eri_syscall_is_fault_or_ok (rec.result))
    {
      uint64_t revents;
      if (! try_unserialize (uint64, th, &revents)
	  || syscall_poll_revents (th, user_fds, nfds, revents)
		!= (rec.result != ERI_EFAULT)) diverged (th);
    }

  uint8_t res_tmo;
  if (! try_unserialize (uint8, th, &res_tmo) || (! user_tmo && res_tmo))
    diverged (th);

  if (res_tmo)
    {
      struct eri_timespec tmo;
      if (! try_unserialize (timespec, th, &tmo)) diverged (th);
      copy_obj_to_user (th, user_tmo, &tmo);
    }

  if (! io_in (th, rec.in)) diverged (th);
  syscall_leave (th, 1, rec.result);
}

DEFINE_SYSCALL (poll) { syscall_do_poll (SYSCALL_ARGS); }
DEFINE_SYSCALL (ppoll) { syscall_do_poll (SYSCALL_ARGS); }

DEFINE_SYSCALL (epoll_create) { syscall_do_res_io (th); }
DEFINE_SYSCALL (epoll_create1) { syscall_do_res_io (th); }

static eri_noreturn void
syscall_do_epoll_wait (SYSCALL_PARAMS)
{
  uint8_t pwait = (int32_t) regs->rax == __NR_epoll_pwait;

  struct eri_epoll_event *user_events = (void *) regs->rsi;
  int32_t max_events = regs->rdx;
  const eri_sigset_t *user_sig = pwait ? (void *) regs->r8 : 0;
  uint64_t sig_set_size = user_sig ? regs->r9 : 0;

  if (max_events <= 0
      || max_events > ERI_INT_MAX / sizeof (struct eri_epoll_event))
    syscall_leave (th, 0, ERI_EINVAL);

  if (user_sig)
    {
      if (! read_user_obj_opt (th, user_sig))
	syscall_leave (th, 0, ERI_EFAULT);
      if (sig_set_size != ERI_SIG_SETSIZE)
	syscall_leave (th, 0, ERI_EINVAL);
    }

  struct eri_syscall_res_in_record rec
	= syscall_do_fetch_res_in (th, ERI_SYSCALL_EPOLL_WAIT_MAGIC);

  if (eri_syscall_is_ok (rec.result) && rec.result > max_events)
    diverged (th);

  if (eri_syscall_is_fault_or_ok (rec.result))
    {
      uint64_t len = rec.result == ERI_EFAULT
			? 1 : eri_min (rec.result + 1, max_events);
      uint8_t done = 1;
      uint64_t i;
      for (i = 0; i < len && done; ++i)
	{
	  struct eri_epoll_event event;
	  if (! try_unserialize (uint8, th, &done)
	      || ! try_unserialize (epoll_event, th, &event)) diverged (th);

	  if (! copy_obj_to_user (th, user_events + i, &event))
	    {
	      if (rec.result == max_events) diverged (th);
	      else if (i < len - 1) diverged (th);
	    }
	}

      if (i != len || (rec.result == ERI_EFAULT && done)) diverged (th);
    }

  if (! io_in (th, rec.in)) diverged (th);
  syscall_leave (th, 1, rec.result);
  diverged (th);
}

DEFINE_SYSCALL (epoll_wait) { syscall_do_epoll_wait (SYSCALL_ARGS); }
DEFINE_SYSCALL (epoll_pwait) { syscall_do_epoll_wait (SYSCALL_ARGS); }

DEFINE_SYSCALL (epoll_ctl)
{
  struct eri_epoll_event *user_event = (void *) regs->r10;
  if (! read_user_obj_opt (th, user_event))
    syscall_leave (th, 0, ERI_EFAULT);

  syscall_do_res_io (th);
}

static uint8_t
syscall_get_read_data (struct thread *th, void *dst,
		       uint64_t total, uint8_t readv)
{
  struct thread_group *group = th->group;

  uint64_t buf_size = eri_min (total,
		eri_max (group->file_buf_size, group->page_size) * 2);
  uint8_t *buf = buf_size <= 1024 ? __builtin_alloca (buf_size)
		: eri_assert_mtmalloc (group->pool, buf_size);

  uint8_t res = 0;
  uint64_t off = 0, iov_off = 0, size;
  struct eri_iovec *iov = dst;

  while (1)
    {
      if (! try_unserialize (uint64, th, &size)) goto out;
      if (! size) break;

      if (off + size > total) goto out;

      uint64_t ser_off = 0;
      while (ser_off < size)
	{
	  uint64_t ser_size = eri_min (buf_size, size - ser_off);
	  if (! try_unserialize (uint8_array, th, buf, ser_size))
	    goto out;

	  if (! readv)
	    {
	      uint8_t *user = (uint8_t *) dst + off + ser_off;
	      if (! copy_to_user (th, user, buf, ser_size))
		goto out;
	    }
	  else
	    {
	      uint64_t o = 0;
	      while (o < ser_size)
		{
		  while (iov->len == 0) ++iov;

		  uint8_t *user = (uint8_t *) iov->base + iov_off;
		  uint64_t s = eri_min (iov->len - iov_off, ser_size - o);
		  if (! copy_to_user (th, user, buf + o, s)) goto out;

		  o += s;
		  if ((iov_off += s) == iov->len)
		    {
		      iov_off = 0;
		      ++iov;
		    }
		}
	    }
	  ser_off += ser_size;
	}

      off += size;
    }
  /* Live failed to record all data, must have something wrong.  */
  res = off == total;

out:
  if (buf_size > 1024) eri_assert_mtfree (group->pool, buf);
  return res;
}

static uint64_t
sum_iovec (struct eri_iovec *iov, int32_t n)
{
  uint64_t sum = 0;
  int32_t i;
  for (i = 0; i < n; ++i) sum += iov[i].len;
  return sum;
}

static uint8_t
syscall_read_data (struct thread *th, void *dst, uint8_t readv,
		uint64_t limit, struct eri_syscall_res_in_record *rec)
{
  if (! check_magic (th, ERI_SYSCALL_READ_MAGIC)
      || ! try_unserialize (syscall_res_in_record, th, rec))
    return 0;

  if (eri_syscall_is_error (rec->result) || rec->result == 0)
    return 1;

  if (rec->result > (readv ? sum_iovec (dst, limit) : limit))
    return 0;

  return syscall_get_read_data (th, dst, rec->result, readv);
}

static eri_noreturn void
syscall_do_read (SYSCALL_PARAMS)
{

  int32_t nr = regs->rax;
  struct eri_syscall_res_in_record rec;
  if (nr == __NR_read || nr == __NR_pread64
      || nr == __NR_getdents || nr == __NR_getdents64)
    {
      uint64_t buf = regs->rsi;
      uint64_t size = regs->rdx;
      eri_entry__test_invalidate (entry, &buf);
      if (! syscall_read_data (th, (void *) buf, 0, regs->rdx, &rec))
	diverged (th);

      if (rec.result == ERI_EFAULT) syscall_wipe (th, (void *) buf, size, 1);
    }
  else
    {
      struct eri_iovec *iov;
      int32_t iov_cnt;
      syscall_leave_if_error (th, 0, call_with_user_access (th, 1,
		eri_entry__syscall_get_rw_iov, entry, &iov, &iov_cnt));

      if (! syscall_read_data (th, iov, 1, iov_cnt, &rec))
	diverged (th);

      if (rec.result == ERI_EFAULT) syscall_wipe_iovec (th, iov, iov_cnt, 1);
      eri_entry__syscall_free_rw_iov (th->entry, iov);
    }
  if (! io_in (th, rec.in)) diverged (th);
  syscall_leave (th, 1, rec.result);
}

DEFINE_SYSCALL (read) { syscall_do_read (SYSCALL_ARGS); }
DEFINE_SYSCALL (pread64) { syscall_do_read (SYSCALL_ARGS); }
DEFINE_SYSCALL (readv) { syscall_do_read (SYSCALL_ARGS); }
DEFINE_SYSCALL (preadv) { syscall_do_read (SYSCALL_ARGS); }
DEFINE_SYSCALL (preadv2) { syscall_do_read (SYSCALL_ARGS); }

static eri_noreturn void
syscall_do_write (SYSCALL_PARAMS)
{
  int32_t nr = regs->rax;
  uint8_t writev = nr != __NR_write && nr != __NR_pwrite64;

  uint64_t buf = regs->rsi;
  struct eri_iovec *iov;
  int32_t iov_cnt;
  if (! writev) eri_entry__test_invalidate (entry, &buf);
  else syscall_leave_if_error (th, 0, call_with_user_access (th, 1,
		eri_entry__syscall_get_rw_iov, entry, &iov, &iov_cnt));

  struct eri_syscall_res_io_record rec;
  if (! check_magic (th, ERI_SYSCALL_RES_IO_MAGIC)
      || ! try_unserialize (syscall_res_io_record, th, &rec))
    goto div;
  if (! io_out (th, rec.out)) goto div;

  if (rec.res.result == ERI_EFAULT)
    {
      if (! writev) syscall_wipe (th, (void *) buf, regs->rdx, 0);
      else syscall_wipe_iovec (th, iov, iov_cnt, 0);
    }

  if (eri_syscall_is_error (rec.res.result) || rec.res.result == 0)
    goto out;

  if (rec.res.result > (writev ? sum_iovec (iov, iov_cnt) : regs->rdx))
    goto div;

  struct eri_access acc;
  if (! writev)
    {
      set_write (th, &acc, buf, rec.res.result);
      update_access (th, &acc, 1);
    }
  else
    {
      uint64_t c = 0;
      struct eri_iovec *v = iov;
      while (c < rec.res.result)
	{
	  uint64_t s = eri_min (v->len, rec.res.result - c);
	  set_write (th, &acc, (v++)->base, s);
	  update_access (th, &acc, 1);
	  c += s;
	}
    }

out:
  if (eri_syscall_is_ok (rec.res.result)
      && (regs->rdi == 1 || regs->rdi == 2))
    eri_entry__syscall (entry);

  if (writev) eri_entry__syscall_free_rw_iov (entry, iov);
  if (! io_in (th, rec.res.in)) diverged (th);
  syscall_leave (th, 1, rec.res.result);

div:
  if (writev) eri_entry__syscall_free_rw_iov (entry, iov);
  diverged (th);
}

DEFINE_SYSCALL (write) { syscall_do_write (SYSCALL_ARGS); }
DEFINE_SYSCALL (pwrite64) { syscall_do_write (SYSCALL_ARGS); }
DEFINE_SYSCALL (writev) { syscall_do_write (SYSCALL_ARGS); }
DEFINE_SYSCALL (pwritev) { syscall_do_write (SYSCALL_ARGS); }
DEFINE_SYSCALL (pwritev2) { syscall_do_write (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (fallocate)

SYSCALL_TO_IMPL (fsync)
SYSCALL_TO_IMPL (fdatasync)
SYSCALL_TO_IMPL (sync_file_range)

SYSCALL_TO_IMPL (readahead)
SYSCALL_TO_IMPL (sendfile)
SYSCALL_TO_IMPL (copy_file_range)
SYSCALL_TO_IMPL (splice)
SYSCALL_TO_IMPL (vmsplice)
SYSCALL_TO_IMPL (tee)

SYSCALL_TO_IMPL (io_setup)
SYSCALL_TO_IMPL (io_destroy)
SYSCALL_TO_IMPL (io_getevents)
SYSCALL_TO_IMPL (io_submit)
SYSCALL_TO_IMPL (io_cancel)

DEFINE_SYSCALL (lseek) { syscall_do_res_io (th); }

SYSCALL_TO_IMPL (ioctl)

static eri_noreturn void
syscall_do_stat (SYSCALL_PARAMS)
{
  int32_t nr = regs->rax;
  uint8_t at = nr == __NR_newfstatat;
  if (nr != __NR_fstat)
    {
      const char *user_path = (void *) (at ? regs->rsi : regs->rdi);
      syscall_leave_if_error (th, 0, syscall_read_user_path (th, user_path));
    }

  struct eri_stat *user_stat = (void *) (at ? regs->rdx : regs->rsi);

  struct eri_syscall_stat_record rec;
  if (! check_magic (th, ERI_SYSCALL_STAT_MAGIC)
      || ! try_unserialize (syscall_stat_record, th, &rec)) diverged (th);

  uint64_t res = rec.res.result;

  rec.stat.pad = 0;
  if (! syscall_copy_obj_to_user (th, res, user_stat, &rec.stat)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (stat) { syscall_do_stat (SYSCALL_ARGS); }
DEFINE_SYSCALL (fstat) { syscall_do_stat (SYSCALL_ARGS); }
DEFINE_SYSCALL (newfstatat) { syscall_do_stat (SYSCALL_ARGS); }
DEFINE_SYSCALL (lstat) { syscall_do_stat (SYSCALL_ARGS); }

DEFINE_SYSCALL (access) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (faccessat) { syscall_do_open (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (setxattr)
SYSCALL_TO_IMPL (fsetxattr)
SYSCALL_TO_IMPL (lsetxattr)
SYSCALL_TO_IMPL (getxattr)
SYSCALL_TO_IMPL (fgetxattr)
SYSCALL_TO_IMPL (lgetxattr)

SYSCALL_TO_IMPL (listxattr)
SYSCALL_TO_IMPL (flistxattr)
SYSCALL_TO_IMPL (llistxattr)

SYSCALL_TO_IMPL (removexattr)
SYSCALL_TO_IMPL (fremovexattr)
SYSCALL_TO_IMPL (lremovexattr)

DEFINE_SYSCALL (getdents) { syscall_do_read (SYSCALL_ARGS); }
DEFINE_SYSCALL (getdents64) { syscall_do_read (SYSCALL_ARGS); }

static eri_noreturn void
syscall_do_getcwd (struct thread *th, char *user_buf, uint64_t size)
{
  struct eri_syscall_res_in_record rec
	= syscall_do_fetch_res_in (th, ERI_SYSCALL_GETCWD_MAGIC);

  if (eri_syscall_is_non_fault_error (rec.result)) goto err;

  uint64_t len;
  if (! try_unserialize (uint64, th, &len) || len > size)
    diverged (th);

  uint8_t buf[1024];
  uint64_t c = 0;
  for (c = 0; c < len; c += sizeof buf)
    {
      uint64_t l = eri_min (len - c, sizeof buf);
      if (! try_unserialize (uint8_array, th, buf, l)) diverged (th);
      if (! copy_to_user (th, user_buf + c, buf, l)) break;
    }

  if ((c < len) != (rec.result == ERI_EFAULT)) diverged (th);

err:
  if (! io_in (th, rec.in)) diverged (th);
  syscall_leave (th, 1, rec.result);
}

DEFINE_SYSCALL (getcwd)
{
  syscall_do_getcwd (th, (void *) regs->rdi, regs->rsi);
}

DEFINE_SYSCALL (chdir)
{
  const char *user_path = (void *) regs->rdi;
  syscall_leave_if_error  (th, 0, syscall_read_user_path (th, user_path));
  syscall_do_res_io (th);
}

DEFINE_SYSCALL (fchdir) { syscall_do_res_io (th); }

static const char *
syscall_rename_get_oldpath (int32_t nr, struct eri_registers *regs)
{
  if (nr == __NR_rename || nr == __NR_link || nr == __NR_symlink
      || nr == __NR_symlinkat) return (void *) regs->rdi;
  else return (void *) regs->rsi;
}

static const char *
syscall_rename_get_newpath (int32_t nr, struct eri_registers *regs)
{
  if (nr == __NR_rename || nr == __NR_link || nr == __NR_symlink)
    return (void *) regs->rsi;
  else if (nr == __NR_symlinkat) return (void *) regs->rdx;
  else return (void *) regs->r10;
}

static eri_noreturn void
syscall_do_rename (SYSCALL_PARAMS)
{
  int32_t nr = regs->rax;
  const char *user_oldpath = syscall_rename_get_oldpath (nr, regs);
  const char *user_newpath = syscall_rename_get_newpath (nr, regs);

  syscall_leave_if_error (th, 0, syscall_read_user_path (th, user_oldpath));
  syscall_leave_if_error (th, 0, syscall_read_user_path (th, user_newpath));

  syscall_do_res_io (th);
}

DEFINE_SYSCALL (rename) { syscall_do_rename (SYSCALL_ARGS); }
DEFINE_SYSCALL (renameat) { syscall_do_rename (SYSCALL_ARGS); }
DEFINE_SYSCALL (renameat2) { syscall_do_rename (SYSCALL_ARGS); }

DEFINE_SYSCALL (mkdir) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (mkdirat) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (rmdir) { syscall_do_open (SYSCALL_ARGS); }

DEFINE_SYSCALL (link) { syscall_do_rename (SYSCALL_ARGS); }
DEFINE_SYSCALL (linkat) { syscall_do_rename (SYSCALL_ARGS); }

DEFINE_SYSCALL (unlink) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (unlinkat) { syscall_do_open (SYSCALL_ARGS); }

DEFINE_SYSCALL (symlink) { syscall_do_rename (SYSCALL_ARGS); }
DEFINE_SYSCALL (symlinkat) { syscall_do_rename (SYSCALL_ARGS); }

static eri_noreturn void
syscall_do_readlink (SYSCALL_PARAMS)
{
  uint8_t at = (int32_t) regs->rax == __NR_readlinkat;
  const char *user_path = (void *) (at ? regs->rsi : regs->rdi);

  syscall_leave_if_error (th, 0, syscall_read_user_path (th, user_path));

  char *user_buf = (void *) (at ? regs->rdx : regs->rsi);
  uint64_t size = at ? regs->r10 : regs->rdx;

  syscall_do_getcwd (th, user_buf, size);
}

DEFINE_SYSCALL (readlink) { syscall_do_readlink (SYSCALL_ARGS); }
DEFINE_SYSCALL (readlinkat) { syscall_do_readlink (SYSCALL_ARGS); }

DEFINE_SYSCALL (mknod) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (mknodat) { syscall_do_open (SYSCALL_ARGS); }

DEFINE_SYSCALL (umask) { syscall_do_res_io (th); }

DEFINE_SYSCALL (chmod) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (fchmod) { syscall_do_res_io (th); }
DEFINE_SYSCALL (fchmodat) { syscall_do_open (SYSCALL_ARGS); }

DEFINE_SYSCALL (chown) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (fchown) { syscall_do_res_io (th); }
DEFINE_SYSCALL (fchownat) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (lchown) { syscall_do_open (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (utime)
SYSCALL_TO_IMPL (utimes)
SYSCALL_TO_IMPL (futimesat)
SYSCALL_TO_IMPL (utimensat)

DEFINE_SYSCALL (ustat)
{
  struct eri_ustat *user_ustat = (void *) regs->rsi;

  struct eri_syscall_ustat_record rec;
  eri_memset (&rec.ustat, 0, sizeof rec.ustat);
  if (! check_magic (th, ERI_SYSCALL_USTAT_MAGIC)
      || ! try_unserialize (syscall_ustat_record, th, &rec)) diverged (th);

  uint64_t res = rec.res.result;

  if (! syscall_copy_obj_to_user (th, res, user_ustat, &rec.ustat)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

static eri_noreturn void
syscall_do_statfs (SYSCALL_PARAMS)
{
  struct eri_statfs *user_statfs = (void *) regs->rsi;

  struct eri_syscall_statfs_record rec;
  if (! check_magic (th, ERI_SYSCALL_STATFS_MAGIC)
      || ! try_unserialize (syscall_statfs_record, th, &rec)) diverged (th);

  eri_memset (rec.statfs.spare, 0, sizeof rec.statfs.spare);

  uint64_t res = rec.res.result;
  if (! syscall_copy_obj_to_user (th, res, user_statfs, &rec.statfs)
      || ! io_in (th, rec.res.in)) diverged (th);

  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (statfs)
{
  const char *user_path = (void *) regs->rdi;
  syscall_leave_if_error (th, 0, syscall_read_user_path (th, user_path));

  syscall_do_statfs (SYSCALL_ARGS);
}

DEFINE_SYSCALL (fstatfs) { syscall_do_statfs (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (sysfs)
SYSCALL_TO_IMPL (sync)
SYSCALL_TO_IMPL (syncfs)

SYSCALL_TO_IMPL (mount)
SYSCALL_TO_IMPL (umount2)

DEFINE_SYSCALL (chroot) { syscall_do_no_sys (th); }
DEFINE_SYSCALL (pivot_root) { syscall_do_no_sys (th); }

static uint8_t
mm_wait (struct thread *th, uint64_t exp)
{
  return version_wait (th, &th->group->mm, exp);
}

static void
mm_update (struct thread *th)
{
  version_update (th, &th->group->mm);
}

static uint64_t
syscall_mm_enter (struct thread *th, uint16_t magic)
{
  struct eri_syscall_res_in_record rec
			= syscall_do_fetch_res_in (th, magic);
  if (! mm_wait (th, rec.in)) diverged (th);
  return rec.result;
}

static eri_noreturn void
syscall_mm_leave (struct thread *th, uint64_t res)
{
  mm_update (th);
  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (mmap)
{
  uint64_t len = regs->rsi;
  if (! len) syscall_leave (th, 0, ERI_EINVAL);

  uint64_t res  = syscall_mm_enter (th, ERI_SYSCALL_MMAP_MAGIC);
  if (eri_syscall_is_error (res)) goto out;

  int32_t prot = regs->rdx;
  int32_t flags = regs->r10;
  uint8_t anony = !! (flags & ERI_MAP_ANONYMOUS);

  if (! anony) prot |= ERI_PROT_READ;
  prot = eri_common_get_mem_prot (prot);

  uint64_t id;
  if (! try_unserialize (uint64, th, &id) || (anony && id)) diverged (th);

  int32_t fd = -1;
  if (! anony)
    {
      uint8_t ok;
      if (! try_unserialize (uint8, th, &ok) || ! ok) diverged (th);

      if ((fd = open_mmap_file (th->group->path, id)) == -1) diverged (th);
    }

  /* XXX: flags */
  flags = (flags & ~(ERI_MAP_TYPE | ERI_MAP_GROWSDOWN))
	  | ERI_MAP_PRIVATE | ERI_MAP_FIXED;
  uint8_t err = eri_syscall_is_error (
			eri_syscall (mmap, res, len, prot, flags, fd, 0));
  if (! anony) eri_assert_syscall (close, fd);

  if (err) diverged (th);

  struct eri_access acc = { res, len, ERI_ACCESS_WRITE };
  update_access (th, &acc, 1);

  update_mm_prot (th, res, len, prot);

out:
  syscall_mm_leave (th, res);
}

DEFINE_SYSCALL (mprotect)
{
  uint64_t res = syscall_mm_enter (th, ERI_SYSCALL_RES_IN_MAGIC);
  if (eri_syscall_is_error (res)) goto out;

  uint64_t addr = regs->rdi;
  uint64_t len = regs->rsi;
  int32_t prot = eri_common_get_mem_prot (regs->rdx);
  if (eri_syscall_is_error (
		eri_syscall (mprotect, addr, len, prot))) diverged (th);

  update_mm_prot (th, addr, len, prot);

out:
  syscall_mm_leave (th, res);
}

DEFINE_SYSCALL (munmap)
{
  uint64_t res = syscall_mm_enter (th, ERI_SYSCALL_RES_IN_MAGIC);
  if (eri_syscall_is_error (res)) goto out;

  if (eri_syscall_is_error (eri_entry__syscall (entry))) diverged (th);

  update_mm_prot (th, regs->rdi, regs->rsi, 0);

out:
  syscall_mm_leave (th, res);
}

DEFINE_SYSCALL (mremap)
{
  uint64_t old_address = regs->rdi;
  uint64_t old_size = regs->rsi;
  uint64_t new_size = regs->rdx;

  uint64_t res = syscall_mm_enter (th, ERI_SYSCALL_RES_IN_MAGIC);
  /* XXX: may also indicate something */
  if (eri_syscall_is_error (res)) goto out;

  int32_t flags = res == old_address
			? 0 : ERI_MREMAP_MAYMOVE | ERI_MREMAP_FIXED;

  if (eri_syscall_is_error (eri_syscall (mremap, old_address, old_size,
					 new_size, flags, res)))
    diverged (th);

  if (eri_enable_analyzer)
    {
      struct eri_range old_range = { old_address, old_address + old_size };
      struct eri_range new_range = { res, new_size };
      eri_analyzer__update_mm_remap (th->analyzer, old_range, new_range);

      struct eri_access acc = { res, new_size, ERI_ACCESS_WRITE };
      update_access (th, &acc, 1);
    }

out:
  syscall_mm_leave (th, res);
}

DEFINE_SYSCALL (madvise) { syscall_do_res_io (th); }

DEFINE_SYSCALL (brk)
{
  uint64_t res = syscall_mm_enter (th, ERI_SYSCALL_RES_IN_MAGIC);

  struct thread_group *group = th->group;
  uint64_t old = eri_round_up (group->brk, group->page_size);
  uint64_t now = eri_round_up (res, group->page_size);

  if (old < now && eri_syscall_is_error (
	eri_syscall (mmap, old, now - old,
		ERI_PROT_READ | ERI_PROT_WRITE | ERI_PROT_EXEC,
		ERI_MAP_PRIVATE | ERI_MAP_FIXED | ERI_MAP_ANONYMOUS, -1, 0)))
    diverged (th);
  if (old > now && eri_syscall_is_error (
				eri_syscall (munmap, now, old - now)))
    diverged (th);

  group->brk = res;
  syscall_mm_leave (th, res);
}

SYSCALL_TO_IMPL (msync)
SYSCALL_TO_IMPL (mincore)
SYSCALL_TO_IMPL (mlock)
SYSCALL_TO_IMPL (mlock2)
SYSCALL_TO_IMPL (mlockall)
SYSCALL_TO_IMPL (munlock)
SYSCALL_TO_IMPL (munlockall)

SYSCALL_TO_IMPL (modify_ldt)
SYSCALL_TO_IMPL (swapon)
SYSCALL_TO_IMPL (swapoff)

static uint64_t
syscall_futex_check_wait (struct thread *th, uint64_t user_addr,
			  const struct eri_timespec *user_timeout)
{
  return eri_syscall_futex_check_user_addr (user_addr, page_size (th))
		? : (! read_user_obj_opt (th, user_timeout) ? ERI_EFAULT : 0);
}

static uint64_t
syscall_fetch_futex_record (struct thread *th,
			    struct eri_syscall_futex_record *rec)
{
  if (! check_magic (th, ERI_SYSCALL_FUTEX_MAGIC)
      || ! try_unserialize (syscall_futex_record, th, rec)) diverged (th);
  return rec->res.result;
}

static uint8_t
syscall_futex_load_user (struct thread *th, uint64_t user_addr,
			 struct eri_atomic_record *rec, uint64_t res)
{
  if (! rec->ok)
    return ! read_user (th, user_addr, sizeof (int32_t)) && res == ERI_EFAULT;

  if (! atomic_wait (th, user_addr, sizeof (int32_t), rec->ver)
      || ! read_user (th, user_addr, sizeof (int32_t))) return 0;

  atomic_update (th, user_addr, sizeof (int32_t));
  return 1;
}

static eri_noreturn void
syscall_do_futex_wait (SYSCALL_PARAMS)
{
  uint64_t user_addr = regs->rdi;
  uint32_t op = regs->rsi;
  const struct eri_timespec *user_timeout = (void *) regs->r10;
  uint32_t mask = (op & ERI_FUTEX_CMD_MASK) == ERI_FUTEX_WAIT ? -1 : regs->r9;

  syscall_leave_if_error (th, 0,
	syscall_futex_check_wait (th, user_addr, user_timeout));

  if (! mask) syscall_leave (th, 0, ERI_EINVAL);

  struct eri_syscall_futex_record rec;
  uint64_t res = syscall_fetch_futex_record (th, &rec);

  if (! syscall_futex_load_user (th, user_addr, &rec.atomic, res))
    diverged (th);

  if (! io_in (th, rec.res.in)) diverged (th);
  syscall_leave (th, 1, res);
}

static eri_noreturn void
syscall_do_futex_wake (SYSCALL_PARAMS)
{
  uint64_t user_addr = regs->rdi;
  uint32_t op = regs->rsi;
  uint32_t mask = (op & ERI_FUTEX_CMD_MASK) == ERI_FUTEX_WAKE ? -1 : regs->r9;

  syscall_leave_if_error (th, 0,
	eri_syscall_futex_check_wake (op, mask, user_addr, page_size (th)));

  syscall_do_res_in (th);
}

static eri_noreturn void
syscall_do_futex_requeue (SYSCALL_PARAMS)
{
  uint64_t user_addr[] = { regs->rdi, regs->r8 };
  uint32_t op = regs->rsi;

  syscall_leave_if_error (th, 0,
	eri_syscall_futex_check_wake2 (op, -1, user_addr, page_size (th)));

  struct eri_syscall_futex_requeue_record rec;
  if (! check_magic (th, ERI_SYSCALL_FUTEX_REQUEUE_MAGIC)
      || ! try_unserialize (syscall_futex_requeue_record, th, &rec))
    diverged (th);

  uint64_t res = rec.res.result;

  if (rec.cmp
      && ! syscall_futex_load_user (th, user_addr[0], &rec.atomic, res))
    diverged (th);

  if (! io_in (th, rec.res.in)) diverged (th);
  syscall_leave (th, 1, res);
}

static eri_noreturn void
syscall_do_futex_wake_op (SYSCALL_PARAMS)
{
  uint64_t user_addr[] = { regs->rdi, regs->r8 };
  uint32_t op = regs->rsi;
  int32_t val3 = regs->r9;

  syscall_leave_if_error (th, 0,
	eri_syscall_futex_check_wake2 (op, -1, user_addr, page_size (th)));

  uint8_t op_op = eri_futex_op_get_op (val3);
  uint8_t op_cmp = eri_futex_op_get_cmp (val3);
  int32_t op_arg = eri_futex_op_get_arg (val3);

  if (op_op >= ERI_FUTEX_OP_NUM || op_cmp >= ERI_FUTEX_OP_CMP_NUM)
    syscall_leave (th, 0, ERI_ENOSYS);

  struct eri_syscall_futex_record rec;
  uint64_t res = syscall_fetch_futex_record (th, &rec);

  int32_t old;
  if (! do_atomic (th, eri_syscall_futex_atomic_code_from_wake_op (op_op),
		   (void *) user_addr[1], sizeof (int32_t),
		   op_op == ERI_FUTEX_OP_ANDN ? ~op_arg : op_arg,
		   &rec.atomic, &old, 0)) diverged (th);

  if (! rec.atomic.ok && res != ERI_EFAULT) diverged (th);

  if (! io_in (th, rec.res.in)) diverged (th);
  syscall_leave (th, 1, res);
}

DEFINE_SYSCALL (futex)
{
  int32_t op = regs->rsi;

  switch (op & ERI_FUTEX_CMD_MASK)
    {
    case ERI_FUTEX_WAIT:
    case ERI_FUTEX_WAIT_BITSET: syscall_do_futex_wait (SYSCALL_ARGS);
    case ERI_FUTEX_WAKE:
    case ERI_FUTEX_WAKE_BITSET: syscall_do_futex_wake (SYSCALL_ARGS);
    case ERI_FUTEX_REQUEUE:
    case ERI_FUTEX_CMP_REQUEUE: syscall_do_futex_requeue (SYSCALL_ARGS);
    case ERI_FUTEX_WAKE_OP: syscall_do_futex_wake_op (SYSCALL_ARGS);
    case ERI_FUTEX_LOCK_PI:
    case ERI_FUTEX_TRYLOCK_PI:
    case ERI_FUTEX_UNLOCK_PI:
    case ERI_FUTEX_WAIT_REQUEUE_PI:
    case ERI_FUTEX_CMP_REQUEUE_PI:
    default: syscall_leave (th, 0, ERI_ENOSYS);
    }
}

DEFINE_SYSCALL (set_robust_list) { syscall_do_no_sys (th); }
DEFINE_SYSCALL (get_robust_list) { syscall_do_no_sys (th); }

SYSCALL_TO_IMPL (pkey_mprotect)
SYSCALL_TO_IMPL (pkey_alloc)
SYSCALL_TO_IMPL (pkey_free)

SYSCALL_TO_IMPL (membarrier)

SYSCALL_TO_IMPL (mbind)
SYSCALL_TO_IMPL (set_mempolicy)
SYSCALL_TO_IMPL (get_mempolicy)
SYSCALL_TO_IMPL (migrate_pages)
SYSCALL_TO_IMPL (move_pages)

SYSCALL_TO_IMPL (shmget)
SYSCALL_TO_IMPL (shmat)
SYSCALL_TO_IMPL (shmctl)
SYSCALL_TO_IMPL (shmdt)

SYSCALL_TO_IMPL (semget)
SYSCALL_TO_IMPL (semop)
SYSCALL_TO_IMPL (semtimedop)
SYSCALL_TO_IMPL (semctl)

SYSCALL_TO_IMPL (msgget)
SYSCALL_TO_IMPL (msgsnd)
SYSCALL_TO_IMPL (msgrcv)
SYSCALL_TO_IMPL (msgctl)

SYSCALL_TO_IMPL (mq_open)
SYSCALL_TO_IMPL (mq_unlink)
SYSCALL_TO_IMPL (mq_timedsend)
SYSCALL_TO_IMPL (mq_timedreceive)
SYSCALL_TO_IMPL (mq_notify)
SYSCALL_TO_IMPL (mq_getsetattr)

SYSCALL_TO_IMPL (add_key)
SYSCALL_TO_IMPL (request_key)
SYSCALL_TO_IMPL (keyctl)

SYSCALL_TO_IMPL (vhangup)

SYSCALL_TO_IMPL (reboot)
SYSCALL_TO_IMPL (kexec_load)
SYSCALL_TO_IMPL (kexec_file_load)

SYSCALL_TO_IMPL (iopl)
SYSCALL_TO_IMPL (ioperm)

SYSCALL_TO_IMPL (init_module)
SYSCALL_TO_IMPL (finit_module)
SYSCALL_TO_IMPL (delete_module)

SYSCALL_TO_IMPL (lookup_dcookie)

SYSCALL_TO_IMPL (process_vm_readv)
SYSCALL_TO_IMPL (process_vm_writev)

DEFINE_SYSCALL (remap_file_pages) { syscall_do_no_sys (th); }

static eri_noreturn void
syscall (struct thread *th)
{
  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);

  eri_log (th->log.file, "%lu %lx\n", regs->rax, regs->rip);

  switch (regs->rax)
    {
#define SYSCALL_CASE(name) \
  case ERI_PASTE (__NR_, name):						\
    ERI_PASTE (syscall_, name) (th, entry, regs);

    ERI_SYSCALLS (SYSCALL_CASE)
    default: syscall_leave (th, 0, ERI_ENOSYS);
    }
}

static eri_noreturn void
sync_async (struct thread *th)
{
  uint64_t steps;
  if (! check_magic (th, ERI_SYNC_ASYNC_MAGIC)
      || ! try_unserialize (uint64, th, &steps)) diverged (th);

  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);

  if (test_fetch_mark (th, fetch_mark (th)) == ERI_ASYNC_RECORD)
    {
      if (regs->rflags & ERI_RFLAGS_TF) set_async_signal (th);
      else
	{
	  th->sync_async_trace = 1;
	  th->sync_async_trace_steps = steps;
	  /* XXX: this can be slow with large repeats... */
	  regs->rflags |= ERI_RFLAGS_TF;
	}
    }

  eri_entry__leave (entry);
}

static eri_noreturn void
atomic (struct thread *th)
{
  struct eri_entry *entry = th->entry;
  uint16_t code = eri_entry__get_op_code (entry);
  struct eri_registers *regs = eri_entry__get_regs (entry);

  uint64_t old;

  struct eri_atomic_record rec;
  if (! check_magic (th, ERI_ATOMIC_MAGIC)
      || ! try_unserialize (atomic_record, th, &rec)
      || ! do_atomic (th, code, (void *) eri_entry__get_atomic_mem (entry),
		      eri_entry__get_atomic_size (entry),
		      eri_entry__get_atomic_val (entry), &rec,
		      code == ERI_OP_ATOMIC_CMPXCHG ? &regs->rax : &old,
		      &regs->rflags)) diverged (th);

  fetch_test_async_signal (th);
  eri_entry__atomic_leave (entry, old);
}

static uint64_t
hash_regs (eri_file_t log, struct eri_registers *regs)
{
  if (eri_global_enable_debug >= 9 || eri_global_enable_debug == 7)
    {
#define LOG_GPREG(creg, reg) \
  eri_log (log, ERI_STR (reg) " %lx\n", regs->reg);
      ERI_FOREACH_GPREG (LOG_GPREG)
      eri_log (log, "rflags %lx\n", regs->rflags & ERI_RFLAGS_STATUS_MASK);
      eri_log (log, "rip %lx\n", regs->rip);
    }

  return eri_hashs (
#define HASH_GPREG(creg, reg)	regs->reg,
	ERI_FOREACH_GPREG (HASH_GPREG)
	regs->rflags & ERI_RFLAGS_STATUS_MASK, regs->rip);
}

static eri_noreturn void
main_entry (struct eri_entry *entry)
{
  struct thread *th = eri_entry__get_th (entry);
  uint16_t code = eri_entry__get_op_code (entry);
  eri_log (th->log.file, "%u %lx\n", code,
	   hash_regs (th->log.file, eri_entry__get_regs (entry)));
  if (code == ERI_OP_SYSCALL) syscall (th);
  else if (code == ERI_OP_SYNC_ASYNC) sync_async (th);
  else if (eri_op_is_pub_atomic (code)) atomic (th);
  else eri_assert_unreachable ();
}

#define SIG_FETCH_ASYNC	ERI_NSIG

static uint64_t
fetch_async_sig_info (struct thread *th, struct eri_siginfo *info,
		      int32_t *sig)
{
  uint64_t in;
  if (! try_unserialize (uint64, th, &in)
      || ! try_unserialize (siginfo, th, info) || eri_si_sync (info))
    diverged (th);
  *sig = info->sig;
  return in;
}

static eri_noreturn void
sig_action (struct eri_entry *entry)
{
  struct thread *th = eri_entry__get_th (entry);
  eri_log (th->log.file, "\n");
  struct eri_siginfo *info = eri_entry__get_sig_info (entry);
  int32_t sig = info->sig;

  if (sig == SIG_FETCH_ASYNC
      && ! io_in (th, fetch_async_sig_info (th, info, &sig)))
    diverged (th);
  if (eri_si_sync (info) && ! check_magic (th, ERI_SIGNAL_MAGIC))
    diverged (th);

  if (sig == 0) check_exit (th);

  if (eri_si_sync (info) && eri_sig_set_set (&th->sig_mask, sig))
    check_exit (th);

  struct eri_sig_act act;
  if (! try_unserialize (sig_act, th, &act)) diverged (th);

  if (act.type == ERI_SIG_ACT_LOST)
    {
      eri_log_info (th->log.file, "lost SIGTRAP\n");
      eri_entry__clear_signal (entry);
      fetch_test_async_signal (th);
      eri_entry__leave (entry);
    }

  if (act.type == ERI_SIG_ACT_IGNORE || act.type > ERI_SIG_ACT_NUM
      || act.type != eri_sig_digest_act (info, &act.act))
    {
      eri_log_info (th->log.file, "inconsistent sig_act detected\n");
      diverged (th);
    }

  if (! version_wait (th, th->group->sig_acts + sig - 1, act.ver))
    diverged (th);

  if (eri_sig_act_internal_act (&act)) check_exit (th);

  eri_log (th->log.file, "%u %lx\n", sig,
	   hash_regs (th->log.file, eri_entry__get_regs (entry)));

  if (! call_with_user_access (th,
			ERI_ENTRY__MAX_SETUP_USER_FRAME_USER_ACCESS,
			eri_entry__setup_user_frame, entry, &act.act,
			&th->sig_alt_stack, &th->sig_mask))
    check_exit (th);

  eri_entry__clear_signal (entry);
  eri_set_sig_mask (&th->sig_mask, &act.act.mask);

  fetch_test_async_signal (th);
  eri_entry__leave (entry);
}

static uint8_t
handle_signal (struct eri_siginfo *info, struct eri_ucontext *ctx,
	       struct thread *th)
{
  int32_t sig = info->sig;
  if (eri_global_enable_debug >= 3)
    eri_log_info (th->log.file, "sig %u, info %lx, fault.addr %lx, "
	"rip %lx, rip - base %lx, rax %lx, rbx %lx, rcx %lx, rdx %lx, "
	"rsi %lx, rdi %lx, rbp %lx, rsp %lx, r8 %lx, r9 %lx, r10 %lx, "
	"r11 %lx, r12 %lx r13 %lx, r14 %lx, r15 %lx, rflags %lx\n",
	sig, info, info->fault.addr,
	ctx->mctx.rip, ctx->mctx.rip - th->group->base,
        ctx->mctx.rax, ctx->mctx.rbx, ctx->mctx.rcx, ctx->mctx.rdx,
	ctx->mctx.rsi, ctx->mctx.rdi, ctx->mctx.rbp, ctx->mctx.rsp,
	ctx->mctx.r8, ctx->mctx.r9, ctx->mctx.r10, ctx->mctx.r11,
	ctx->mctx.r12, ctx->mctx.r13, ctx->mctx.r14, ctx->mctx.r15,
	ctx->mctx.rflags);
  else if (eri_global_enable_debug >= 1)
    eri_log_info (th->log.file, "sig %u, info %lx, fault.addr %lx, "
	"rip %lx, rip - base %lx, rax %lx\n",
	sig, info, info->fault.addr,
	ctx->mctx.rip, ctx->mctx.rip - th->group->base, ctx->mctx.rax);


  if (info->code == ERI_SI_TKILL && info->kill.pid == th->group->pid)
    info->sig = SIG_FETCH_ASYNC;
  else if (! eri_si_sync (info)) return 0;

  struct eri_entry *entry = th->entry;
  uint16_t code = eri_entry__get_op_code (entry);
  if (eri_si_single_step (info))
    {
      if (eri_entry__sig_test_clear_single_step (entry, ctx->mctx.rip))
	return 0;

      if (code == ERI_OP_SYNC_ASYNC && th->sync_async_trace)
	{
	  if (th->sync_async_trace_steps
		? --th->sync_async_trace_steps
		: ctx->mctx.rip == eri_entry__get_regs (entry)->rip)
	    return 0;

	  th->sync_async_trace_steps = 0;
	  ctx->mctx.rflags &= ~ERI_RFLAGS_TF;
	  info->sig = SIG_FETCH_ASYNC;
	}
    }

  if (eri_entry__sig_is_access_fault (entry, info))
    {
      if (eri_op_is_pub_atomic (code))
	eri_entry__set_signal (entry, info, ctx);

      eri_entry__sig_access_fault (entry, &ctx->mctx, info->fault.addr);
      return 0;
    }

  if (eri_si_sync (info))
    eri_assert (! eri_within (&th->group->map_range, ctx->mctx.rip));

  eri_entry__sig_set_test_op_ret (th->entry,
		eri_struct_of (info, struct eri_sigframe, info));
  return 1;
}

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  struct thread *th = *(void **) ctx->stack.sp;
  if (eri_enable_analyzer)
    {
      struct eri_analyzer__sig_handler_args args = {
	th->analyzer, info, ctx, (void *) handle_signal, th
      };
      eri_analyzer__sig_handler (&args);
    }
  else handle_signal (info, ctx, th);
}
