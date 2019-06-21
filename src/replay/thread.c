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
  struct eri_lock lock;
  uint64_t ver;
  uint8_t dead_locked;
  ERI_LST_NODE_FIELDS (version_waiter)
};

struct version
{
  struct eri_lock lock;
  uint64_t ver;

  ERI_LST_NODE_FIELDS (version)
  ERI_LST_LIST_FIELDS (version_waiter)
};

struct version_activity
{
  uint64_t count;

  struct eri_lock lock;
  ERI_LST_LIST_FIELDS (version)
};

ERI_DEFINE_LIST (static, version_waiter,
		 struct version, struct version_waiter)
ERI_DEFINE_LIST (static, version, struct version_activity, struct version)

static void
version_init (struct version *ver)
{
  eri_init_lock (&ver->lock, 0);
  ver->ver = 0;
  ERI_LST_INIT_LIST (version_waiter, ver);
}

static void
version_activity_init (struct version_activity *act)
{
  act->count = 1;
  eri_init_lock (&act->lock, 0);
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

  uint64_t page_size;
  struct eri_range map_range;

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

  struct eri_lock exit_lock;
  uint64_t thread_count;

  int32_t user_pid;

  struct version io;

  uint64_t brk;
  struct version mm;

  struct version freeze;
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

  int32_t *clear_user_tid;
  int32_t user_tid;

  struct eri_sigset sig_mask;
  struct eri_stack sig_alt_stack;

  eri_aligned16 uint8_t sig_stack[THREAD_SIG_STACK_SIZE];
  eri_aligned16 uint8_t stack[0];
};

static uint8_t
version_wait (struct thread *th, struct version *ver, uint64_t exp)
{
  if (eri_atomic_load (&ver->ver, 0) >= exp) return 1;

  eri_assert_lock (&ver->lock);
  if (ver->ver >= exp)
    {
      eri_assert_unlock (&ver->lock);
      return 1;
    }

  struct version_activity *act = &th->group->ver_act;

  struct version_waiter waiter = { ERI_INIT_LOCK (1), exp, 0 };
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
  if (waiter.dead_locked)
    eri_log_info (th->log.file, "dead lock detected\n");
  return ! waiter.dead_locked;
}

static void
version_update (struct thread *th, struct version *ver)
{
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

static struct thread_group *
create_group (const struct eri_replay_rtld_args *rtld_args)
{
  struct eri_mtpool *pool = eri_init_mtpool_from_buf (
				rtld_args->buf, rtld_args->buf_size, 1);
  struct thread_group *group
			= eri_assert_malloc (&pool->pool, sizeof *group);
  group->pool = pool;

  group->page_size = rtld_args->page_size;
  group->map_range = rtld_args->map_range;
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

  if (eri_enable_analyzer)
    {
      struct eri_analyzer_group__create_args args = {
        group->pool, &group->map_range, group->log, group->page_size,
	group->file_buf_size, 64 /* XXX parameterize */, &group->pid
      };
      group->analyzer_group = eri_analyzer_group__create (&args);
    }

  group->pid = eri_assert_syscall (getpid);

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

  eri_init_lock (&group->exit_lock, 0);
  group->thread_count = 1;

  version_init (&group->io);
  version_init (&group->mm);
  version_init (&group->freeze);
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

static eri_noreturn void exit (struct thread *th);

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
	group->analyzer_group, pth ? pth->analyzer : 0,
	id, th->entry, &th->tid, exit, th
      };
      th->analyzer = eri_analyzer__create (&args);
    }

  th->file_buf = file_buf;
  th->file = file;
  th->marks = 0;

  th->alive = 1;
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

#define diverged(th, local) \
  do {									\
    struct thread *_th = th;						\
    uint8_t _local = local;						\
    if (! eri_enable_analyzer) eri_assert_unreachable ();		\
    if (_local)								\
      eri_lassert (_th->log.file,					\
		   ! version_wait (_th, &_th->group->freeze, 1));	\
    eri_log_info (_th->log.file, "diverged\n");				\
    eri_analyzer__exit_group (_th->analyzer);				\
  } while (0)

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
  if (! try_unserialize_mark (th, &mark)) diverged (th, 1);
  return mark;
}

static void
set_async_signal (struct thread *th)
{
  eri_assert_syscall (tgkill, th->group->pid, th->tid, ERI_SIGRTMIN);
}

static eri_noreturn void
start (struct thread *th, uint8_t next)
{
  struct eri_stack st = {
    (uint64_t) th->sig_stack, ERI_SS_AUTODISARM, THREAD_SIG_STACK_SIZE
  };
  eri_assert_syscall (sigaltstack, &st, 0);

  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_GS, th->entry);

  if ((next != (uint8_t) -1 ? next : fetch_mark (th)) == ERI_ASYNC_RECORD)
    set_async_signal (th);
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
  start (th, next);
}

eri_noreturn void
eri_replay_start (struct eri_replay_rtld_args *rtld_args)
{
  eri_global_enable_debug = rtld_args->debug;
  eri_debug ("%lx, %lx, %u\n",
	     rtld_args->map_range.start, rtld_args->buf, rtld_args->buf_size);
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
  if (fetch_mark (th) == ERI_ASYNC_RECORD) set_async_signal (th);
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
  copy_to_user (th, dst, src, sizeof *(dst))
#define copy_obj_to_user_or_fault(th, dst, src) \
  (copy_obj_to_user (th, dst, src) ? 0 : ERI_EFAULT)

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
    eri_set_read (acc, (uint64_t) mem, eri_min (done + 1, size));
  if (type & WRITE)
    eri_set_write (acc + 1, (uint64_t) mem, eri_min (done + 1, size));
  update_access (th, acc, eri_length_of (acc));
  return done == size;
}

#define read_user(th, src, size)	access_user (th, src, size, READ)
#define write_user(th, dst, size)	access_user (th, dst, size, WRITE)
#define read_write_user(th, mem, size) \
  access_user (th, mem, size, READ | WRITE)

#define read_obj_from_user(th, obj)	read_user (th, obj, sizeof *(obj))

static uint8_t
read_str_from_user (struct thread *th, const char *str,
		    uint64_t max, uint64_t *len)
{
  eri_assert (max);

  struct eri_entry *entry = th->entry;
  struct eri_access acc;
  uint64_t done;

  if (! eri_entry__test_access (entry, str, &done))
    {
      eri_set_read (&acc, (uint64_t) str, done + 1);
      update_access (th, &acc, 1);
      return 0;
    }

  uint64_t i;
  for (i = 0; i < max && str[i]; ++i) continue;
  eri_entry__reset_test_access (entry);

  if (len) *len = i;
  eri_set_read (&acc, (uint64_t) str, eri_min (i + 1, max));
  update_access (th, &acc, 1);
  return 1;
}

static uint8_t
do_atomic_wait (struct thread *th, uint64_t slot, uint64_t ver)
{
  struct thread_group *group = th->group;
  uint64_t idx = eri_atomic_hash (slot, group->atomic_table_size);
  return version_wait (th, group->atomic_table + idx, ver);
}

static uint8_t
atomic_wait (struct thread *th,
	     uint64_t mem, uint8_t size, struct eri_pair ver)
{
  return do_atomic_wait (th, eri_atomic_slot (mem), ver.first)
	 && (! eri_atomic_cross_slot (mem, size) ? 1 : do_atomic_wait (th,
				  eri_atomic_slot2 (mem, size), ver.second));
}

static void
do_atomic_updated (struct thread *th, uint64_t slot)
{
  struct thread_group *group = th->group;
  uint64_t idx = eri_atomic_hash (slot, group->atomic_table_size);
  version_update (th, group->atomic_table + idx);
}

static void
atomic_updated (struct thread *th, uint64_t mem, uint8_t size)
{
  do_atomic_updated (th, eri_atomic_slot (mem));
  if (eri_atomic_cross_slot (mem, size))
    do_atomic_updated (th, eri_atomic_slot2 (mem, size));
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

static uint64_t
syscall_fetch_result (struct thread *th)
{
  uint64_t res;
  if (! check_magic (th, ERI_SYSCALL_RESULT_MAGIC)
      || ! try_unserialize (uint64, th, &res)) diverged (th, 1);
  return res;
}

static uint64_t
syscall_fetch_in (struct thread *th)
{
  uint64_t in;
  if (! check_magic (th, ERI_SYSCALL_IN_MAGIC)
      || ! try_unserialize (uint64, th, &in)) diverged (th, 1);
  return in;
}

static void
syscall_fetch_out (struct thread *th)
{
  uint64_t out;
  if (! check_magic (th, ERI_SYSCALL_OUT_MAGIC)
      || ! try_unserialize (uint64, th, &out)) diverged (th, 1);
  if (! io_out (th, out)) diverged (th, 0);
}

static struct eri_syscall_res_in_record
syscall_do_fetch_res_in (struct thread *th, uint16_t magic)
{
  struct eri_syscall_res_in_record rec;
  if (! check_magic (th, magic)
      || ! try_unserialize (syscall_res_in_record, th, &rec))
    diverged (th, 1);
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
      || ! try_unserialize (syscall_res_io_record, th, &rec))
    diverged (th, 1);
  if (! io_out (th, rec.out)) diverged (th, 0);

  struct eri_syscall_res_in_record res = { rec.result, rec.in };
  return res;
}

static eri_noreturn void
syscall_do_res_in (struct thread *th)
{
  struct eri_syscall_res_in_record rec = syscall_fetch_res_in (th);
  if (! io_in (th, rec.in)) diverged (th, 0);
  syscall_leave (th, 1, rec.result);
}

static eri_noreturn void
syscall_do_res_io (struct thread *th)
{
  struct eri_syscall_res_in_record rec = syscall_fetch_res_io (th);
  if (! io_in (th, rec.in)) diverged (th, 0);
  syscall_leave (th, 1, rec.result);
}

DEFINE_SYSCALL (clone)
{
  struct eri_syscall_clone_record rec;
  if (! check_magic (th, ERI_SYSCALL_CLONE_MAGIC)
      || ! try_unserialize (syscall_clone_record, th, &rec))
    diverged (th, 1);

  if (! io_out (th, rec.out)) diverged (th, 0);

  uint64_t res = rec.result;
  if (eri_syscall_is_error (res)) syscall_leave (th, 1, res);

  int32_t flags = regs->rdi;
  int32_t *user_ptid = (void *) regs->rdx;
  int32_t *user_ctid = (void *) regs->r10;

  int32_t *clear_user_tid = flags & ERI_CLONE_CHILD_CLEARTID ? user_ctid : 0;
  struct thread *cth = create (th->group, th, rec.id, clear_user_tid);
  if (! cth) diverged (th, 1);

  eri_atomic_inc (&th->group->thread_count, 1);
  version_activity_inc (&th->group->ver_act);

  if (flags & ERI_CLONE_PARENT_SETTID)
    (void) copy_obj_to_user (th, user_ptid, &res);
  if (flags & ERI_CLONE_CHILD_SETTID)
    (void) copy_obj_to_user (th, user_ctid, &res);

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

  struct eri_sigset mask;
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

static eri_noreturn void
check_exit (struct thread *th)
{
  uint8_t err;
  if (eri_unserialize_uint8_or_eof (th->file, &err))
    {
      eri_log_info (th->log.file, "not eof %u\n", err);
      diverged (th, 1);
    }
  exit (th);
}

static eri_noreturn void
syscall_do_exit (SYSCALL_PARAMS)
{
  int32_t *user_tid = th->clear_user_tid;
  if (user_tid && write_user (th, user_tid, sizeof *user_tid))
    {
      struct eri_syscall_exit_clear_tid_record rec;
      if (! check_magic (th, ERI_SYSCALL_EXIT_CLEAR_TID_MAGIC)
	  || ! try_unserialize (syscall_exit_clear_tid_record, th, &rec))
	diverged (th, 1);

      if (! atomic_wait (th, (uint64_t) user_tid,
			 sizeof *user_tid, rec.clear_tid.ver))
	diverged (th, 0);

      if (rec.clear_tid.updated)
	{
	  if (! eri_entry__test_access (entry, user_tid, 0)) diverged (th, 1);
	  *user_tid = 0;
	  eri_entry__reset_test_access (entry);
	  atomic_updated (th, (uint64_t) user_tid, sizeof *user_tid);
	}

      if (! io_out (th, rec.out)) diverged (th, 0);
    }
  else syscall_fetch_out (th);
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

SYSCALL_TO_IMPL (uname)
SYSCALL_TO_IMPL (sysinfo)
SYSCALL_TO_IMPL (getcpu)
SYSCALL_TO_IMPL (getrandom)

SYSCALL_TO_IMPL (setuid)
SYSCALL_TO_IMPL (getuid)
SYSCALL_TO_IMPL (setgid)
SYSCALL_TO_IMPL (getgid)
SYSCALL_TO_IMPL (geteuid)
SYSCALL_TO_IMPL (getegid)

DEFINE_SYSCALL (gettid) { syscall_leave (th, 0, th->user_tid); }
DEFINE_SYSCALL (getpid) { syscall_leave (th, 0, th->group->user_pid); }

DEFINE_SYSCALL (getppid) { syscall_do_res_in (th); }

SYSCALL_TO_IMPL (setreuid)
SYSCALL_TO_IMPL (setregid)

SYSCALL_TO_IMPL (setresuid)
SYSCALL_TO_IMPL (getresuid)
SYSCALL_TO_IMPL (setresgid)
SYSCALL_TO_IMPL (getresgid)

SYSCALL_TO_IMPL (setfsuid)
SYSCALL_TO_IMPL (setfsgid)

SYSCALL_TO_IMPL (setgroups)
SYSCALL_TO_IMPL (getgroups)

SYSCALL_TO_IMPL (setsid)
SYSCALL_TO_IMPL (getsid)
SYSCALL_TO_IMPL (setpgid)
SYSCALL_TO_IMPL (getpgid)
SYSCALL_TO_IMPL (getpgrp)

SYSCALL_TO_IMPL (settimeofday)
SYSCALL_TO_IMPL (gettimeofday)
SYSCALL_TO_IMPL (time)
SYSCALL_TO_IMPL (times)
SYSCALL_TO_IMPL (adjtimex)

SYSCALL_TO_IMPL (clock_settime)
SYSCALL_TO_IMPL (clock_gettime)
SYSCALL_TO_IMPL (clock_getres)
SYSCALL_TO_IMPL (clock_nanosleep)
SYSCALL_TO_IMPL (clock_adjtime)

SYSCALL_TO_IMPL (nanosleep)

SYSCALL_TO_IMPL (alarm)
SYSCALL_TO_IMPL (setitimer)
SYSCALL_TO_IMPL (getitimer)

SYSCALL_TO_IMPL (timer_create)
SYSCALL_TO_IMPL (timer_settime)
SYSCALL_TO_IMPL (timer_gettime)
SYSCALL_TO_IMPL (timer_getoverrun)
SYSCALL_TO_IMPL (timer_delete)

SYSCALL_TO_IMPL (setrlimit)
SYSCALL_TO_IMPL (getrlimit)
SYSCALL_TO_IMPL (prlimit64)
SYSCALL_TO_IMPL (getrusage)

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

SYSCALL_TO_IMPL (setpriority)
SYSCALL_TO_IMPL (getpriority)

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
  struct eri_sigset mask;
  struct eri_sigset old_mask = th->sig_mask;
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

  if (! read_obj_from_user (th, user_act))
    syscall_leave (th, 0, ERI_EFAULT);

  uint64_t res = 0;
  uint64_t act_ver;
  if (user_old_act)
    {
      struct eri_sigaction act;
      if (! check_magic (th, ERI_SYSCALL_RT_SIGACTION_MAGIC)
	  || ! try_unserialize (sigaction, th, &act)
	  || ! try_unserialize (uint64, th, &act_ver))
	diverged (th, 1);

      res = copy_obj_to_user_or_fault (th, user_old_act, &act);
    }
  else if (! check_magic (th, ERI_SYSCALL_RT_SIGACTION_SET_MAGIC)
	   || ! try_unserialize (uint64, th, &act_ver))
    diverged (th, 1);

  struct thread_group *group = th->group;
  if ((user_act || ! eri_syscall_is_error (res))
      && ! version_wait (th, group->sig_acts + sig - 1, act_ver))
    diverged (th, 0);
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
		!= (rec.result != ERI_EFAULT)) diverged (th, 1);

  if (! io_in (th, rec.in)) diverged (th, 0);

  syscall_leave (th, 1, rec.result);
}

static eri_noreturn void
syscall_do_pause (struct thread *th)
{
  if (! io_in (th, syscall_fetch_in (th))) diverged (th, 0);
  syscall_leave (th, 1, ERI_EINTR);
}

DEFINE_SYSCALL (pause) { syscall_do_pause (th); }

DEFINE_SYSCALL (rt_sigsuspend)
{
  struct eri_sigset *user_mask = (void *) regs->rdi;
  uint64_t size = regs->rsi;

  if (size != ERI_SIG_SETSIZE) syscall_leave (th, 0, ERI_EINVAL);

  if (! read_obj_from_user (th, user_mask))
    syscall_leave (th, 0, ERI_EFAULT);

  syscall_do_pause (th);
}

DEFINE_SYSCALL (rt_sigtimedwait)
{
  struct eri_sigset *user_set = (void *) regs->rdi;
  struct eri_siginfo *user_info = (void *) regs->rsi;
  struct eri_timespec *user_timeout = (void *) regs->rdx;
  uint64_t size = regs->r10;

  if (size != ERI_SIG_SETSIZE) syscall_leave (th, 0, ERI_EINVAL);

  if (! read_obj_from_user (th, user_set)
      || (user_timeout && ! read_obj_from_user (th, user_timeout)))
    syscall_leave (th, 0, ERI_EFAULT);

  struct eri_syscall_rt_sigtimedwait_record rec;
  if (! check_magic (th, ERI_SYSCALL_RT_SIGTIMEDWAIT_MAGIC)
      || ! try_unserialize (syscall_rt_sigtimedwait_record, th, &rec)
      || (user_info && ! eri_syscall_is_non_fault_error (rec.result)
	  && copy_obj_to_user (th, user_info, &rec.info)
		!= (rec.result != ERI_EFAULT))) diverged (th, 1);

  if (! io_in (th, rec.in)) diverged (th, 0);

  syscall_leave (th, 1, rec.result);
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
  if (read_obj_from_user (th, user_info) != (rec.result != ERI_EFAULT))
    diverged (th, 1);
  if (! io_in (th, rec.in)) diverged (th, 0);
  syscall_leave (th, 1, rec.result);
}

DEFINE_SYSCALL (rt_sigqueueinfo)
{ syscall_do_rt_sigqueueinfo (SYSCALL_ARGS); }
DEFINE_SYSCALL (rt_tgsigqueueinfo)
{ syscall_do_rt_sigqueueinfo (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (restart_syscall)

SYSCALL_TO_IMPL (socket)
SYSCALL_TO_IMPL (connect)
SYSCALL_TO_IMPL (accept)
SYSCALL_TO_IMPL (accept4)
SYSCALL_TO_IMPL (sendto)
SYSCALL_TO_IMPL (recvfrom)
SYSCALL_TO_IMPL (sendmsg)
SYSCALL_TO_IMPL (sendmmsg)
SYSCALL_TO_IMPL (recvmsg)
SYSCALL_TO_IMPL (recvmmsg)
SYSCALL_TO_IMPL (shutdown)
SYSCALL_TO_IMPL (bind)
SYSCALL_TO_IMPL (listen)
SYSCALL_TO_IMPL (getsockname)
SYSCALL_TO_IMPL (getpeername)
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
  struct eri_sigset *user_mask = (void *) regs->rsi;

  int32_t flags;
  syscall_leave_if_error (th, 0,
		eri_entry__syscall_get_signalfd (entry, &flags));
  if (! read_obj_from_user (th, user_mask))
    syscall_leave (th, 0, ERI_EINVAL);

  syscall_do_res_io (th);
}

DEFINE_SYSCALL (signalfd) { syscall_do_signalfd (SYSCALL_ARGS); }
DEFINE_SYSCALL (signalfd4) { syscall_do_signalfd (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (pipe)
SYSCALL_TO_IMPL (pipe2)

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
  struct eri_syscall_res_in_record rec = syscall_fetch_res_io (th);
  const char *user_pathname = (void *) (regs->rax == __NR_openat
					? regs->rsi : regs->rdi);
  uint64_t len;
  if (read_str_from_user (th, user_pathname, ERI_PATH_MAX, &len)
	? (len == ERI_PATH_MAX) != (rec.result == ERI_ENAMETOOLONG)
	: rec.result != ERI_EFAULT) diverged (th, 1);
  if (! io_in (th, rec.in)) diverged (th, 0);
  syscall_leave (th, 1, rec.result);
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

SYSCALL_TO_IMPL (select)
SYSCALL_TO_IMPL (pselect6)
SYSCALL_TO_IMPL (poll)
SYSCALL_TO_IMPL (ppoll)

SYSCALL_TO_IMPL (epoll_create)
SYSCALL_TO_IMPL (epoll_create1)
SYSCALL_TO_IMPL (epoll_wait)
SYSCALL_TO_IMPL (epoll_pwait)
SYSCALL_TO_IMPL (epoll_ctl)

static uint8_t
syscall_get_read_data (struct thread *th, void *dst,
		       uint64_t total, uint8_t readv)
{
  struct thread_group *group = th->group;

  uint64_t buf_size = eri_min (total, 2 * group->file_buf_size);
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

#define DIV_NONE	0
#define DIV_LOCAL	1
#define DIV_GLOBAL	2

static eri_noreturn void
syscall_div_in_leave (struct thread *th, uint8_t div,
		      uint64_t in, uint64_t result)
{
  if (div == DIV_LOCAL) diverged (th, 1);
  if (div == DIV_GLOBAL || ! io_in (th, in)) diverged (th, 0);
  syscall_leave (th, 1, result);
}

static eri_noreturn void
syscall_do_read_data (struct thread *th, void *dst,
		      uint8_t readv, uint64_t limit)
{
  uint8_t div = DIV_NONE;
  struct eri_syscall_res_in_record rec;
  if (! check_magic (th, ERI_SYSCALL_READ_MAGIC)
      || ! try_unserialize (syscall_res_in_record, th, &rec))
    { div = DIV_LOCAL; goto out; };

  if (rec.result == ERI_EFAULT)
    {
      struct eri_access acc;
      eri_set_write (&acc, (uint64_t) (readv
			? ((struct eri_iovec *) dst)->base : dst), 1);
      update_access (th, &acc, 1);
    }

  if (eri_syscall_is_error (rec.result) || rec.result == 0) goto out;

  if (rec.result > (readv ? sum_iovec (dst, limit) : limit))
    { div = DIV_LOCAL; goto out; }

  if (! syscall_get_read_data (th, dst, rec.result, readv)) div = DIV_LOCAL;

out:
  if (readv) eri_entry__syscall_free_rw_iov (th->entry, dst);
  syscall_div_in_leave (th, div, rec.in, rec.result);
}

static eri_noreturn void
syscall_do_read (SYSCALL_PARAMS)
{

  int32_t nr = regs->rax;
  /* XXX: detect memory corruption in analysis */
  if (nr == __NR_read || nr == __NR_pread64)
    {
      uint64_t buf = regs->rsi;
      eri_entry__test_invalidate (entry, &buf);
      syscall_do_read_data (th, (void *) buf, 0, regs->rdx);
    }
  else
    {
      struct eri_iovec *iov;
      int32_t iov_cnt;
      syscall_leave_if_error (th, 0, call_with_user_access (th, 1,
		eri_entry__syscall_get_rw_iov, entry, &iov, &iov_cnt));

      syscall_do_read_data (th, iov, 1, iov_cnt);
    }
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

  uint8_t div = DIV_NONE;
  struct eri_syscall_res_io_record rec;
  if (! check_magic (th, ERI_SYSCALL_RES_IO_MAGIC)
      || ! try_unserialize (syscall_res_io_record, th, &rec))
    { div = DIV_LOCAL; goto out; }
  if (! io_out (th, rec.out)) { div = DIV_GLOBAL; goto out; };

  struct eri_access acc;
  if (rec.result == ERI_EFAULT)
    {
      eri_set_write (&acc, writev ? (uint64_t) iov->base : buf, 1);
      update_access (th, &acc, 1);
      goto out;
    }

  if (eri_syscall_is_error (rec.result) || ! rec.result) goto out;

  if (rec.result > (writev ? sum_iovec (iov, iov_cnt) : regs->rdx))
    { div = DIV_LOCAL; goto out; }

  if (! writev)
    {
      eri_set_write (&acc, buf, rec.result);
      update_access (th, &acc, 1);
    }
  else
    {
      uint64_t c = 0;
      struct eri_iovec *v = iov;
      while (c < rec.result)
	{
	  uint64_t s = eri_min (v->len, rec.result - c);
	  eri_set_write (&acc, (uint64_t) (v++)->base, s);
	  update_access (th, &acc, 1);
	  c += s;
	}
    }

out:
  if (writev) eri_entry__syscall_free_rw_iov (th->entry, iov);
  syscall_div_in_leave (th, div, rec.in, rec.result);
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

SYSCALL_TO_IMPL (stat)
SYSCALL_TO_IMPL (fstat)
SYSCALL_TO_IMPL (newfstatat)
SYSCALL_TO_IMPL (lstat)
SYSCALL_TO_IMPL (access)
SYSCALL_TO_IMPL (faccessat)

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

SYSCALL_TO_IMPL (getdents)
SYSCALL_TO_IMPL (getdents64)

SYSCALL_TO_IMPL (getcwd)
SYSCALL_TO_IMPL (chdir)
SYSCALL_TO_IMPL (fchdir)
SYSCALL_TO_IMPL (rename)
SYSCALL_TO_IMPL (renameat)
SYSCALL_TO_IMPL (renameat2)
SYSCALL_TO_IMPL (mkdir)
SYSCALL_TO_IMPL (mkdirat)
SYSCALL_TO_IMPL (rmdir)

SYSCALL_TO_IMPL (link)
SYSCALL_TO_IMPL (linkat)
SYSCALL_TO_IMPL (unlink)
SYSCALL_TO_IMPL (unlinkat)
SYSCALL_TO_IMPL (symlink)
SYSCALL_TO_IMPL (symlinkat)
SYSCALL_TO_IMPL (readlink)
SYSCALL_TO_IMPL (readlinkat)

SYSCALL_TO_IMPL (mknod)
SYSCALL_TO_IMPL (mknodat)

SYSCALL_TO_IMPL (umask)

SYSCALL_TO_IMPL (chmod)
SYSCALL_TO_IMPL (fchmod)
SYSCALL_TO_IMPL (fchmodat)

SYSCALL_TO_IMPL (chown)
SYSCALL_TO_IMPL (fchown)
SYSCALL_TO_IMPL (fchownat)
SYSCALL_TO_IMPL (lchown)

SYSCALL_TO_IMPL (utime)
SYSCALL_TO_IMPL (utimes)
SYSCALL_TO_IMPL (futimesat)
SYSCALL_TO_IMPL (utimensat)

SYSCALL_TO_IMPL (ustat)
SYSCALL_TO_IMPL (statfs)
SYSCALL_TO_IMPL (fstatfs)

SYSCALL_TO_IMPL (sysfs)
SYSCALL_TO_IMPL (sync)
SYSCALL_TO_IMPL (syncfs)

SYSCALL_TO_IMPL (mount)
SYSCALL_TO_IMPL (umount2)

SYSCALL_TO_IMPL (chroot)
SYSCALL_TO_IMPL (pivot_root)

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
  if (! mm_wait (th, rec.in)) diverged (th, 0);
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
  if (! try_unserialize (uint64, th, &id) || (anony && id)) diverged (th, 1);

  int32_t fd = -1;
  if (! anony)
    {
      uint8_t ok;
      if (! try_unserialize (uint8, th, &ok) || ! ok) diverged (th, 1);

      if ((fd = open_mmap_file (th->group->path, id)) == -1) diverged (th, 1);
    }

  /* XXX: flags */
  flags = (flags & ~(ERI_MAP_TYPE | ERI_MAP_GROWSDOWN))
	  | ERI_MAP_PRIVATE | ERI_MAP_FIXED;
  uint8_t err = eri_syscall_is_error (
			eri_syscall (mmap, res, len, prot, flags, fd, 0));
  if (! anony) eri_assert_syscall (close, fd);

  if (err) diverged (th, 1);

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
		eri_syscall (mprotect, addr, len, prot))) diverged (th, 1);

  update_mm_prot (th, addr, len, prot);

out:
  syscall_mm_leave (th, res);
}

DEFINE_SYSCALL (munmap)
{
  uint64_t res = syscall_mm_enter (th, ERI_SYSCALL_RES_IN_MAGIC);
  if (eri_syscall_is_error (res)) goto out;

  if (eri_syscall_is_error (eri_entry__syscall (entry))) diverged (th, 1);

  update_mm_prot (th, regs->rdi, regs->rsi, 0);

out:
  syscall_mm_leave (th, res);
}

SYSCALL_TO_IMPL (mremap)
SYSCALL_TO_IMPL (madvise)

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
    diverged (th, 1);
  if (old > now && eri_syscall_is_error (
				eri_syscall (munmap, now, old - now)))
    diverged (th, 1);

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

DEFINE_SYSCALL (futex)
{
  int32_t *user_addr = (void *) regs->rdi;
  int32_t op = regs->rsi;
  int32_t cmd = op & ERI_FUTEX_CMD_MASK;
  struct eri_timespec *user_timeout = (void *) regs->r10;
  if (cmd == ERI_FUTEX_WAIT || cmd == ERI_FUTEX_WAKE)
    {
      uint64_t res = syscall_fetch_result (th);
      uint8_t ok = read_obj_from_user (th, user_addr)
		   && (cmd != ERI_FUTEX_WAIT || ! user_timeout
		       || read_obj_from_user (th, user_timeout));
      if (ok != (res != ERI_EFAULT)) diverged (th, 1);
      syscall_leave (th, 1, res);
    }

  syscall_leave (th, 0, ERI_ENOSYS);
}

SYSCALL_TO_IMPL (set_robust_list)
SYSCALL_TO_IMPL (get_robust_list)

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

SYSCALL_TO_IMPL (remap_file_pages) /* deprecated */

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
      || ! try_unserialize (uint64, th, &steps)) diverged (th, 1);

  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);

  if (fetch_mark (th) == ERI_ASYNC_RECORD)
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

#define DEFINE_ATOMIC_TYPE(type) \
static void								\
ERI_PASTE (atomic_, type) (uint16_t code, type *mem, uint64_t val,	\
			   struct eri_registers *regs)			\
{									\
  if (code == ERI_OP_ATOMIC_STORE || code == ERI_OP_ATOMIC_XCHG)	\
    *mem = val;								\
  else if (code == ERI_OP_ATOMIC_INC)					\
    eri_atomic_inc_x (mem, &regs->rflags, 0);				\
  else if (code == ERI_OP_ATOMIC_DEC)					\
    eri_atomic_dec_x (mem, &regs->rflags, 0);				\
  else if (code == ERI_OP_ATOMIC_CMPXCHG)				\
    eri_atomic_cmpxchg_x (mem, &regs->rax, val, &regs->rflags, 0);	\
  else eri_assert_unreachable ();					\
}

DEFINE_ATOMIC_TYPE (uint8_t)
DEFINE_ATOMIC_TYPE (uint16_t)
DEFINE_ATOMIC_TYPE (uint32_t)
DEFINE_ATOMIC_TYPE (uint64_t)

static eri_noreturn void
atomic (struct thread *th)
{
  struct eri_entry *entry = th->entry;
  uint16_t code = eri_entry__get_op_code (entry);
  uint64_t mem = eri_entry__get_atomic_mem (entry);
  uint8_t size = eri_entry__get_atomic_size (entry);

  if (! atomic_access_user (th, (void *) mem, size, code))
    eri_entry__restart (entry);

  struct eri_atomic_record rec;
  if (! check_magic (th, ERI_ATOMIC_MAGIC)
      || ! try_unserialize (atomic_record, th, &rec)) diverged (th, 1);
  if (! atomic_wait (th, mem, size, rec.ver)) diverged (th, 0);

  uint64_t val = eri_entry__get_atomic_val (entry);

  struct eri_registers *regs = eri_entry__get_regs (entry);

  if (rec.updated)
    {
      if (code == ERI_OP_ATOMIC_LOAD) diverged (th, 1);

      eri_assert (size == 1 || size == 2 || size == 4 || size == 8);

      if (! eri_entry__test_access (entry, mem, 0)) diverged (th, 1);
      if (size == 1) atomic_uint8_t (code, (void *) mem, val, regs);
      else if (size == 2) atomic_uint16_t (code, (void *) mem, val, regs);
      else if (size == 4) atomic_uint32_t (code, (void *) mem, val, regs);
      else if (size == 8) atomic_uint64_t (code, (void *) mem, val, regs);
      eri_entry__reset_test_access (entry);

      atomic_updated (th, mem, size);
    }

  fetch_test_async_signal (th);

  if (code == ERI_OP_ATOMIC_LOAD || code == ERI_OP_ATOMIC_XCHG)
    eri_entry__atomic_interleave (entry, rec.val);

  eri_entry__leave (entry);
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
  else if (eri_op_is_atomic (code)) atomic (th);
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
    diverged (th, 1);
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
    diverged (th, 0);
  if (eri_si_sync (info) && ! check_magic (th, ERI_SIGNAL_MAGIC))
    diverged (th, 1);

  if (sig == 0) check_exit (th);

  if (eri_si_sync (info) && eri_sig_set_set (&th->sig_mask, sig))
    check_exit (th);

  struct eri_sig_act act;
  if (! try_unserialize (sig_act, th, &act)) diverged (th, 1);

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
      diverged (th, 1);
    }

  if (! version_wait (th, th->group->sig_acts + sig - 1, act.ver))
    diverged (th, 0);

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
  if (eri_enabled_debug ())
    eri_log_info (th->log.file, "%u %lx %lx %lx %lx %lx\n", sig, info,
		  ctx->mctx.rip, ctx->mctx.rip - th->group->map_range.start,
		  ctx->mctx.r11, ctx->mctx.rflags);

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
      if (eri_op_is_atomic (code))
	eri_entry__set_signal (entry, info, ctx);

      eri_entry__sig_access_fault (entry, &ctx->mctx, info->fault.addr);
      return 0;
    }

  if (eri_si_sync (info))
    eri_assert (! eri_within (&th->group->map_range, ctx->mctx.rip));

  eri_entry__sig_test_op_ret (th->entry,
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
