/* vim: set ft=cpp: */

/*
 * XXX: There is no acceptable way to completely prevent user from
 * corrupting our memory without hardware support (e.g. pkey, while which
 * can't gurantee the whole safety, but most).
 * The protection is done for the syscalls, but it's too
 * costly for normal memory accessing instructions.
 *
 * The behaviour of corrupting our memory is not undefined and user
 * won't be signaled. It's may even undetectable in the replay/analysis if
 * the record buffer is corrupted.
 *
 * There shall be no other newly introduced undefined behaviour.
 */

#include <stdarg.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/elf.h>
#include <lib/buf.h>
#include <lib/lock.h>
#include <lib/rbtree.h>
#include <lib/list.h>
#include <lib/malloc.h>
#include <lib/syscall.h>
#include <lib/atomic.h>

#include <common/debug.h>
#include <common/common.h>
#include <common/entry.h>
#include <common/serial.h>

#include <live/common.h>
#include <live/rtld.h>
#include <live/signal-thread.h>
#include <live/thread-futex.h>
#include <live/thread-recorder.h>
#include <live/thread.h>

#define THREAD_SIG_STACK_SIZE	(2 * 4096)

struct eri_live_thread
{
  struct eri_live_thread_group *group;
  struct eri_live_signal_thread *sig_th;

  uint64_t id;
  struct eri_buf_file log;
  struct eri_buf_file sig_log;

  int32_t alive;
  eri_lock_t start_lock;
  int32_t user_tid;
  int32_t *clear_user_tid;

  struct eri_entry *entry;
  struct eri_live_thread_futex *futex;
  struct eri_live_thread_recorder *rec;

  struct eri_sig_act sig_act;
  uint8_t sig_force_masked;
  struct eri_sigset *sig_force_deliver;

  int32_t tid;
  struct eri_stack sig_alt_stack;

  eri_aligned16 uint8_t sig_stack[THREAD_SIG_STACK_SIZE];

  eri_aligned16 uint8_t stack[0];
};

struct fdf_sig_mask
{
  uint64_t ref_count;
  eri_lock_t lock;
  struct eri_sigset mask;
};

struct fdf
{
  int32_t fd;
  int32_t flags;
  struct fdf_sig_mask *sig_mask;

  ERI_RBT_NODE_FIELDS (fdf, struct fdf)
};

struct eri_live_thread_group
{
  struct eri_mtpool *pool;

  uint64_t page_size;
  struct eri_range map_range;
  uint64_t base;

  const char *log;
  uint64_t file_buf_size;

  uint64_t init_user_stack_size;

  int32_t pid;
  int32_t user_pid;

  eri_lock_t fdf_lock;
  ERI_RBT_TREE_FIELDS (fdf, struct fdf)

  struct eri_live_atomic *atomic;
  struct eri_live_thread_futex_group *futex_group;

  uint64_t stack_size;

  struct eri_live_thread_recorder_group *rec_group;

  uint64_t *io;

  eri_lock_t mm_lock;
  uint64_t mm;
};

ERI_DEFINE_RBTREE (static, fdf, struct eri_live_thread_group,
		   struct fdf, int32_t, eri_less_than)

static uint64_t
page_size (struct eri_live_thread *th) { return th->group->page_size; }

static void
fdf_alloc_insert (struct eri_live_thread_group *group, int32_t fd,
		  int32_t flags, const struct eri_sigset *sig_mask)
{
  struct eri_mtpool *pool = group->pool;
  struct fdf *fdf = eri_assert_mtmalloc (pool, sizeof *fdf);
  fdf->fd = fd;
  fdf->flags = flags;
  if (sig_mask)
    {
      fdf->sig_mask = eri_assert_mtmalloc (pool, sizeof *fdf->sig_mask);
      fdf->sig_mask->ref_count = 1;
      fdf->sig_mask->lock = 0;
      fdf->sig_mask->mask = *sig_mask;
    }
  fdf_rbt_insert (group, fdf);
}

static void
fdf_dup (struct eri_live_thread_group *group, int32_t fd,
	 const struct fdf *fdf)
{
  fdf_alloc_insert (group, fd, fdf->flags,
		    fdf->sig_mask ? &fdf->sig_mask->mask : 0);
}

static void
fdf_remove_free (struct eri_live_thread_group *group, struct fdf *fdf)
{
  fdf_rbt_remove (group, fdf);
  if (fdf->sig_mask)
    {
      if (! eri_atomic_dec_fetch (&fdf->sig_mask->ref_count, 1))
	eri_assert_mtfree (group->pool, fdf->sig_mask);
    }
  eri_assert_mtfree (group->pool, fdf);
}

static struct fdf *
fdf_try_lock (struct eri_live_thread_group *group, int32_t fd)
{
  eri_assert_lock (&group->fdf_lock);
  struct fdf *fdf = fdf_rbt_get (group, &fd, ERI_RBT_EQ);
  if (! fdf) eri_assert_unlock (&group->fdf_lock);
  return fdf;
}

static void
init_fdf (struct eri_live_thread_group *group)
{
  int32_t fd = eri_assert_syscall (open, "/proc/self/fd",
				   ERI_O_RDONLY | ERI_O_DIRECTORY);
  uint8_t buf[128];
  uint64_t nread;
  while ((nread = eri_assert_syscall (getdents, fd, buf, sizeof buf)))
    {
      uint64_t p;
      struct eri_dirent *d;
      for (p = 0; p < nread; p += d->reclen)
	{
	  d = (void *) (buf + p);
	  if (eri_strcmp (d->name, ".") == 0
	      || eri_strcmp (d->name, "..") == 0) continue;

	  int32_t efd = eri_assert_atoi (d->name, 10);
	  if (efd == fd) continue;
	  int32_t flags = eri_assert_syscall (fcntl, efd, ERI_F_GETFL);
	  fdf_alloc_insert (group, efd, flags & ERI_O_NONBLOCK, 0);
	  eri_assert_syscall (fcntl, efd, ERI_F_SETFL,
			      flags & ~ERI_O_NONBLOCK);
	}
    }
  eri_assert_syscall (close, fd);
}

static void
disable_vdso (struct eri_auxv *auxv)
{
  for (; auxv->type != ERI_AT_NULL; ++auxv)
    if (auxv->type == ERI_AT_SYSINFO || auxv->type == ERI_AT_SYSINFO_EHDR)
      auxv->type = ERI_AT_IGNORE;
}

static uint64_t
io_in (struct eri_live_thread *th)
{
  return eri_live_in (th->group->io);
}

static uint64_t
io_out (struct eri_live_thread *th)
{
  return eri_live_out (th->group->io);
}

struct eri_live_thread_group *
eri_live_thread__create_group (struct eri_mtpool *pool,
			struct eri_live_thread__create_group_args *args)
{
  struct eri_live_rtld_args *rtld_args = args->rtld_args;

  uint64_t init_user_stack_size = 8 * 1024 * 1024;
  uint64_t atomic_table_size =  2 * 1024 * 1024;
  uint64_t futex_table_size =  1024; /* TODO parameterize */

  uint64_t stack_size = 2 * 1024 * 1024;
  const char *path = 0;

  if (rtld_args->envp)
    {
      char **p;
      for (p = rtld_args->envp; *p; ++p)
	(void) (eri_get_arg_int (*p, "ERS_INIT_USER_STACK_SIZE=",
				 &init_user_stack_size, 10)
	|| eri_get_arg_int (*p, "ERS_ATOMIC_TABLE_SIZE=",
			    &atomic_table_size, 10)
	|| eri_get_arg_int (*p, "ERS_STACK_SIZE=", &stack_size, 10)
	|| eri_get_arg_str (*p, "ERS_DATA=", (void *) &path));
    }

  if (! path && (args->log || eri_global_enable_debug)) path = "ers-data";

  struct eri_live_thread_group *group = eri_assert_mtmalloc (
						pool, sizeof *group);
  group->pool = pool;
  group->page_size = rtld_args->page_size;
  group->map_range.start = rtld_args->map_start;
  group->map_range.end = rtld_args->map_end;
  group->base = rtld_args->base;
  group->log = args->log;
  group->file_buf_size = args->file_buf_size;
  group->init_user_stack_size = init_user_stack_size;
  group->user_pid = args->user_pid;

  group->fdf_lock = 0;
  ERI_RBT_INIT_TREE (fdf, group);
  init_fdf (group);

  group->atomic = eri_live_create_atomic (group->pool, atomic_table_size);
  group->futex_group = eri_live_thread_futex__create_group (
			group->pool, futex_table_size, group->atomic);

  group->stack_size = stack_size;

  group->rec_group = eri_live_thread_recorder__create_group (
		pool, path, group->file_buf_size, group->page_size);

  group->io = args->io;

  group->mm_lock = 0;
  group->mm = 0;
  return group;
}

void
eri_live_thread__destroy_group (struct eri_live_thread_group *group)
{
  struct fdf *fd, *nfd;
  ERI_RBT_FOREACH_SAFE (fdf, group, fd, nfd)
    fdf_remove_free (group, fd);

  eri_live_destroy_atomic (group->atomic);
  eri_live_thread_futex__destroy_group (group->futex_group);
  eri_live_thread_recorder__destroy_group (group->rec_group);
  eri_assert_mtfree (group->pool, group);
}

static eri_noreturn void main_entry (struct eri_entry *entry);
static eri_noreturn void sig_action (struct eri_entry *entry);

static void
open_log (struct eri_live_thread *th, struct eri_buf_file *log,
	  const char *name)
{
  struct eri_live_thread_group *group = th->group;
  eri_open_log (group->pool, log, group->log, name, th->id,
		eri_enabled_debug () ? 0 : group->file_buf_size);
}

static struct eri_live_thread *
create (struct eri_live_thread_group *group,
	struct eri_live_signal_thread *sig_th, int32_t *clear_user_tid)
{
  struct eri_live_thread *th
	= eri_assert_mtmalloc (group->pool, sizeof *th + group->stack_size);
  th->group = group;
  th->sig_th = sig_th;
  th->id = eri_live_signal_thread__get_id (sig_th);
  open_log (th, &th->log, "l");
  open_log (th, &th->sig_log, "ls");
  eri_log (th->log.file, "%lx %lx\n", th, sig_th);
  th->alive = 1;
  th->start_lock = 1;
  th->clear_user_tid = clear_user_tid;

  struct eri_entry__create_args args = {
    group->pool, &group->map_range, th, th->stack + group->stack_size,
    main_entry, sig_action
  };
  th->entry = eri_entry__create (&args);
  th->futex = eri_live_thread_futex__create (
			group->futex_group, th->entry, th->log.file);
  th->rec = eri_live_thread_recorder__create (
			group->rec_group, th->entry, th->id, th->log.file);

  th->sig_force_deliver = 0;
  return th;
}

struct eri_live_thread *
eri_live_thread__create_main (struct eri_live_thread_group *group,
			      struct eri_live_signal_thread *sig_th,
			      struct eri_live_rtld_args *rtld_args,
			      int32_t user_tid)
{
  if (rtld_args->auxv) disable_vdso (rtld_args->auxv);

  struct eri_live_thread *th = create (group, sig_th, 0);
  th->user_tid = user_tid;
  eri_log (th->log.file, "base = %lx\n", group->base);
  struct eri_entry *entry = th->entry;

  struct eri_registers *regs = eri_entry__get_regs (entry);
  eri_memset (regs, 0, sizeof *regs);
  regs->rsp = rtld_args->rsp;
  regs->rdx = rtld_args->rdx;
  regs->rip = rtld_args->rip;

  eri_assert_syscall (sigaltstack, 0, &th->sig_alt_stack);
  return th;
}

static eri_noreturn void
start (struct eri_live_thread *th)
{
  eri_log (th->log.file, "%lx\n", th);
  eri_assert_syscall (prctl, ERI_PR_SET_PDEATHSIG, ERI_SIGKILL);
  eri_assert (eri_assert_syscall (getppid) == th->group->user_pid);

  eri_live_signal_thread__init_thread_sig_stack (
	th->sig_th, th->sig_stack, THREAD_SIG_STACK_SIZE);

  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_GS, th->entry);

  eri_assert_lock (&th->start_lock);
  eri_log (th->log.file, "tid = %u, user_tid = %u\n",
	   th->tid, th->user_tid);

  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  eri_entry__leave (th->entry);
}

static void
fix_init_maps (struct eri_live_thread_group *group, uint64_t rsp)
{
  struct eri_buf buf;
  eri_live_init_get_maps (group->pool, &group->map_range, &buf);
  struct eri_smaps_map *maps = buf.buf;
  uint64_t n = buf.o;

  uint64_t i, stack_end = 0;
  for (i = 0; i < n; ++i)
    if (eri_within (&maps[i].range, rsp))
      {
	eri_xassert (! stack_end, eri_info);
	stack_end = maps[i].range.end;
	break;
      }
  eri_xassert (stack_end, eri_info);

  uint64_t min_stack_start = 0;
  for (i = 0; i < n; ++i)
    if (! eri_within (&maps[i].range, rsp)
	&& maps[i].range.start < stack_end)
      min_stack_start = eri_max (min_stack_start, maps[i].range.end);
  if (group->map_range.start < stack_end)
    min_stack_start = eri_max (min_stack_start, group->map_range.end);

  for (i = 0; i < n; ++i)
    {
      uint64_t start = maps[i].range.start;
      uint64_t end = maps[i].range.end;
      const char *path = maps[i].path;
      int32_t prot = eri_common_get_mem_prot (maps[i].prot);
      if (path && (eri_strcmp (path, "[vvar]") == 0
		   || eri_strcmp (path, "[vdso]") == 0))
	eri_assert_syscall (munmap, start, end - start);
      else if (eri_within (&maps[i].range, rsp))
	{
	  /* XXX: mimic grows_down */
	  eri_xassert (prot & ERI_PROT_READ, eri_info);
	  eri_xassert (prot & ERI_PROT_WRITE, eri_info);

	  struct eri_rlimit lim;
	  eri_assert_syscall (prlimit64, 0, ERI_RLIMIT_STACK, 0, &lim);
	  uint64_t max_size = eri_round_down (
			eri_min (lim.max, group->init_user_stack_size),
			group->page_size) ? : stack_end - start;

	  uint64_t size = eri_min (stack_end - min_stack_start, max_size);
	  uint8_t *tmp = (void *) eri_assert_syscall (mmap, 0, size,
		prot, ERI_MAP_PRIVATE | ERI_MAP_STACK | ERI_MAP_ANONYMOUS,
		-1, 0);
	  uint64_t data_size = stack_end - rsp;
	  eri_memcpy (tmp + size - data_size, (void *) rsp, data_size);
	  eri_assert_syscall (mremap, tmp, size, size,
		ERI_MREMAP_MAYMOVE | ERI_MREMAP_FIXED, stack_end - size);

	  uint64_t guard = stack_end - size - group->page_size;
	  if (guard >= min_stack_start)
	    eri_syscall (mmap, guard, group->page_size, 0,
		ERI_MAP_PRIVATE | ERI_MAP_FIXED | ERI_MAP_ANONYMOUS, -1, 0);
	}
      else if (prot != maps[i].prot)
	eri_assert_syscall (mprotect, start, end - start, prot);
    }

  eri_live_init_free_maps (group->pool, &buf);
}

static eri_noreturn void
start_main (struct eri_live_thread *th)
{
  /* XXX: unspecified? necessary? */
  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_FS, 0);

  struct eri_live_thread_group *group = th->group;
  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);

  fix_init_maps (group, regs->rsp);

  struct eri_init_record rec = {
    0, regs->rdx, regs->rsp, regs->rip,
    group->page_size, eri_assert_syscall (brk, 0),
    *eri_live_signal_thread__get_sig_mask (th->sig_th), th->sig_alt_stack,
    group->user_pid, group->map_range,
    eri_live_atomic_get_table_size (group->atomic)
  };
  eri_live_thread_recorder__rec_init (th->rec, &rec);

  start (th);
}

void
eri_live_thread__clone_main (struct eri_live_thread *th)
{
  struct eri_sys_clone_args args = {

    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | ERI_SIGCHLD,

    eri_entry__get_stack (th->entry) - 8, &th->tid, &th->alive, 0,
    start_main, th
  };

  th->group->pid = eri_assert_sys_clone (&args);
  eri_assert_unlock (&th->start_lock);
}

struct eri_live_thread__create_args
{
  struct eri_live_thread *pth;
  struct eri_live_thread *cth;
};

struct eri_live_thread *
eri_live_thread__create (struct eri_live_signal_thread *sig_th,
			 struct eri_live_thread__create_args *create_args)
{
  struct eri_live_thread *pth = create_args->pth;

  struct eri_entry *pentry = pth->entry;
  struct eri_registers *pregs = eri_entry__get_regs (pentry);

  int32_t flags = pregs->rdi;
  int32_t *ctid = (void *) pregs->r10;
  int32_t *clear_user_tid = flags & ERI_CLONE_CHILD_CLEARTID ? ctid : 0;
  struct eri_live_thread *th = create (pth->group, sig_th, clear_user_tid);
  create_args->cth = th;

  struct eri_entry *entry = th->entry;

  struct eri_registers *regs = eri_entry__get_regs (entry);
  *regs = *pregs;
  regs->rsp = pregs->rsi;
  regs->rax = 0;
  regs->rcx = regs->rip;
  regs->r11 = regs->rflags;

  th->sig_alt_stack = pth->sig_alt_stack;
  return th;
}

void
eri_live_thread__set_user_tid (struct eri_live_thread *th,
			       int32_t user_tid)
{
  th->user_tid = user_tid;
}

uint64_t
eri_live_thread__clone (struct eri_live_thread *th)
{
  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);
  void *new_tls = (void *) regs->r8;
  struct eri_sys_clone_args args = {

    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_THREAD
    | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | (new_tls ? ERI_CLONE_SETTLS : 0),

    eri_entry__get_stack (entry) - 8,
    &th->tid, &th->alive, new_tls, start, th
  };

  eri_log (th->log.file, "clone %lx\n", args.stack);
  uint64_t res = eri_sys_clone (&args);

  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  return res;
}

void
eri_live_thread__destroy (struct eri_live_thread *th)
{
  eri_live_thread_recorder__destroy (th->rec);
  eri_live_thread_futex__destroy (th->futex);
  eri_entry__destroy (th->entry);

  struct eri_mtpool *pool = th->group->pool;
  eri_close_log (pool, &th->log);
  eri_close_log (pool, &th->sig_log);
  eri_assert_mtfree (pool, th);
}

void
eri_live_thread__join (struct eri_live_thread *th)
{
  eri_assert_sys_futex_wait (&th->alive, 1, 0);
}

/*
 * Guide of syscalls:
 *
 * 1. strictly record any order that may used as sync method, record and
 *    inc io version before syscalls that may produce externally visible
 *    side effect, record io version after syscalls that may use external
 *    side effect.
 *
 *    This is not applied to the memory related syscalls, while these
 *    syscalls can indeed be used as sync method. This is because memory
 *    related syscalls also affect normal instructions with memory
 *    operands, which obviously can not be precisely recorded.
 *
 *    We can develop the level of common sync usages in the analysis.
 *
 * 2. try to not record deterministic syscalls, e.g. gettid / pid. This
 *    is basically for the performance reason, non practicable sync by
 *    any unncessary records shall be removed by the analysis. Accepting
 *    recording more than necessary eases the implementation particularly
 *    in error handling (or completely leaving the error handling to the
 *    kernel).
 *
 *    EFAULT is treated as deterministic syscall result providing special
 *    treatement of memory related operations.
 *
 * 3. Any results that can't be easily got shall be reported by the
 *    analyzer (possibly as undefined behaviour), such results includs:
 *
 *    a) how much bytes writes when EFAULT returns. [DELETED]
 *       As long as the order of memory operations is determined, the
 *       result can be determined. XXX: test this.
 *
 *    Keep updating this list.
 */

#define non_conforming	eri_log_info

static void
syscall_record (struct eri_live_thread *th, uint16_t magic, void *rec)
{
  eri_live_thread_recorder__rec_syscall (th->rec, magic, rec);
}

static eri_unused void
syscall_record_result (struct eri_live_thread *th, uint64_t res)
{
  syscall_record (th, ERI_SYSCALL_RESULT_MAGIC, (void *) res);
}

static void
syscall_record_in (struct eri_live_thread *th)
{
  syscall_record (th, ERI_SYSCALL_IN_MAGIC, (void *) io_in (th));
}

static void
syscall_record_res_in (struct eri_live_thread *th, uint64_t res)
{
  struct eri_syscall_res_in_record rec = { res, io_in (th) };
  syscall_record (th, ERI_SYSCALL_RES_IN_MAGIC, &rec);
}

static eri_unused void
syscall_record_out (struct eri_live_thread *th)
{
  syscall_record (th, ERI_SYSCALL_OUT_MAGIC, (void *) io_out (th));
}

static void
syscall_record_res_io (struct eri_live_thread *th,
		       struct eri_syscall_res_io_record *rec)
{
  rec->res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_RES_IO_MAGIC, rec);
}

static uint64_t
syscall_copy_to_user (struct eri_entry *entry, uint64_t res, void *dst,
		      const void *src, uint64_t size, uint8_t opt)
{
  if (eri_syscall_is_error (res) || (opt && ! dst)) return res;
  return eri_entry__copy_to_user (entry, dst, src, size, 0)
						? res : ERI_EFAULT;
}

#define syscall_copy_obj_to_user(entry, res, dst, src) \
  ({ typeof (dst) _dst = dst;						\
     syscall_copy_to_user (entry, res, dst, src, sizeof *_dst, 0); })
#define syscall_copy_obj_to_user_opt(entry, res, dst, src) \
  ({ typeof (dst) _dst = dst;						\
     syscall_copy_to_user (entry, res, dst, src, sizeof *_dst, 1); })

#define SYSCALL_PARAMS \
  struct eri_live_thread *th, struct eri_entry *entry,			\
  struct eri_registers *regs, struct eri_live_signal_thread *sig_th
#define SYSCALL_ARGS	th, entry, regs, sig_th

static uint64_t
syscall_copy_path_from_user (struct eri_live_thread *th,
			     char **path, const char *user_path)
{
  struct eri_mtpool *pool = th->group->pool;
  uint64_t len = ERI_PATH_MAX;
  char *t = eri_assert_mtmalloc (pool, len);
  if (! eri_entry__copy_str_from_user (th->entry, t, user_path, &len, 0))
    {
      eri_assert_mtfree (pool, t);
      return ERI_EFAULT;
    }
  if (len == ERI_PATH_MAX)
    {
      eri_assert_mtfree (pool, t);
      return ERI_ENAMETOOLONG;
    }
  *path = eri_assert_mtmalloc (pool, len + 1);
  eri_strcpy (*path, t);
  eri_assert_mtfree (pool, t);
  return 0;
}

static eri_noreturn void
syscall_do_no_sys (SYSCALL_PARAMS)
{
  /* XXX: inteneded not to impl for now.  */
  eri_entry__syscall_leave (entry, ERI_ENOSYS);
}

static eri_unused eri_noreturn void
syscall_do_res_in (SYSCALL_PARAMS)
{
  uint64_t res = eri_entry__syscall (entry);
  syscall_record_res_in (th, res);
  eri_entry__syscall_leave (entry, res);
}

static eri_noreturn void
syscall_do_res_io (SYSCALL_PARAMS)
{
  struct eri_syscall_res_io_record rec = { io_out (th) };
  rec.res.result = eri_entry__syscall (entry);
  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

static uint64_t
syscall_do_signal_thread (struct eri_live_thread *th)
{
  struct eri_sys_syscall_args args;
  struct eri_registers *regs = eri_entry__get_regs (th->entry);
  eri_init_sys_syscall_args_from_registers (&args, regs);
  return eri_live_signal_thread__syscall (th->sig_th, &args);
}

#define DEFINE_SYSCALL(name) \
static eri_noreturn void						\
ERI_PASTE (syscall_, name) (SYSCALL_PARAMS)

static eri_noreturn void
syscall_restart (struct eri_entry *entry)
{
  eri_entry__sig_wait_pending (entry, 0);
  eri_entry__restart (entry);
}

#define SYSCALL_TO_IMPL(name) \
DEFINE_SYSCALL (name)							\
{									\
  eri_info ("syscall not implemented: %lu\n", regs->rax);		\
  eri_entry__syscall_leave (th->entry, ERI_ENOSYS);			\
}

DEFINE_SYSCALL (clone)
{
  int32_t flags = regs->rdi;
  int32_t *user_ptid = (void *) regs->rdx;
  int32_t *user_ctid = (void *) regs->r10;
  /* XXX: support more */
  eri_assert (flags == ERI_CLONE_SUPPORTED_FLAGS);

  struct eri_live_thread__create_args create_args = { th };
  struct eri_live_signal_thread__clone_args args = { &create_args };

  if (! eri_live_signal_thread__clone (sig_th, &args))
    syscall_restart (entry);

  uint64_t res = args.result;
  struct eri_syscall_clone_record rec = {
    args.out, res, create_args.cth->id
  };

  if (eri_syscall_is_ok (res))
    {
      if (flags & ERI_CLONE_PARENT_SETTID)
	(void) eri_entry__copy_obj_to_user (entry, user_ptid, &res, 0);
      if (flags & ERI_CLONE_CHILD_SETTID)
	(void) eri_entry__copy_obj_to_user (entry, user_ctid, &res, 0);
      rec.id = create_args.cth->id;
      eri_assert_unlock (&create_args.cth->start_lock);
    }
  syscall_record (th, ERI_SYSCALL_CLONE_MAGIC, &rec);
  eri_entry__syscall_leave (entry, res);
}

SYSCALL_TO_IMPL (unshare)
SYSCALL_TO_IMPL (kcmp)
SYSCALL_TO_IMPL (fork)
SYSCALL_TO_IMPL (vfork)
SYSCALL_TO_IMPL (setns)

DEFINE_SYSCALL (set_tid_address)
{
  th->clear_user_tid = (void *) regs->rdi;
  eri_entry__syscall_leave (entry, 0);
}

static eri_noreturn void
syscall_do_exit (SYSCALL_PARAMS)
{
  eri_log (th->log.file, "exit\n");
  int32_t nr = regs->rax;
  uint8_t exit_group = nr == __NR_exit_group;
  int32_t status = regs->rdi;

  if (! eri_live_signal_thread__exit (sig_th, exit_group, status))
    syscall_restart (entry);

  struct eri_syscall_exit_record rec = { 0 };

  if (exit_group) goto out;

  uint64_t user_tid = (uint64_t) th->clear_user_tid;
  struct eri_live_atomic_args args = {
    th->log.file, entry, ERI_OP_ATOMIC_STORE,
    (void *) user_tid, sizeof (int32_t), &rec.clear_tid
  };
  eri_live_atomic (th->group->atomic, &args);
  if (rec.clear_tid.ok
      && ! eri_syscall_futex_check_user_addr (user_tid, page_size (th)))
    eri_live_thread_futex__wake (th->futex, user_tid, 1, -1);

out:
  rec.out = io_out (th);
  syscall_record (th, ERI_SYSCALL_EXIT_MAGIC, &rec);

  eri_log (th->log.file, "syscall exit\n");
  eri_assert_sys_exit_nr (nr, 0);
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
  struct eri_utsname utsname;
  eri_assert_syscall (uname, &utsname);

  struct eri_syscall_uname_record rec;

  eri_memset (&rec.utsname, 0, sizeof rec.utsname);
  eri_strcpy (rec.utsname.sysname, utsname.sysname);
  eri_strcpy (rec.utsname.nodename, utsname.nodename);
  eri_strcpy (rec.utsname.release, utsname.release);
  eri_strcpy (rec.utsname.version, utsname.version);
  eri_strcpy (rec.utsname.machine, utsname.machine);
  eri_strcpy (rec.utsname.domainname, utsname.domainname);

  rec.res.result = syscall_copy_obj_to_user (entry, 0,
					     user_utsname, &rec.utsname);
  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_UNAME_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

SYSCALL_TO_IMPL (sysinfo)
SYSCALL_TO_IMPL (getcpu)
SYSCALL_TO_IMPL (getrandom)

SYSCALL_TO_IMPL (setuid)
SYSCALL_TO_IMPL (getuid)
SYSCALL_TO_IMPL (setgid)
SYSCALL_TO_IMPL (getgid)
SYSCALL_TO_IMPL (geteuid)
SYSCALL_TO_IMPL (getegid)

DEFINE_SYSCALL (gettid)
{
  eri_entry__syscall_leave (entry, th->user_tid);
}

DEFINE_SYSCALL (getpid)
{
  eri_entry__syscall_leave (entry, th->group->user_pid);
}

DEFINE_SYSCALL (getppid)
{
  uint64_t res = syscall_do_signal_thread (th);
  syscall_record_res_in (th, res);
  eri_entry__syscall_leave (entry, res);
}

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

DEFINE_SYSCALL (time)
{
  int64_t *user_tloc = (void *) regs->rdi;

  uint64_t res = eri_entry__syscall (entry, (0, 0));
  res = syscall_copy_obj_to_user_opt (entry, res, user_tloc, &res);
  syscall_record_res_in (th, res);
  eri_entry__syscall_leave (entry, res);
}

DEFINE_SYSCALL (times)
{
  struct eri_tms *user_buf = (void *) regs->rdi;

  struct eri_syscall_times_record rec = { 0 };
  /* XXX: cutimes & cstimes */
  uint64_t res = eri_entry__syscall (entry, (0, user_buf ? &rec.tms : 0));
  rec.res.result = syscall_copy_obj_to_user_opt (entry, res,
						 user_buf, &rec.tms);
  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_TIMES_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

/* XXX: test */
DEFINE_SYSCALL (settimeofday)
{
  const struct eri_timeval *user_tv = (void *) regs->rdi;
  if (regs->rsi)
    non_conforming (th->log.file,
		    "tz for settimeofday is obsoleted, treat as NULL.");

  struct eri_timeval tv;
  if (user_tv
      && ! eri_entry__copy_obj_from_user (entry, &tv, user_tv, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  struct eri_syscall_res_io_record rec = { io_out (th) };

  rec.res.result = eri_entry__syscall (entry,
				       (0, user_tv ? &tv : 0), (1, 0));
  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (gettimeofday)
{
  struct eri_timeval *user_tv = (void *) regs->rdi;
  if (regs->rsi)
    non_conforming (th->log.file,
		    "tz for gettimeofday is obsoleted, treat as NULL.");

  struct eri_syscall_gettimeofday_record rec = { 0 };
  uint64_t res = eri_entry__syscall (entry,
				(0, user_tv ? &rec.time : 0), (1, 0));
  rec.res.result = syscall_copy_obj_to_user_opt (entry, res,
						 user_tv, &rec.time);
  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_GETTIMEOFDAY_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (clock_settime)
{
  int32_t id = regs->rdi;
  const struct eri_timespec *user_time = (void *) regs->rsi;

  eri_entry__syscall_leave_if_error (entry,
				     eri_syscall_check_clock_id (id));

  struct eri_timespec time;
  if (! eri_entry__copy_obj_from_user (entry, &time, user_time, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  struct eri_syscall_res_io_record rec = { io_out (th) };

  rec.res.result = eri_entry__syscall (entry, (1, &time));
  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

static eri_noreturn void
syscall_do_clock_gettime (SYSCALL_PARAMS)
{
  uint8_t time = (int32_t) regs->rax == __NR_clock_getres;
  int32_t id = regs->rdi;
  struct eri_timespec *user_time = (void *) regs->rsi;

  eri_entry__syscall_leave_if_error (entry,
				     eri_syscall_check_clock_id (id));

  struct eri_syscall_clock_gettime_record rec = { 0 };

  uint64_t res = eri_entry__syscall (entry,
				(1, user_time || ! time ? &rec.time : 0));

  rec.res.result = syscall_copy_to_user (entry, res, user_time,
				&rec.time, sizeof *user_time, ! time);

  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_CLOCK_GETTIME_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
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
    eri_entry__syscall_leave_if_error (entry,
				eri_syscall_check_clock_id (regs->rdi));

  struct eri_timex buf;
  if (! eri_entry__copy_obj_from_user (entry, &buf, user_buf, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  struct eri_syscall_res_io_record rec = {
    io_out (th), { eri_entry__syscall (entry, (clock ? 1 : 0, &buf)) }
  };
  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
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

  eri_entry__syscall_leave_if_error (entry,
		eri_syscall_check_prlimit64_resource (resource));

  struct eri_rlimit rlimit;
  if (! eri_entry__copy_obj_from_user (entry, &rlimit, user_rlimit, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  struct eri_syscall_res_in_record rec = {
    eri_entry__syscall (entry, (1, &rlimit)), io_in (th)
  };
  syscall_record (th, ERI_SYSCALL_RES_IN_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.result);
}

DEFINE_SYSCALL (getrlimit)
{
  int32_t resource = regs->rdi;
  struct eri_rlimit *user_rlimit = (void *) regs->rsi;

  eri_entry__syscall_leave_if_error (entry,
		eri_syscall_check_prlimit64_resource (resource));

  struct eri_syscall_getrlimit_record rec = { 0 };
  uint64_t res = eri_entry__syscall (entry, (1, &rec.rlimit));

  rec.res.result = syscall_copy_obj_to_user (entry, res,
					     user_rlimit, &rec.rlimit);
  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_GETRLIMIT_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (prlimit64)
{
  int32_t pid = eri_live_signal_thread__map_tid (sig_th, regs->rdi);
  int32_t resource = regs->rsi;
  const struct eri_rlimit *user_new_rlimit = (void *) regs->rdx;
  struct eri_rlimit *user_old_rlimit = (void *) regs->r10;

  eri_entry__syscall_leave_if_error (entry,
		eri_syscall_check_prlimit64_resource (resource));

  struct eri_rlimit new_rlimit;
  if (user_new_rlimit
      && ! eri_entry__copy_obj_from_user (entry, &new_rlimit,
					  user_new_rlimit, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  struct eri_syscall_prlimit64_record rec = { io_out (th) };

  uint64_t res = eri_entry__syscall (entry, (0, pid),
			(2, user_new_rlimit ? &new_rlimit : 0),
			(3, user_old_rlimit ? &rec.rlimit : 0));

  rec.res.result = syscall_copy_obj_to_user_opt (entry, res,
					user_old_rlimit, &rec.rlimit);
  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_PRLIMIT64_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (getrusage)
{
  int32_t who = regs->rdi;
  struct eri_rusage *user_rusage = (void *) regs->rsi;

  eri_entry__syscall_leave_if_error (entry,
		eri_syscall_check_getrusage_who (who));

  struct eri_syscall_getrusage_record rec = { 0 };
  uint8_t res = eri_entry__syscall (entry, (1, &rec.rusage));
  rec.res.result = syscall_copy_obj_to_user (entry, res,
					     user_rusage, &rec.rusage);
  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_GETRUSAGE_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

SYSCALL_TO_IMPL (capset)
SYSCALL_TO_IMPL (capget)

SYSCALL_TO_IMPL (personality)
SYSCALL_TO_IMPL (prctl)

DEFINE_SYSCALL (arch_prctl)
{
  /* XXX: warning for set gs */
  eri_entry__syscall_leave (entry, eri_entry__syscall (entry));
}

SYSCALL_TO_IMPL (quotactl)
SYSCALL_TO_IMPL (acct)

SYSCALL_TO_IMPL (setpriority)
SYSCALL_TO_IMPL (getpriority)

DEFINE_SYSCALL (sched_yield)
{
  eri_entry__syscall_leave (entry, eri_entry__syscall (entry));
}

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
  struct eri_sigset old_mask;
  old_mask = *eri_live_signal_thread__get_sig_mask (sig_th);

  struct eri_sigset mask;
  eri_entry__syscall_leave_if_error (entry,
	eri_entry__syscall_get_rt_sigprocmask (entry, &old_mask, &mask, 0));

  if (eri_entry__syscall_rt_sigprocmask_mask (entry))
    {
      if (! eri_live_signal_thread__sig_mask_async (sig_th, &mask))
	syscall_restart (entry);

      if (eri_live_signal_thread__signaled (sig_th))
	eri_entry__sig_wait_pending (entry, 0);
    }

  eri_entry__syscall_leave (entry,
	eri_entry__syscall_set_rt_sigprocmask (entry, &old_mask, 0));
}

DEFINE_SYSCALL (rt_sigaction)
{
  int32_t sig = regs->rdi;
  const struct eri_sigaction *user_act = (void *) regs->rsi;
  struct eri_sigaction *user_old_act = (void *) regs->rdx;

  if (! eri_sig_catchable (sig))
    eri_entry__syscall_leave (entry, ERI_EINVAL);

  if (! user_act && ! user_old_act)
    eri_entry__syscall_leave (entry, 0);

  struct eri_sigaction act;
  if (user_act && ! eri_entry__copy_obj_from_user (entry, &act, user_act, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  struct eri_sig_act old_act;
  struct eri_live_signal_thread__sig_action_args args = {
    sig, user_act ? &act : 0, user_old_act ? &old_act.act : 0
  };
  if (! eri_live_signal_thread__sig_action (sig_th, &args))
    syscall_restart (entry);

  uint64_t res = syscall_copy_obj_to_user_opt (entry, 0,
					       user_old_act, &old_act.act);

  if (user_old_act)
    {
      old_act.ver = args.ver;
      syscall_record (th, ERI_SYSCALL_RT_SIGACTION_MAGIC, &old_act);
    }
  else syscall_record (th, ERI_SYSCALL_RT_SIGACTION_SET_MAGIC,
		       (void *) args.ver);
  eri_entry__syscall_leave (entry, res);
}

DEFINE_SYSCALL (sigaltstack)
{
  eri_entry__syscall_leave (entry,
	eri_entry__syscall_sigaltstack (entry, &th->sig_alt_stack, 0));
}

DEFINE_SYSCALL (rt_sigreturn)
{
  if (! eri_live_signal_thread__sig_mask_all (sig_th))
    syscall_restart (entry);

  struct eri_stack st = {
    (uint64_t) th->sig_stack, ERI_SS_AUTODISARM, THREAD_SIG_STACK_SIZE
  };
  struct eri_sigset mask;

  if (! eri_entry__syscall_rt_sigreturn (entry, &st, &mask, 0))
    syscall_restart (entry);

  th->sig_alt_stack = st;
  eri_live_signal_thread__sig_reset (sig_th, &mask);
  eri_entry__leave (entry);
}

DEFINE_SYSCALL (rt_sigpending)
{
  eri_entry__syscall_leave_if_error (entry,
	eri_entry__syscall_validate_rt_sigpending (entry));

  struct eri_syscall_rt_sigpending_record rec = { 0 };

  struct eri_sys_syscall_args args = {
    __NR_rt_sigpending, { (uint64_t) &rec.set, ERI_SIG_SETSIZE }
  };
  rec.res.result = eri_live_signal_thread__syscall (sig_th, &args);

  eri_assert (eri_syscall_is_ok (rec.res.result));
  if (! eri_entry__copy_to_user (entry, (void *) regs->rdi,
				 &rec.set, ERI_SIG_SETSIZE, 0))
    rec.res.result = ERI_EFAULT;

  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_RT_SIGPENDING_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

static eri_noreturn void
syscall_do_pause (SYSCALL_PARAMS)
{
  eri_entry__sig_wait_pending (entry, 0);
  syscall_record_in (th);
  eri_entry__syscall_leave (entry, ERI_EINTR);
}

DEFINE_SYSCALL (pause) { syscall_do_pause (SYSCALL_ARGS); }

DEFINE_SYSCALL (rt_sigsuspend)
{
  const struct eri_sigset *user_mask = (void *) regs->rdi;
  uint64_t size = regs->rsi;

  if (size != ERI_SIG_SETSIZE)
    eri_entry__syscall_leave (entry, ERI_EINVAL);

  struct eri_sigset mask;
  if (! eri_entry__copy_obj_from_user (entry, &mask, user_mask, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  if (! eri_live_signal_thread__sig_tmp_mask_async (sig_th, &mask))
    syscall_restart (entry);

  syscall_do_pause (SYSCALL_ARGS);
}

DEFINE_SYSCALL (rt_sigtimedwait)
{
  const struct eri_sigset *user_set = (void *) regs->rdi;
  struct eri_siginfo *user_info = (void *) regs->rsi;
  const struct eri_timespec *user_timeout = (void *) regs->rdx;
  uint64_t size = regs->r10;

  struct eri_sigset set;
  struct eri_timespec timeout;

  if (size != ERI_SIG_SETSIZE) eri_entry__syscall_leave (entry, ERI_EINVAL);

  if (! eri_entry__copy_obj_from_user (entry, &set, user_set, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  if (user_timeout
      && !eri_entry__copy_obj_from_user (entry, &timeout, user_timeout, 0))
    eri_entry__syscall_leave (entry, ERI_EFAULT);

  const struct eri_sigset *mask
		= eri_live_signal_thread__get_sig_mask (sig_th);

  struct eri_sigset tmp_mask = *mask;
  eri_sig_diff_set (&tmp_mask, &set);

  eri_sig_and_set (&set, mask);
  eri_atomic_store (&th->sig_force_deliver, &set, 1);

  eri_assert (eri_live_signal_thread__sig_tmp_mask_async (sig_th, &tmp_mask));

  struct eri_syscall_rt_sigtimedwait_record rec = { 0 };

  if (! eri_entry__sig_wait_pending (entry, user_timeout ? &timeout : 0))
    {
      if (eri_live_signal_thread__sig_tmp_mask_async (sig_th, mask))
	{
	  eri_atomic_store (&th->sig_force_deliver, 0, 1);
	  rec.res.result = ERI_EAGAIN;
	  goto record;
	}
      eri_entry__sig_wait_pending (entry, 0);
    }

  eri_atomic_store (&th->sig_force_deliver, 0, 1);

  struct eri_siginfo *info = eri_entry__get_sig_info (entry);
  if (info->sig == ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP
      || ! eri_sig_set_set (&set, info->sig))
    {
      rec.res.result = ERI_EINTR;
      goto record;
    }

  rec.res.result = info->sig;
  if (user_info) rec.info = *info;
  else rec.info.sig = 0;

  eri_entry__clear_signal (entry);
  eri_live_signal_thread__sig_reset (sig_th, 0);

  rec.res.result = syscall_copy_obj_to_user_opt (entry, rec.res.result,
						 user_info, &rec.info);

record:
  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_RT_SIGTIMEDWAIT_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

static eri_noreturn void
syscall_do_kill (SYSCALL_PARAMS)
{
  struct eri_syscall_res_io_record rec = {
    io_out (th), { syscall_do_signal_thread (th) }
  };

  if (eri_syscall_is_ok (rec.res.result)
      && eri_live_signal_thread__signaled (sig_th))
    eri_entry__sig_wait_pending (entry, 0);

  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (kill) { syscall_do_kill (SYSCALL_ARGS); }
DEFINE_SYSCALL (tkill) { syscall_do_kill (SYSCALL_ARGS); }
DEFINE_SYSCALL (tgkill) { syscall_do_kill (SYSCALL_ARGS); }
DEFINE_SYSCALL (rt_sigqueueinfo) { syscall_do_kill (SYSCALL_ARGS); }
DEFINE_SYSCALL (rt_tgsigqueueinfo) { syscall_do_kill (SYSCALL_ARGS); }

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
  struct eri_live_thread_group *group = th->group;
  int32_t fd = regs->rdi;
  const struct eri_sigset *user_mask = (void *) regs->rsi;

  int32_t flags;
  eri_entry__syscall_leave_if_error (entry,
		eri_entry__syscall_get_signalfd (entry, &flags));

  struct eri_sigset mask;
  if (! eri_entry__copy_obj_from_user (entry, &mask, user_mask, 0))
    eri_entry__syscall_leave (entry, ERI_EINVAL); /* by kernel */

  struct eri_syscall_res_io_record rec = { io_out (th) };
  if (fd == -1)
    {
      int32_t fdf_flags = flags & ERI_SFD_NONBLOCK;
      flags |= ERI_SFD_NONBLOCK;

      eri_assert_lock (&group->fdf_lock);
      rec.res.result = eri_syscall (signalfd4, fd, &mask,
				    ERI_SIG_SETSIZE, flags);
      if (eri_syscall_is_ok (rec.res.result))
	fdf_alloc_insert (group, rec.res.result, fdf_flags, &mask);
      eri_assert_unlock (&group->fdf_lock);
      goto record;
    }

  struct fdf *fdf = fdf_try_lock (group, fd);
  if (! fdf) { rec.res.result = ERI_EBADF; goto record; }
  else if (! fdf->sig_mask)
    {
      rec.res.result = ERI_EINVAL;
      eri_assert_unlock (&group->fdf_lock);
      goto record;
    }

  eri_assert_lock (&fdf->sig_mask->lock);
  rec.res.result = eri_syscall (signalfd4, fd, &mask, ERI_SIG_SETSIZE, flags);
  if (eri_syscall_is_ok (rec.res.result)) fdf->sig_mask->mask = mask;
  eri_assert_unlock (&fdf->sig_mask->lock);
  eri_assert_unlock (&group->fdf_lock);

record:
  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
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
  struct eri_live_thread_group *group = th->group;

  uint8_t at = (int32_t) regs->rax == __NR_openat;
  /* XXX: The order of error check may changed.  */
  const char *user_path = (void *) (at ? regs->rsi : regs->rdi);
  char *path;
  /* XXX: /proc */
  eri_entry__syscall_leave_if_error (entry,
		syscall_copy_path_from_user (th, &path, user_path));

  struct eri_syscall_res_io_record rec = { io_out (th) };
  eri_assert_lock (&group->fdf_lock);
  rec.res.result = eri_entry__syscall_interruptible (entry,
						     (at ? 1 : 0, path));
  if (eri_syscall_is_ok (rec.res.result))
    {
      uint8_t openat = (int32_t) regs->rax == __NR_openat;
      int32_t fd = rec.res.result;
      int32_t flags = openat ? regs->rdx : regs->rsi;
      /*
       * XXX: the following two operations may cause crash when some
       * close is not done through us
       */
      if (! (flags & ERI_O_NONBLOCK)) /* to keep open blockable */
	eri_assert_syscall (fcntl, fd, ERI_F_SETFL, flags | ERI_O_NONBLOCK);
      fdf_alloc_insert (th->group, fd, flags & ERI_O_NONBLOCK, 0);
    }
  eri_assert_unlock (&group->fdf_lock);

  if (rec.res.result == ERI_EINTR) eri_entry__sig_wait_pending (entry, 0);
  syscall_record_res_io (th, &rec);
  eri_assert_mtfree (group->pool, path);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (open) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (openat) { syscall_do_open (SYSCALL_ARGS); }
DEFINE_SYSCALL (creat) { syscall_do_open (SYSCALL_ARGS); }

DEFINE_SYSCALL (close)
{
  struct eri_live_thread_group *group = th->group;
  int32_t fd = regs->rdi;

  struct eri_syscall_res_io_record rec = { io_out (th) };
  struct fdf *fdf = fdf_try_lock (group, fd);
  if (! fdf) { rec.res.result = ERI_EBADF; goto record; }

  struct eri_sys_syscall_args args = { __NR_close, { fd } };
  rec.res.result = eri_entry__sys_syscall_interruptible (entry, &args);

  if (eri_syscall_is_ok (rec.res.result))
    fdf_remove_free (group, fdf);
  eri_assert_unlock (&group->fdf_lock);

record:
  if (rec.res.result == ERI_EINTR) eri_entry__sig_wait_pending (entry, 0);
  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (dup)
{
  struct eri_live_thread_group *group = th->group;
  int32_t fd = regs->rdi;

  struct eri_syscall_res_io_record rec = { io_out (th) };
  struct fdf *fdf = fdf_try_lock (group, fd);
  if (! fdf) { rec.res.result = ERI_EBADF; goto record; }

  rec.res.result = eri_syscall (dup, fd);

  if (eri_syscall_is_ok (rec.res.result))
    fdf_dup (group, rec.res.result, fdf);
  eri_assert_unlock (&group->fdf_lock);

record:
  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

static eri_noreturn void
syscall_do_dup2 (SYSCALL_PARAMS)
{
  struct eri_live_thread_group *group = th->group;
  uint8_t dup3 = (int32_t) regs->rax == __NR_dup3;
  int32_t fd = regs->rdi;
  int32_t new_fd = regs->rsi;
  int32_t flags = dup3 ? regs->rdx : 0;

  if (fd == new_fd)
    eri_entry__syscall_leave (entry, dup3 ? ERI_EINVAL : new_fd);

  struct eri_syscall_res_io_record rec = { io_out (th) };
  struct fdf *fdf = fdf_try_lock (group, fd);
  if (! fdf) { rec.res.result = ERI_EBADF; goto record; }

  rec.res.result = eri_syscall (dup3, fd, new_fd, flags);

  if (eri_syscall_is_ok (rec.res.result))
    {
      new_fd = rec.res.result;
      struct fdf *new_fdf = fdf_rbt_get (group, &new_fd, ERI_RBT_EQ);
      if (new_fdf) fdf_remove_free (group, new_fdf);

      fdf_dup (group, new_fd, fdf);
    }
  eri_assert_unlock (&group->fdf_lock);

record:
  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (dup2) { syscall_do_dup2 (SYSCALL_ARGS); }
DEFINE_SYSCALL (dup3) { syscall_do_dup2 (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (name_to_handle_at)
SYSCALL_TO_IMPL (open_by_handle_at)

DEFINE_SYSCALL (fcntl)
{
  struct eri_live_thread_group *group = th->group;
  int32_t fd = regs->rdi;
  int32_t cmd = regs->rsi;

  if (cmd == ERI_F_DUPFD || cmd == ERI_F_DUPFD_CLOEXEC
      || cmd == ERI_F_GETFL || cmd == ERI_F_SETFL)
    {
      struct eri_syscall_res_io_record rec = { io_out (th) };
      struct fdf *fdf = fdf_try_lock (group, fd);
      if (! fdf) { rec.res.result = ERI_EBADF; goto record_kill; }

      if (cmd == ERI_F_SETFL)
	rec.res.result = eri_syscall (fcntl, fd, cmd,
				  regs->rdx | ERI_O_NONBLOCK);
      else rec.res.result = eri_syscall (fcntl, fd, cmd, regs->rdx);

      if (eri_syscall_is_ok (rec.res.result))
	{
	  if (cmd == ERI_F_DUPFD || cmd == ERI_F_DUPFD_CLOEXEC)
	    fdf_dup (group, rec.res.result, fdf);
	  else if (cmd == ERI_F_GETFL)
	    rec.res.result &= fdf->flags | ~ERI_O_NONBLOCK;
	  else fdf->flags = regs->rdx & ERI_O_NONBLOCK;
	}
      eri_assert_unlock (&group->fdf_lock);

    record_kill:
      syscall_record_res_io (th, &rec);
      eri_entry__syscall_leave (entry, rec.res.result);
    }

  /* TODO: other cmd */
  eri_entry__syscall_leave (entry, eri_entry__syscall (entry));
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
syscall_read_sig_fd (struct eri_live_thread *th,
		     struct eri_sys_syscall_args *args, int32_t flags,
		     struct fdf_sig_mask *mask)
{
  struct eri_live_thread_group *group = th->group;
  struct eri_live_signal_thread *sig_th = th->sig_th;
  eri_atomic_inc (&mask->ref_count, 0);
  eri_assert_unlock (&group->fdf_lock);

  struct eri_live_signal_thread__sig_fd_read_args read_args = {
    args, flags, &mask->lock, &mask->mask
  };
  uint8_t done = eri_live_signal_thread__sig_fd_read (sig_th, &read_args);

  if (! eri_atomic_dec_fetch (&mask->ref_count, 1))
    eri_assert_mtfree (group->pool, mask);
  return done;
}

/*
 * This is so mainly because initialy we want to record the order
 * of memory related info, e.g. EFAULT, the idea is dropped as discussed
 * in the guide of syscalls. This is preserved now for the consistency
 * with signalfd, see signal-thread.c, and it's not that hard to impl.
 */
static uint64_t
syscall_read_write (struct eri_entry *entry, int32_t flags,
		    struct eri_sys_syscall_args *args, uint8_t read)
{
  uint64_t res = eri_sys_syscall (args);
  if ((flags & ERI_O_NONBLOCK) || res != ERI_EAGAIN) return res;

  int32_t fd = args->a[0];
  struct eri_pollfd pollfd = { fd, read ? ERI_POLLIN : ERI_POLLOUT };
  struct eri_sys_syscall_args poll_args = {
    __NR_poll, { (uint64_t) &pollfd, 1, -1 }
  };

  do
    {
      res = eri_entry__sys_syscall_interruptible (entry, &poll_args);
      if (res == ERI_EINTR) break;

      res = eri_sys_syscall (args);
    }
  while (res == ERI_EAGAIN);
  return res;
}

static void
syscall_record_read (struct eri_live_thread *th, uint64_t res,
		     void *dst, uint8_t readv)
{
  struct eri_syscall_res_in_record rec = { res, io_in (th) };
  eri_live_thread_recorder__rec_syscall_read (th->rec, &rec, readv, dst);
}

static eri_noreturn void
syscall_do_read (SYSCALL_PARAMS)
{
  struct eri_live_thread_group *group = th->group;
  int32_t nr = regs->rax;
  int32_t fd = regs->rdi;
  uint64_t buf = regs->rsi;
  uint64_t count = regs->rdx;

  eri_entry__test_invalidate (entry, &buf);

  uint64_t res;

  struct fdf *fdf = fdf_try_lock (group, fd);
  if (! fdf) { res = ERI_EBADF; goto record; }

  int32_t flags = fdf->flags;
  struct eri_sys_syscall_args args = { nr, { fd, buf, count, regs->r10 } };

  if (fdf->sig_mask)
    {
      if (! syscall_read_sig_fd (th, &args, flags, fdf->sig_mask))
	syscall_restart (entry);

      res = args.result;
      goto record;
    }

  eri_assert_unlock (&group->fdf_lock);
  res = syscall_read_write (entry, flags, &args, 1);

record:
  if (res == ERI_EINTR) eri_entry__sig_wait_pending (entry, 0);
  syscall_record_read (th, res, (void *) buf, 0);
  eri_entry__syscall_leave (entry, res);
}

static eri_noreturn void
syscall_do_readv (SYSCALL_PARAMS)
{
  struct eri_live_thread_group *group = th->group;
  int32_t nr = regs->rax;
  int32_t fd = regs->rdi;

  struct eri_iovec *iov;
  int32_t iov_cnt;
  eri_entry__syscall_leave_if_error (entry,
		eri_entry__syscall_get_rw_iov (entry, &iov, &iov_cnt, 0));

  uint64_t res;

  struct fdf *fdf = fdf_try_lock (group, fd);
  if (! fdf) { res = ERI_EBADF; goto record; }

  int flags = fdf->flags;
  struct eri_sys_syscall_args args = {
    nr, { fd, (uint64_t) iov, iov_cnt, regs->r10, regs->r8 }
  };

  if (fdf->sig_mask)
    {
      if (! syscall_read_sig_fd (th, &args, flags, fdf->sig_mask))
	{
	  eri_assert_mtfree (group->pool, iov);
	  syscall_restart (entry);
	}

      res = args.result;
      goto record;
    }

  eri_assert_unlock (&group->fdf_lock);
  res = syscall_read_write (entry, flags, &args, 1);

record:
  if (res == ERI_EINTR) eri_entry__sig_wait_pending (entry, 0);
  syscall_record_read (th, res, iov, 1);
  eri_entry__syscall_free_rw_iov (entry, iov);
  eri_entry__syscall_leave (entry, res);
}

DEFINE_SYSCALL (read) { syscall_do_read (SYSCALL_ARGS); }
DEFINE_SYSCALL (pread64) { syscall_do_read (SYSCALL_ARGS); }
DEFINE_SYSCALL (readv) { syscall_do_readv (SYSCALL_ARGS); }
DEFINE_SYSCALL (preadv) { syscall_do_readv (SYSCALL_ARGS); }
DEFINE_SYSCALL (preadv2) { syscall_do_readv (SYSCALL_ARGS); }

static eri_noreturn void
syscall_do_write (SYSCALL_PARAMS)
{
  struct eri_live_thread_group *group = th->group;
  int32_t nr = regs->rax;
  int32_t fd = regs->rdi;
  uint64_t buf = regs->rsi;
  uint64_t count = regs->rdx;

  eri_entry__test_invalidate (entry, &buf);

  struct eri_syscall_res_io_record rec = { io_out (th) };

  struct fdf *fdf = fdf_try_lock (group, fd);
  if (! fdf) { rec.res.result = ERI_EBADF; goto record; }
  if (fdf->sig_mask) { rec.res.result = ERI_EINVAL; goto record; }

  int32_t flags = fdf->flags;
  struct eri_sys_syscall_args args = { nr, { fd, buf, count, regs->r10 } };

  eri_assert_unlock (&group->fdf_lock);
  rec.res.result = syscall_read_write (entry, flags, &args, 0);

record:
  syscall_record_res_io (th, &rec);
  eri_entry__syscall_leave (entry, rec.res.result);
}

static eri_noreturn void
syscall_do_writev (SYSCALL_PARAMS)
{
  struct eri_live_thread_group *group = th->group;
  int32_t nr = regs->rax;
  int32_t fd = regs->rdi;

  struct eri_iovec *iov;
  int32_t iov_cnt;
  eri_entry__syscall_leave_if_error (entry,
		eri_entry__syscall_get_rw_iov (entry, &iov, &iov_cnt, 0));

  struct eri_syscall_res_io_record rec = { io_out (th) };

  struct fdf *fdf = fdf_try_lock (group, fd);
  if (! fdf) { rec.res.result = ERI_EBADF; goto record; }
  if (fdf->sig_mask) { rec.res.result = ERI_EINVAL; goto record; }

  int32_t flags = fdf->flags;
  struct eri_sys_syscall_args args = {
    nr, { fd, (uint64_t) iov, iov_cnt, regs->r10, regs->r8 }
  };

  eri_assert_unlock (&group->fdf_lock);
  rec.res.result = syscall_read_write (entry, flags, &args, 0);

record:
  syscall_record_res_io (th, &rec);
  eri_assert_mtfree (group->pool, iov);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (write) { syscall_do_write (SYSCALL_ARGS); }
DEFINE_SYSCALL (pwrite64) { syscall_do_write (SYSCALL_ARGS); }
DEFINE_SYSCALL (writev) { syscall_do_writev (SYSCALL_ARGS); }
DEFINE_SYSCALL (pwritev) { syscall_do_writev (SYSCALL_ARGS); }
DEFINE_SYSCALL (pwritev2) { syscall_do_writev (SYSCALL_ARGS); }

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

DEFINE_SYSCALL (lseek) { syscall_do_res_io (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (ioctl)

static eri_noreturn void
syscall_do_stat (SYSCALL_PARAMS)
{
  int32_t nr = (int32_t) regs->rax;
  uint8_t at = nr == __NR_newfstatat;
  uint64_t fd_or_path = regs->rdi;
  if (nr != __NR_fstat)
    {
      const char *user_path = (void *) (at ? regs->rsi : regs->rdi);
      eri_entry__syscall_leave_if_error (entry,
	syscall_copy_path_from_user (th, (void *) &fd_or_path, user_path));
    }

  struct eri_stat *user_stat = (void *) (at ? regs->rdx : regs->rsi);

  struct eri_syscall_stat_record rec = { 0 };
  uint64_t res = eri_entry__syscall (entry,
			(at ? 1 : 0, fd_or_path), (at ? 2 : 1, &rec.stat));
  rec.res.result = syscall_copy_obj_to_user (entry, res,
					     user_stat, &rec.stat);
  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_STAT_MAGIC, &rec);
  if (nr != __NR_fstat)
    eri_assert_mtfree (th->group->pool, (void *) fd_or_path);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (stat) { syscall_do_stat (SYSCALL_ARGS); }
DEFINE_SYSCALL (fstat) { syscall_do_stat (SYSCALL_ARGS); }
DEFINE_SYSCALL (newfstatat) { syscall_do_stat (SYSCALL_ARGS); }
DEFINE_SYSCALL (lstat) { syscall_do_stat (SYSCALL_ARGS); }

static eri_noreturn void
syscall_do_access (SYSCALL_PARAMS)
{
  int32_t nr = regs->rax;
  uint8_t at = nr == __NR_unlinkat || nr == __NR_faccessat
	       || nr == __NR_fchmodat;
  uint8_t io = nr != __NR_access && nr != __NR_faccessat;

  const char *user_path = (void *) (at ? regs->rsi : regs->rdi);
  char *path;
  eri_entry__syscall_leave_if_error (entry,
		syscall_copy_path_from_user (th, &path, user_path));

  uint64_t res;
  if (io)
    {
      struct eri_syscall_res_io_record rec = { io_out (th) };
      res = rec.res.result = eri_entry__syscall (entry, (at ? 1 : 0, path));
      syscall_record_res_io (th, &rec);
    }
  else
    {
      res = eri_entry__syscall (entry, (at ? 1 : 0, path));
      syscall_record_res_in (th, res);
    }
  eri_assert_mtfree (th->group->pool, path);
  eri_entry__syscall_leave (entry, res);
}

DEFINE_SYSCALL (access) { syscall_do_access (SYSCALL_ARGS); }
DEFINE_SYSCALL (faccessat) { syscall_do_access (SYSCALL_ARGS); }

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

static eri_noreturn void
syscall_do_getdents (SYSCALL_PARAMS)
{
  struct eri_sys_syscall_args args;
  eri_init_sys_syscall_args_from_registers (&args, regs);
  eri_entry__test_invalidate (entry, args.a + 1);
  uint64_t res = eri_sys_syscall (&args);

  syscall_record_read (th, res, (void *) args.a[1], 0);
  eri_entry__syscall_leave (entry, res);
}

DEFINE_SYSCALL (getdents) { syscall_do_getdents (SYSCALL_ARGS); }
DEFINE_SYSCALL (getdents64) { syscall_do_getdents (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (getcwd)
SYSCALL_TO_IMPL (chdir)
SYSCALL_TO_IMPL (fchdir)

static eri_noreturn void
syscall_do_rename (SYSCALL_PARAMS)
{
  int32_t nr = regs->rax;
  uint8_t oldpath_idx = ! (nr == __NR_rename || nr == __NR_link
			   || nr == __NR_symlink || nr == __NR_symlinkat);
  uint8_t newpath_idx = (nr == __NR_rename || nr == __NR_link
		|| nr == __NR_symlink) ? 1 : (nr == __NR_symlinkat ? 2 : 3);
  const char *user_oldpath = (void *) (oldpath_idx ? regs->rsi : regs->rdi);
  const char *user_newpath = (void *) (newpath_idx == 1 ? regs->rsi
				: (newpath_idx == 2 ? regs->rdx : regs->r10));
  char *oldpath, *newpath;
  eri_entry__syscall_leave_if_error (entry,
		syscall_copy_path_from_user (th, &oldpath, user_oldpath));
  uint64_t res = syscall_copy_path_from_user (th, &newpath, user_newpath);
  if (eri_syscall_is_error (res))
    {
      eri_assert_mtfree (th->group->pool, oldpath);
      eri_entry__syscall_leave (entry, res);
    }

  struct eri_syscall_res_io_record rec = { io_out (th) };
  rec.res.result = eri_entry__syscall (entry,
				(oldpath_idx, oldpath), (newpath_idx, newpath));
  syscall_record_res_io (th, &rec);
  eri_assert_mtfree (th->group->pool, oldpath);
  eri_assert_mtfree (th->group->pool, newpath);
  eri_entry__syscall_leave (entry, rec.res.result);
}

DEFINE_SYSCALL (rename) { syscall_do_rename (SYSCALL_ARGS); }
DEFINE_SYSCALL (renameat) { syscall_do_rename (SYSCALL_ARGS); }
DEFINE_SYSCALL (renameat2) { syscall_do_rename (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (mkdir)
SYSCALL_TO_IMPL (mkdirat)
SYSCALL_TO_IMPL (rmdir)

DEFINE_SYSCALL (link) { syscall_do_rename (SYSCALL_ARGS); }
DEFINE_SYSCALL (linkat) { syscall_do_rename (SYSCALL_ARGS); }
DEFINE_SYSCALL (unlink) { syscall_do_access (SYSCALL_ARGS); }
DEFINE_SYSCALL (unlinkat) { syscall_do_access (SYSCALL_ARGS); }
DEFINE_SYSCALL (symlink) { syscall_do_rename (SYSCALL_ARGS); }
DEFINE_SYSCALL (symlinkat) { syscall_do_rename (SYSCALL_ARGS); }

static uint64_t
syscall_do_readlink_buf (struct eri_entry *entry, uint8_t at,
			 char *buf, uint64_t size)
{
  return eri_entry__syscall (entry, (at ? 2 : 1, buf), (at ? 3 : 2, size));
}

/* TODO */
static eri_noreturn void
syscall_do_readlink (SYSCALL_PARAMS)
{
  uint8_t at = (int32_t) regs->rax == __NR_readlinkat;
  const char *user_path = (void *) (at ? regs->rsi : regs->rdi);
  char *path;
  eri_entry__syscall_leave_if_error (entry,
		syscall_copy_path_from_user (th, &path, user_path));

  struct eri_mtpool *pool = th->group->pool;

  char *user_buf = (void *) (at ? regs->rdx : regs->rsi);
  uint64_t buf_size = at ? regs->r10 : regs->rdx;

  char *buf = 0;
  uint64_t res;

  struct eri_syscall_res_in_record rec = { 0 };
  if (buf_size == 0)
    {
      rec.result = res = eri_entry__syscall (entry);
      goto record;
    }

  if (buf_size > ERI_PATH_MAX)
    {
      uint64_t size = ERI_PATH_MAX;
      while (1)
	{
	  buf = eri_assert_mtmalloc (pool, size);
	  res = syscall_do_readlink_buf (entry, at, buf, size);
	  if (res != size) break;
	  eri_assert_mtfree (pool, buf);
	  size = eri_min (size * 2, buf_size);
	}
    }
  else
    {
      buf = eri_assert_mtmalloc (pool, buf_size);
      res = syscall_do_readlink_buf (entry, at, buf, buf_size);
    }

  rec.result = eri_syscall_is_ok (res)
	       && ! eri_entry__copy_to_user (entry, user_buf, buf, res, 0)
		? ERI_EFAULT : res;

record:
  rec.in = io_in (th);
  eri_live_thread_recorder__rec_syscall_readlink (th->rec, &rec, buf,
					eri_syscall_is_ok (res) ? res : 0);
  eri_assert_mtfree (pool, path);
  if (buf) eri_assert_mtfree (pool, buf);
  eri_entry__syscall_leave (entry, rec.result);
}

DEFINE_SYSCALL (readlink) { syscall_do_readlink (SYSCALL_ARGS); }
DEFINE_SYSCALL (readlinkat) { syscall_do_readlink (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (mknod)
SYSCALL_TO_IMPL (mknodat)

SYSCALL_TO_IMPL (umask)

DEFINE_SYSCALL (chmod) { syscall_do_access (SYSCALL_ARGS); }
DEFINE_SYSCALL (fchmod) { syscall_do_res_io (SYSCALL_ARGS); }
DEFINE_SYSCALL (fchmodat) { syscall_do_access (SYSCALL_ARGS); }

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

DEFINE_SYSCALL (mmap)
{
  uint64_t len = regs->rsi;
  int32_t flags = regs->r10;

  /* XXX: handle more */
  if (flags & ERI_MAP_GROWSDOWN)
    non_conforming (th->log.file, "map grows down\n");

  if ((flags & ERI_MAP_TYPE) == ERI_MAP_SHARED
      && (flags & ERI_MAP_TYPE) == ERI_MAP_SHARED_VALIDATE)
    non_conforming (th->log.file, "map shared\n");

  if (! len) eri_entry__syscall_leave (entry, ERI_EINVAL);

  int32_t prot = regs->rdx;
  uint8_t anony = !! (flags & ERI_MAP_ANONYMOUS);
  /*
   * XXX: rec_mmap can't handle file mapping with no read permission.
   * We can't do:
   * 1. map with read permission and then remove it,
   * 2. map to our space and remap it,
   * for both are not atomic.
   * We can delay the record until this area becomes readable, for which
   * we need to do some bookkeeping.
   */
  if (! anony && ! (prot & ERI_PROT_READ))
    {
      non_conforming (th->log.file,
	"non anonymosu mapping with no read permission is not supported, "
	"read permission is implied\n");
      prot |= ERI_PROT_READ;
    }
  prot = eri_common_get_mem_prot (prot);

  struct eri_live_thread_group *group = th->group;
  eri_assert_lock (&group->mm_lock);
  struct eri_syscall_res_in_record rec = {
    eri_syscall (mmap, regs->rdi, len, prot, flags, regs->r8, regs->r9),
    group->mm++
  };
  eri_assert_unlock (&group->mm_lock);

  eri_live_thread_recorder__rec_syscall_mmap (th->rec, &rec,
					      anony ? 0 : len);
  eri_entry__syscall_leave (entry, rec.result);
}

static eri_noreturn void
syscall_do_munmap (SYSCALL_PARAMS)
{
  struct eri_live_thread_group *group = th->group;
  eri_assert_lock (&group->mm_lock);
  struct eri_syscall_res_in_record rec = {
    eri_entry__syscall (entry), group->mm++
  };
  eri_assert_unlock (&group->mm_lock);
  syscall_record (th, ERI_SYSCALL_RES_IN_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.result);
}

DEFINE_SYSCALL (mprotect)
{
  struct eri_live_thread_group *group = th->group;
  eri_assert_lock (&group->mm_lock);
  int32_t prot = eri_common_get_mem_prot (regs->rdx);
  struct eri_syscall_res_in_record rec = {
    eri_syscall (mprotect, regs->rdi, regs->rsi, prot), group->mm++
  };
  eri_assert_unlock (&group->mm_lock);
  syscall_record (th, ERI_SYSCALL_RES_IN_MAGIC, &rec);
  eri_entry__syscall_leave (entry, rec.result);
}

DEFINE_SYSCALL (munmap) { syscall_do_munmap (SYSCALL_ARGS); }

SYSCALL_TO_IMPL (mremap)

DEFINE_SYSCALL (madvise) { syscall_do_res_io (SYSCALL_ARGS); }

DEFINE_SYSCALL (brk) { syscall_do_munmap (SYSCALL_ARGS); }

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
syscall_futex_get_timeout (struct eri_entry *entry,
	const struct eri_timespec *user_timeout, struct eri_timespec *timeout)
{
  if (! user_timeout) return 0;
  if (! eri_entry__copy_obj_from_user (entry, timeout, user_timeout, 0))
    return ERI_EFAULT;
  /* This complicates the replay, let kernel check.  */
#if 0
  if ((int64_t) timeout->sec < 0 || timeout->nsec >= 1000000000)
    return ERI_EINVAL;
#endif
  return 0;
}

static uint64_t
syscall_futex_check_wait (struct eri_live_thread *th, uint64_t user_addr,
	const struct eri_timespec *user_timeout, struct eri_timespec *timeout)
{
  return eri_syscall_futex_check_user_addr (user_addr, page_size (th))
	   ? : syscall_futex_get_timeout (th->entry, user_timeout, timeout);
}

static eri_noreturn void
syscall_do_futex_record_leave (struct eri_live_thread *th,
			       struct eri_syscall_futex_record *rec)
{
  rec->res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_FUTEX_MAGIC, rec);
  eri_entry__syscall_leave (th->entry, rec->res.result);
}

static eri_noreturn void
syscall_do_futex_wait (SYSCALL_PARAMS)
{
  uint64_t user_addr = regs->rdi;
  uint32_t op = regs->rsi;
  int32_t val = regs->rdx;
  const struct eri_timespec *user_timeout = (void *) regs->r10;
  uint32_t cmd = op & ERI_FUTEX_CMD_MASK;
  uint32_t mask = cmd == ERI_FUTEX_WAIT ? -1 : regs->r9;

  struct eri_timespec timeout;
  eri_entry__syscall_leave_if_error (entry,
	syscall_futex_check_wait (th, user_addr, user_timeout, &timeout));

  if (! mask) eri_entry__syscall_leave (entry, ERI_EINVAL);

  struct eri_syscall_futex_record rec = { 0 };
  struct eri_live_thread_futex__wait_args args = {
    user_addr, val, mask, cmd != ERI_FUTEX_WAIT,
    !! (op & ERI_FUTEX_CLOCK_REALTIME), user_timeout ? &timeout : 0, &rec
  };
  eri_live_thread_futex__wait (th->futex, &args);

  if (rec.res.result == ERI_EINTR) eri_entry__sig_wait_pending (entry, 0);
  syscall_do_futex_record_leave (th, &rec);
}

static eri_noreturn void
syscall_do_futex_wake (SYSCALL_PARAMS)
{
  uint64_t user_addr = regs->rdi;
  uint32_t op = regs->rsi;
  int32_t max = regs->rdx;
  uint32_t mask = (op & ERI_FUTEX_CMD_MASK) == ERI_FUTEX_WAKE ? -1 : regs->r9;

  eri_entry__syscall_leave_if_error (entry,
	eri_syscall_futex_check_wake (op, mask, user_addr, page_size (th)));

  uint64_t res = eri_live_thread_futex__wake (th->futex,
					      user_addr, max, mask);
  syscall_record_res_in (th, res);
  eri_entry__syscall_leave (entry, res);
}

static eri_noreturn void
syscall_do_futex_requeue (SYSCALL_PARAMS)
{
  uint64_t user_addr[] = { regs->rdi, regs->r8 };
  uint32_t op = regs->rsi;
  int32_t val = regs->rdx;
  int32_t val2 = regs->r10;
  int32_t val3 = regs->r9;

  int32_t cmd = op & ERI_FUTEX_CMD_MASK;

  eri_entry__syscall_leave_if_error (entry,
	eri_syscall_futex_check_wake2 (op, -1, user_addr, page_size (th)));

  struct eri_syscall_futex_requeue_record rec = { 0 };

  struct eri_live_thread_futex__requeue_args args = {
    { user_addr[0], user_addr[1] }, val, val2,
    cmd != ERI_FUTEX_REQUEUE, val3, &rec
  };
  eri_live_thread_futex__requeue (th->futex, &args);

  rec.res.in = io_in (th);
  syscall_record (th, ERI_SYSCALL_FUTEX_REQUEUE_MAGIC, &rec);

  eri_entry__syscall_leave (entry, rec.res.result);
}

static eri_noreturn void
syscall_do_futex_wake_op (SYSCALL_PARAMS)
{
  uint64_t user_addr[] = { regs->rdi, regs->r8 };
  uint32_t op = regs->rsi;
  int32_t val = regs->rdx;
  int32_t val2 = regs->r10;
  int32_t val3 = regs->r9;

  eri_entry__syscall_leave_if_error (entry,
	eri_syscall_futex_check_wake2 (op, -1, user_addr, page_size (th)));

  uint8_t op_op = eri_futex_op_get_op (val3);
  uint8_t op_cmp = eri_futex_op_get_cmp (val3);
  int32_t op_arg = eri_futex_op_get_arg (val3);
  int32_t op_cmp_arg = eri_futex_op_get_cmp_arg (val3);

  if (op_op >= ERI_FUTEX_OP_NUM || op_cmp >= ERI_FUTEX_OP_CMP_NUM)
    eri_entry__syscall_leave (entry, ERI_ENOSYS);

  struct eri_syscall_futex_record rec = { 0 };
  struct eri_live_thread_futex__wake_op_args args = {
    { user_addr[0], user_addr[1] }, { val, val2 },
    op_op, op_cmp, op_arg, op_cmp_arg, &rec
  };
  eri_live_thread_futex__wake_op (th->futex, &args);

  syscall_do_futex_record_leave (th, &rec);
}

DEFINE_SYSCALL (futex)
{
  uint32_t op = regs->rsi;

#if 0
  if (! (op & ERI_FUTEX_PRIVATE_FLAG))
    non_conforming (th->log.file, "shared futex is not supported\n");

  uint64_t user_addr = regs->rdi;
  uint32_t op = regs->rsi;
  int32_t val = regs->rdx;
  const struct eri_timespec *user_timeout = (void *) regs->r10;
  int32_t val2 = regs->r10;
  uint64_t user_addr2 = regs->r8;
  int32_t val3 = regs->r9;
#endif

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
    default: eri_entry__syscall_leave (entry, ERI_ENOSYS);
    }
}

DEFINE_SYSCALL (set_robust_list) { syscall_do_no_sys (SYSCALL_ARGS); }
DEFINE_SYSCALL (get_robust_list) { syscall_do_no_sys (SYSCALL_ARGS); }

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

SYSCALL_TO_IMPL (remap_file_pages)

static eri_noreturn void
syscall (struct eri_live_thread *th)
{
  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);

  switch ((int32_t) regs->rax)
    {
#define SYSCALL_CASE(name) \
  case ERI_PASTE (__NR_, name):						\
    ERI_PASTE (syscall_, name) (th, entry, regs, th->sig_th);

    ERI_SYSCALLS (SYSCALL_CASE)
    default: eri_entry__syscall_leave (entry, ERI_ENOSYS);
    }
}

static eri_noreturn void
sync_async (struct eri_live_thread *th)
{
  struct eri_entry *entry = th->entry;
  struct eri_registers *regs = eri_entry__get_regs (entry);
  eri_live_thread_recorder__rec_sync_async (th->rec, regs->rcx);
  eri_entry__leave (entry);
}

/*
 * Guide of atomics:
 * Adding an atomic op is relatively easy, but there are several places
 * to modify:
 * 1. common/common.h, to add the op code;
 * 2. common/common.h, _ERI_DEFINE_DO_ATOMIC_TYPE to impl it, which needs
 *    lib/atomic*.h;
 * 3. common/entry.c, eri_entry__atomic_leave to see if it needs interleave;
 * 4. public/impl.h, to impl the interface;
 * 5. public/public.h.in.m4, and public/public.h.m4, to add the interface;
 * 6. ers/public.h.m4, to export the interface;
 * 7. test...
 */

static eri_noreturn void
atomic (struct eri_live_thread *th)
{
  struct eri_entry *entry = th->entry;

  uint16_t code = eri_entry__get_op_code (entry);
  struct eri_registers *regs = eri_entry__get_regs (entry);

  uint64_t old;
  struct eri_atomic_record rec = { 0 };

  struct eri_live_atomic_args args = {
    th->log.file, entry, code, (void *) eri_entry__get_atomic_mem (entry),
    eri_entry__get_atomic_size (entry),
    &rec, code == ERI_OP_ATOMIC_CMPXCHG ? &regs->rax : &old,
    eri_entry__get_atomic_val (entry), &regs->rflags
  };
  eri_live_atomic (th->group->atomic, &args);

  if (! rec.ok)
    {
      if (eri_si_access_fault (eri_entry__get_sig_info (entry)))
	eri_live_thread_recorder__rec_atomic (th->rec, &rec);

      eri_entry__restart (entry);
    }

  eri_live_thread_recorder__rec_atomic (th->rec, &rec);
  eri_entry__atomic_leave (entry, old);
}

static eri_noreturn void
main_entry (struct eri_entry *entry)
{
  struct eri_live_thread *th = eri_entry__get_th (entry);
  uint16_t code = eri_entry__get_op_code (entry);
  if (code == ERI_OP_SYSCALL) syscall (th);
  else if (code == ERI_OP_SYNC_ASYNC) sync_async (th);
  else if (eri_op_is_pub_atomic (code)) atomic (th);
  else eri_assert_unreachable (); /* XXX: invalid argument */
}

static void
record_signal (struct eri_live_thread *th,
	       struct eri_siginfo *info, struct eri_sig_act *act)
{
  if (info && eri_si_sync (info))
    {
      eri_live_thread_recorder__rec_signal (th->rec, 0, act);
      return;
    }

  struct eri_async_signal_record rec = { io_in (th) };
  if (info) { rec.info = *info; rec.act = *act; }

  eri_live_thread_recorder__rec_signal (th->rec, 1, &rec);
}

static eri_noreturn void
die (struct eri_live_thread *th)
{
  record_signal (th, 0, 0);
  eri_live_signal_thread__die (th->sig_th);
  eri_assert_sys_thread_die (&th->alive);
}

static eri_noreturn void
core (struct eri_live_thread *th, uint8_t term)
{
  eri_log (th->log.file, "core\n");

  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct eri_siginfo *info = eri_entry__get_sig_info (th->entry);

  struct eri_sigset mask;
  eri_assert_sys_sigprocmask (&mask, 0);

  eri_entry__clear_signal (th->entry);
  eri_live_signal_thread__sig_reset (sig_th, &mask);

  if (eri_live_signal_thread__exit (sig_th, 1, term ? 130 : 139))
    {
      if (eri_sig_act_internal_act (&th->sig_act)
	  && ! (eri_si_sync (info) && th->sig_force_masked))
	record_signal (th, info, &th->sig_act);

      if (term) eri_assert_syscall (exit, 0);
      eri_assert_unreachable ();
    }
  else die (th);
}

static eri_noreturn void
sig_action (struct eri_entry *entry)
{
  struct eri_live_thread *th = eri_entry__get_th (entry);
  struct eri_live_signal_thread *sig_th = th->sig_th;

  struct eri_siginfo *info = eri_entry__get_sig_info (entry);

  if (info->sig == ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP) die (th);

  struct eri_sig_act *act = &th->sig_act;
  eri_assert (act->type != ERI_SIG_ACT_IGNORE);

  if (! eri_sig_act_internal_act (act))
    {
      record_signal (th, info, act);
      if (! eri_entry__setup_user_frame (entry, &act->act,
			&th->sig_alt_stack,
			eri_live_signal_thread__get_sig_mask (sig_th), 0))
	core (th, 0);

      eri_entry__clear_signal (entry);
      eri_live_signal_thread__sig_reset (sig_th, &act->act.mask);
      eri_entry__leave (entry);
    }

  if (act->type == ERI_SIG_ACT_STOP)
    {
      /* TODO: stop */

      eri_entry__clear_signal (entry);
      eri_live_signal_thread__sig_reset (sig_th, 0);
      eri_entry__leave (entry);
    }

  core (th, act->type == ERI_SIG_ACT_TERM);
}

static void
sig_digest_act (const struct eri_siginfo *info, struct eri_sig_act *act)
{
  act->type = eri_sig_digest_act (info, &act->act);
}

uint8_t
eri_live_thread__sig_digest_act (
		struct eri_live_thread *th, const struct eri_siginfo *info,
		struct eri_sig_act *act, uint8_t *force_masked)
{
  /*
   * Though this function can be called in different async contexts,
   * This can only happen synchronizly regards to the sig_mask.
   */
  if (eri_si_sync (info) && eri_sig_set_set (
	eri_live_signal_thread__get_sig_mask (th->sig_th), info->sig))
    {
      act->act.act = ERI_SIG_DFL;
      *force_masked = 1;
    }

  sig_digest_act (info, act);

  struct eri_sigset *force = th->sig_force_deliver;
  return act->type != ERI_SIG_ACT_IGNORE
	 || (force && eri_sig_set_set (force, info->sig));
}

static void
sig_prepare (struct eri_live_thread *th, struct eri_siginfo *info)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  uint8_t single_step = eri_si_single_step (info);
  eri_live_signal_thread__sig_prepare (sig_th, info, &th->sig_act);

  if (eri_si_sync (info))
    {
      th->sig_force_masked = 0;
      /* Sync signals are not ignorable.  */
      eri_assert (eri_live_thread__sig_digest_act (th, info, &th->sig_act,
						   &th->sig_force_masked));
    }
  else if (single_step)
    {
      eri_log_info (th->sig_log.file, "lost SIGTRAP\n");
      struct eri_sig_act act = { .type = ERI_SIG_ACT_LOST };
      eri_live_thread_recorder__rec_signal (th->rec, 0, &act);
    }
}

void
eri_live_thread__sig_handler (
		struct eri_live_thread *th, struct eri_sigframe *frame,
		struct eri_sig_act *act)
{
  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;
  eri_log (th->sig_log.file, "sig = %u, frame = %lx, rip = %lx, "
	   "rip - base = %lx, rax = %lx, rcx = %lx, rdx = %lx, rdi = %lx, "
	   "rsi = %lx, r14 = %lx, r15 = %lx\n",
	   info->sig, frame, ctx->mctx.rip, ctx->mctx.rip - th->group->base,
	   ctx->mctx.rax, ctx->mctx.rcx, ctx->mctx.rdx, ctx->mctx.rdi,
	   ctx->mctx.rsi, ctx->mctx.r14, ctx->mctx.r15);

  struct eri_entry *entry = th->entry;
  if (eri_si_single_step (info)
      && eri_entry__sig_test_clear_single_step (entry, ctx->mctx.rip))
    return;

  struct eri_range *map_range = &th->group->map_range;

  uint16_t code = eri_entry__get_op_code (entry);
  if (eri_entry__sig_is_access_fault (entry, info))
    {
      uint64_t fault_addr = info->fault.addr;
      if (code == ERI_OP_SYSCALL
	  /* NOTE: rax should be set after every access done */
	  && (int32_t) eri_entry__get_regs (entry)->rax == __NR_rt_sigreturn)
	{
	  th->sig_force_masked = 1;
	  th->sig_act.type = ERI_SIG_ACT_CORE;
	  eri_entry__set_signal (entry, info, ctx);
	}
      else if (eri_op_is_pub_atomic (code)
	       && ! eri_entry__sig_is_pending (entry))
	{
	  sig_prepare (th, info);
	  eri_entry__set_signal (entry, info, ctx);
	}

      eri_entry__sig_access_fault (entry, &ctx->mctx, fault_addr);
      return;
    }

  if (eri_si_sync (info))
    {
      eri_assert (! eri_within (map_range, ctx->mctx.rip));
      sig_prepare (th, info);
    }
  else th->sig_act = *act;

  eri_entry__sig_test_syscall_interrupted (entry, &ctx->mctx);

  eri_entry__sig_test_op_ret (entry, frame);
}

eri_file_t
eri_live_thread__get_sig_log (const struct eri_live_thread *th)
{
  return th->sig_log.file;
}

int32_t
eri_live_thread__get_pid (const struct eri_live_thread *th)
{
  return th->group->pid;
}

int32_t
eri_live_thread__get_tid (const struct eri_live_thread *th)
{
  return th->tid;
}
