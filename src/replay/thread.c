#include <compiler.h>
#include <common.h>

#include <entry.h>

#include <lib/util.h>
#include <lib/malloc.h>
#include <lib/printf.h>
#include <lib/syscall.h>

#include <public/common.h>
#include <replay/rtld.h>
#include <replay/thread.h>
#include <replay/thread-local.h>

enum
{
#define SIG_HAND_ENUM(chand, hand)	chand,
  ERI_ENTRY_THREAD_ENTRY_SIG_HANDS (SIG_HAND_ENUM)
  SIG_HAND_RETURN_TO_USER
};

struct thread_group
{
  struct eri_mtpool *pool;

  uint64_t map_start;
  uint64_t map_end;

  struct eri_common_args args;

  struct eri_sig_act sig_acts[ERI_NSIG - 1];
};

#define THREAD_SIG_STACK_SIZE	(2 * 4096)

struct thread
{
  struct thread_group *group;

  struct thread_context *ctx;

  eri_file_t file;
  uint8_t *file_buf;

  eri_aligned16 uint8_t sig_stack[THREAD_SIG_STACK_SIZE];
  eri_aligned16 uint8_t stack[0];
};

static uint8_t
internal (struct thread_group *group, uint64_t addr)
{
  return addr >= group->map_start && addr < group->map_end;
}

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (! eri_si_sync (info)) return;

  struct thread *th = *(void **) ctx->stack.sp;
  struct thread_context *th_ctx = th->ctx;
  if (eri_si_single_step (info))
    {
      if (th_ctx->ext.op.sig_hand != SIG_HAND_RETURN_TO_USER) return;
      if (internal (th->group, ctx->mctx.rip)) return;

      if (th_ctx->ext.op.code == _ERS_OP_SYSCALL
	  && th_ctx->swallow_single_step)
	{
	  th_ctx->swallow_single_step = 0;
	  return;
	}

      if (th_ctx->ext.op.code == _ERS_OP_SYNC_ASYNC)

      eri_assert (! th_ctx->swallow_single_step);
      /* TODO */
    }

  /* TODO */
}

static struct thread_group *
create_group (const struct eri_replay_rtld_args *rtld_args)
{
  struct eri_mtpool *pool = eri_init_mtpool_from_buf (
				rtld_args->buf, rtld_args->buf_size, 1);
  struct thread_group *group
			= eri_assert_malloc (&pool->pool, sizeof *group);
  group->pool = pool;

  group->args.path = eri_assert_malloc (&pool->pool,
					eri_strlen (rtld_args->path) + 1);
  eri_strcpy ((void *) group->args.path, rtld_args->path);
  group->args.stack_size = rtld_args->stack_size;
  group->args.file_buf_size = rtld_args->file_buf_size;

  eri_sig_init_acts (group->sig_acts, sig_handler);
  return group;
}

static struct thread *
create (struct thread_group *group, uint64_t id)
{
  struct thread *th = eri_assert_mtmalloc (group->pool,
				sizeof *th + group->args.stack_size);
  th->group = group;
  struct thread_context *th_ctx = eri_assert_mtmalloc (group->pool,
	sizeof *th->ctx + eri_entry_thread_entry_text_size (thread_context));
  th->ctx = th_ctx;

  eri_entry_init (&th_ctx->ext, &th_ctx->ctx, thread_context, th_ctx->text,
		  entry, th->stack + group->args.stack_size);

  th_ctx->swallow_single_step = 0;
  th_ctx->sync_async_trace = 0;
  th_ctx->sync_async_trace_steps = 0;
  th_ctx->atomic_ext_return = 0;

  th_ctx->th = th;
  char name[eri_build_path_len (group->args.path, "t", id)];
  eri_build_path (group->args.path, "t", id, name);

  uint64_t file_buf_size = group->args.file_buf_size;
  th->file_buf = eri_assert_mtmalloc (group->pool, file_buf_size);
  eri_assert_fopen (name, 1, &th->file, th->file_buf, file_buf_size);

  *(void **) th->sig_stack = th;
  return th;
}

eri_noreturn void
eri_replay_start (struct eri_replay_rtld_args *rtld_args)
{
  struct thread_group *group = create_group (rtld_args);
  struct thread *th = create (group, 0);
  struct thread_context *th_ctx = th->ctx;

  th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;
  th_ctx->ext.op.args = 0;
  th_ctx->ext.op.code = _ERS_OP_SYSCALL;

  th_ctx->ext.rbx = 0;
#define ZERO_REG(creg, reg, regs)	(regs)->reg = 0;
  ERI_ENTRY_FOREACH_SREG (ZERO_REG, &th_ctx->ctx.sregs)
  ERI_ENTRY_FOREACH_EREG (ZERO_REG, &th_ctx->eregs)

  main (th_ctx);
}

static eri_noreturn void async_signal (struct thread *th);

static eri_noreturn void
async_signal (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  eri_assert (th_ctx->ext.op.code != _ERS_OP_SYNC_ASYNC);
  /* TODO */
}

static struct thread_context *
start (struct thread *th, uint8_t rec)
{
  struct eri_stack st = {
    (uint64_t) th->sig_stack, 0, THREAD_SIG_STACK_SIZE
  };
  eri_assert_syscall (sigaltstack, &st, 0);

  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_GS, th->ctx);

  if (rec == ERI_ASYNC_RECORD) async_signal (th);
  return th->ctx;
}

static uint8_t
next_record (struct thread *th)
{
  uint8_t rec;
  eri_assert_fread (th->file, &rec, sizeof rec, 0);
  return rec;
}

void
start_main (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  struct eri_marked_init_record init;
  eri_assert_fread (th->file, &init, sizeof init, 0);

  th_ctx->ext.ret = init.rip;
  th_ctx->ctx.rsp = init.rsp;
  th_ctx->ctx.sregs.rdx = init.rdx;

  th->sig_mask = init.sig_mask;
  th->group->map_start = init.start;
  th->group->map_end = init.end;

  uint8_t rec;
  while ((rec = next_record (th)) == ERI_INIT_MAP_RECORD)
    {
      struct eri_init_map_record init_map;
      eri_assert_fread (th->file, &init_map, sizeof init_map, 0);
      uint64_t size = init_map.end - init_map.start;
      uint8_t prot = init_map.prot;
      uint8_t init_prot
		= prot | (init_map.data_count ? ERI_PROT_WRITE : 0);
      /* XXX: grows_down */
      eri_assert_syscall (mmap, init_map.start, size, init_prot,
		ERI_MAP_FIXED | ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
      uint8_t i;
      for (i = 0; i < init_map.data_count; ++i)
	{
	  struct eri_init_map_data_record data;
	  eri_assert_fread (th->file, &data, sizeof data, 0);
	  eri_assert_fread (th->file, (void *) data.start,
			    data.end - data.start, 0);
	}
      if (init_prot != prot)
	eri_assert_syscall (mprotect, init_map.start, size, prot);
    }

  start (th, rec);
}

static uint64_t
syscall (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  uint64_t res = 0;
  /* TODO */

  th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;
  if (next_record (th) == ERI_ASYNC_RECORD) async_signal (th);

  if (th_ctx->ctx.sregs.rflags & ERI_RFLAGS_TRACE_MASK)
    th_ctx->swallow_single_step = 1;
  return res;
}

static void
sync_async (struct thread *th)
{
  struct eri_marked_sync_async_record sync;
  eri_assert_fread (th->file, &sync, sizeof sync, 0);
  eri_assert (sync.magic == ERI_SYNC_ASYNC_MAGIC);

  struct thread_context *th_ctx = th->ctx;
  th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;

  uint8_t async = next_record (th) == ERI_ASYNC_RECORD;
  if (sync.steps) eri_assert (async);

  if (th_ctx->ctx.sregs.rflags & ERI_RFLAGS_TRACE_MASK)

  if (! async) return;

  th_ctx->sync_async_trace
		= (th_ctx->ctx.sregs.rflags & ERI_RFLAGS_TRACE_MASK)
			? SYNC_ASYNC_TRACE_BOTH : SYNC_ASYNC_TRACE_ASYNC;
  th_ctx->sync_async_trace_steps = sync.steps;
  /* XXX: this is slow with large repeats... */
  th_ctx->ctx.sregs.rflags |= ERI_RFLAGS_TRACE_MASK;
}

static void
atomic (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;

  if (th_ctx->atomic_ext_return)
    {
      th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;
      th_ctx->ext.ret = th_ctx->ext.atomic.ret;
      th_ctx->atomic_ext_return = 0;
    }
  else
    {
      /* TODO */
      if (th_ctx->ext.op.code == _ERS_OP_ATOMIC_LOAD
	  || th_ctx->ext.op.code == _ERS_OP_ATOMIC_XCHG)
	th_ctx->atomic_ext_return = 1;
      else
	th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;
    }

  if (next_record (th) == ERI_ASYNC_RECORD) async_signal (th);
}

uint64_t
relax (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  if (th_ctx->ext.op.code == _ERS_OP_SYSCALL)
    return syscall (th);

  if (th_ctx->ext.op.code == _ERS_OP_SYNC_ASYNC) sync_async (th);
  else atomic (th);

  return 0;
}
