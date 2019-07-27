#ifndef ERI_COMMON_ENTRY_H
#define ERI_COMMON_ENTRY_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/syscall.h>
#include <lib/malloc.h>

struct eri_access;

struct eri_entry
{
  uint64_t _zero; /* so that %gs:0 is always zero */

  struct
    {
      uint8_t ret;
      uint8_t args;
      uint16_t code;
    } _op;

  uint64_t _start;

  uint64_t _enter;

  uint64_t _th_enter;
  uint64_t _th_leave;

  struct eri_registers _regs;

  struct eri_ucontext _ctx;
  struct eri_fpstate _fpstate;
  struct eri_siginfo _sig_info;

  uint8_t _sig_wait_pending;
  uint32_t _sig_pending;
  uint8_t _sig_swallow_single_step;

  struct eri_mtpool *_pool;
  struct eri_range *_map_range;

  void *_th;

  uint8_t *_stack;
  void *_entry;
  void *_main_entry;
  void *_sig_action;
  void *_exit;

  struct
    {
      uint64_t mem;
      uint64_t done;
      uint64_t rbx;
      uint64_t rsp;
      uint64_t rbp;
      uint64_t r12;
      uint64_t r13;
      uint64_t r14;
      uint64_t r15;
      uint64_t rip;
    } _access;
  uint8_t _test_access;

  uint64_t _interrupt;
  uint64_t _interrupt_restart;

  union
    {
      struct
	{
	  uint64_t val;
	  uint64_t mem;

	  uint64_t leave;
	} _atomic;
    };

  eri_aligned16 uint8_t text[0];
};

struct eri_entry__create_args
{
  struct eri_mtpool *pool;
  struct eri_range *map_range;

  void *th;
  uint8_t *stack;
  void *entry;
  void *sig_action;

  void *exit;
};

struct eri_entry *eri_entry__create (struct eri_entry__create_args *args);
void eri_entry__destroy (struct eri_entry *entry);

#define eri_entry__get_op_code(entry)	((entry)->_op.code)
#define eri_entry__get_start(entry)	((entry)->_start)

#define eri_entry__get_regs(entry)	(&(entry)->_regs)
#define eri_entry__get_th(entry)	((entry)->_th)
#define eri_entry__get_stack(entry)	((entry)->_stack)
#define eri_entry__get_entry(entry)	((entry)->_entry)

#define eri_entry__get_atomic_val(entry)	((entry)->_atomic.val)
#define eri_entry__get_atomic_mem(entry)	((entry)->_atomic.mem)
#define eri_entry__get_atomic_size(entry)	(1 << (entry)->_op.args)

#define eri_entry__get_interrupt(entry)		((entry)->_interrupt)

eri_noreturn void eri_entry__do_leave (struct eri_entry *entry);
eri_noreturn void eri_entry__leave (struct eri_entry *entry);
eri_noreturn void eri_entry__syscall_leave (
			struct eri_entry *entry, uint64_t res);
#define eri_entry__syscall_leave_if_error(entry, res) \
  do {									\
    struct eri_entry *_entry = entry;					\
    uint64_t _res = res;						\
    if (eri_syscall_is_error (_res))					\
      eri_entry__syscall_leave (_entry, _res);				\
  } while (0)
eri_noreturn void eri_entry__atomic_leave (
			struct eri_entry *entry, uint64_t val);
#define eri_entry__restart(entry) \
  do { struct eri_entry *_entry = entry;				\
       _entry->_regs.rip = _entry->_start;				\
       eri_entry__leave (_entry); } while (0)

#define eri_entry__test_invalidate(entry, mem) \
  ({ uint64_t *_mem = mem;						\
     if (eri_within ((entry)->_map_range, *_mem)) *_mem = 0; })

eri_returns_twice uint8_t _eri_entry__test_access (
		struct eri_entry *entry, uint64_t mem, uint64_t *done);
#define eri_entry__test_access(entry, mem, done) \
  ({ struct eri_entry *_entry = entry;					\
     uint64_t _mem = (uint64_t) (mem);					\
     uint64_t *_done = done;						\
     uint8_t _res;							\
     /* The guard page will protect us if preceeding map_start. */	\
     /* XXX: df should be cleared to make the guard robust */		\
     if (! _mem || eri_within (_entry->_map_range, _mem))		\
       {								\
	 if (_done) *_done = 0;						\
	 _res = 0;							\
       }								\
     else _res = _eri_entry__test_access (_entry, _mem, _done);		\
     eri_barrier (); _res; })
#define eri_entry__reset_test_access(entry) \
  do { eri_barrier (); (entry)->_test_access = 0; } while (0)

uint8_t eri_entry__copy_from_user (struct eri_entry *entry,
	void *dst, const void *src, uint64_t size, struct eri_access *acc);
uint8_t eri_entry__copy_to_user (struct eri_entry *entry,
	void *dst, const void *src, uint64_t size, struct eri_access *acc);
#define eri_entry__copy_obj_from_user(entry, dst, src, acc) \
  eri_entry__copy_from_user (entry, dst, src, sizeof *(dst), acc)
#define eri_entry__copy_obj_to_user(entry, dst, src, acc) \
  eri_entry__copy_to_user (entry, dst, src, sizeof *(dst), acc)
uint8_t eri_entry__copy_str_from_user (struct eri_entry *entry,
	char *dst, const char *src, uint64_t *len, struct eri_access *acc);

#define eri_entry__syscall(entry, ...) \
  ({ struct eri_sys_syscall_args _args;					\
     eri_init_sys_syscall_args_from_registers (&_args,			\
				&(entry)->_regs, ##__VA_ARGS__);	\
     eri_sys_syscall (&_args); })
uint8_t eri_entry__sys_syscall_interruptible (
	struct eri_entry *entry, struct eri_sys_syscall_args *args);
#define eri_entry__syscall_interruptible(entry, res, ...) \
  ({ struct eri_entry *_entry = entry;					\
     struct eri_sys_syscall_args _args;					\
     eri_init_sys_syscall_args_from_registers (&_args,			\
				&_entry->_regs, ##__VA_ARGS__);		\
     uint8_t _done = eri_entry__sys_syscall_interruptible (_entry,	\
							   &_args);	\
     *(res) = _args.result; _done; })

uint64_t eri_entry__syscall_get_rt_sigprocmask (struct eri_entry *entry,
		const eri_sigset_t *old_mask, eri_sigset_t *mask,
		struct eri_access *acc);
#define eri_entry__syscall_rt_sigprocmask_mask(entry) \
  (!! (entry)->_regs.rsi)
uint64_t eri_entry__syscall_set_rt_sigprocmask (struct eri_entry *entry,
		eri_sigset_t *old_mask, struct eri_access *acc);
#define ERI_ENTRY__MAX_SYSCALL_SIGALTSTACK_USER_ACCESSES	2
uint64_t eri_entry__syscall_sigaltstack (struct eri_entry *entry,
		struct eri_stack *stack, struct eri_access *acc);
#define ERI_ENTRY__MAX_SYSCALL_RT_SIGRETURN_USER_ACCESSES	3
uint8_t eri_entry__syscall_rt_sigreturn (struct eri_entry *entry,
		struct eri_stack *stack, eri_sigset_t *mask,
		struct eri_access *acc);
#define eri_entry__syscall_validate_rt_sigpending(entry) \
  ((entry)->_regs.rsi > ERI_SIG_SETSIZE ? ERI_EINVAL : 0)
uint64_t eri_entry__syscall_get_signalfd (struct eri_entry *entry,
					  int32_t *flags);
uint64_t eri_entry__syscall_get_rw_iov (struct eri_entry *entry,
	struct eri_iovec **iov, int32_t *iov_cnt, struct eri_access *acc);
void eri_entry__syscall_free_rw_iov (struct eri_entry *entry,
				     struct eri_iovec *iov);

#define ERI_ENTRY__MAX_SETUP_USER_FRAME_USER_ACCESS		2
uint8_t eri_entry__setup_user_frame (struct eri_entry *entry,
	const struct eri_sigaction *act, struct eri_stack *stack,
	const eri_sigset_t *mask, struct eri_access *acc);

#define eri_entry__get_sig_info(entry)		(&(entry)->_sig_info)
#define eri_entry__sig_is_pending(entry)	((entry)->_sig_pending)

void eri_entry__set_signal (struct eri_entry *entry,
	const struct eri_siginfo *info, const struct eri_ucontext *ctx);
#define eri_entry__clear_signal(entry) \
  do { (entry)->_sig_pending = 0; } while (0)
uint8_t eri_entry__sig_wait_pending (struct eri_entry *entry,
				     struct eri_timespec *timeout);
uint8_t eri_entry__sig_test_clear_single_step (
			struct eri_entry *entry, uint64_t rip);
void _eri_entry__sig_op_ret (struct eri_entry *entry,
			     struct eri_sigframe *frame);
#define eri_entry__sig_set_test_op_ret(entry, frame) \
  do { struct eri_entry *_entry = entry;				\
       struct eri_sigframe *_frame = frame;				\
       eri_entry__set_signal (entry, &_frame->info, &_frame->ctx);	\
       if (_entry->_op.ret)						\
	 _eri_entry__sig_op_ret (_entry, _frame); } while (0)

static eri_unused uint8_t
eri_entry__sig_is_access_fault (struct eri_entry *entry,
				struct eri_siginfo *info)
{
  return eri_si_access_fault (info) && entry->_test_access
	 && ! eri_within (entry->_map_range, info->fault.addr);
}

static eri_unused void
eri_entry__sig_access_fault (struct eri_entry *entry,
			     struct eri_mcontext *mctx, uint64_t fault_addr)
{
  mctx->rax = 0;
  mctx->rbx = entry->_access.rbx;
  mctx->rsp = entry->_access.rsp;
  mctx->rbp = entry->_access.rbp;
  mctx->r12 = entry->_access.r12;
  mctx->r13 = entry->_access.r13;
  mctx->r14 = entry->_access.r14;
  mctx->r15 = entry->_access.r15;
  mctx->rip = entry->_access.rip;
  if (entry->_access.done)
    *(uint64_t *) entry->_access.done = fault_addr - entry->_access.mem;
  entry->_test_access = 0;
}

void eri_entry__sig_test_interrupted (
		struct eri_entry *entry, struct eri_mcontext *mctx);

#endif
