#ifndef ERI_COMMON_ENTRY_H
#define ERI_COMMON_ENTRY_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/syscall.h>
#include <lib/malloc.h>

#define ERI_OP_NOP		0
#define ERI_OP_SYSCALL		1
#define ERI_OP_SYNC_ASYNC	2

#define ERI_OP_ATOMIC_LOAD	3
#define ERI_OP_ATOMIC_STORE	4
#define ERI_OP_ATOMIC_INC	5
#define ERI_OP_ATOMIC_DEC	6
#define ERI_OP_ATOMIC_XCHG	7
#define ERI_OP_ATOMIC_CMPXCHG	8

#define ERI_FOREACH_PUB_OP(p, ...) \
  p (SYSCALL, ##__VA_ARGS__)						\
  p (SYNC_ASYNC, ##__VA_ARGS__)						\
									\
  p (ATOMIC_LOAD, ##__VA_ARGS__)					\
  p (ATOMIC_STORE ##__VA_ARGS__)					\
  p (ATOMIC_INC, ##__VA_ARGS__)						\
  p (ATOMIC_DEC, ##__VA_ARGS__)						\
  p (ATOMIC_XCHG, ##__VA_ARGS__)					\
  p (ATOMIC_CMPXCHG, ##__VA_ARGS__)

#if 0
#define ERI_ATOMIC_LOAD	0x1000
#define ERI_ATOMIC_STORE	0x1001

#define ERI_ATOMIC_INC		0x1002
#define ERI_ATOMIC_DEC		0x1003
#define ERI_ATOMIC_ADD		0x1004
#define ERI_ATOMIC_SUB		0x1005
#define ERI_ATOMIC_ADC		0x1006
#define ERI_ATOMIC_SBB		0x1007
#define ERI_ATOMIC_NEG		0x1008
#define ERI_ATOMIC_AND		0x1009
#define ERI_ATOMIC_OR		0x100a
#define ERI_ATOMIC_XOR		0x100b
#define ERI_ATOMIC_NOT		0x100c
#define ERI_ATOMIC_BTC		0x100d
#define ERI_ATOMIC_BTR		0x100e
#define ERI_ATOMIC_BTS		0x100f
#define ERI_ATOMIC_XCHG	0x1010
#define ERI_ATOMIC_XADD	0x1011
#define ERI_ATOMIC_CMPXCHG	0x1012
#define ERI_ATOMIC_XCHG8B	0x1013
#define ERI_ATOMIC_XCHG16B	0x1014
#endif

#define eri_op_is_atomic(code) \
  ({ uint16_t _code = code;						\
     _code >= ERI_OP_ATOMIC_LOAD && _code <= ERI_OP_ATOMIC_CMPXCHG; })

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

  uint64_t _syscall_interrupt;

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

#define eri_entry__get_regs(entry)	(&(entry)->_regs)
#define eri_entry__get_th(entry)	((entry)->_th)
#define eri_entry__get_stack(entry)	((entry)->_stack)
#define eri_entry__get_entry(entry)	((entry)->_entry)

#define eri_entry__get_atomic_val(entry)	((entry)->_atomic.val)
#define eri_entry__get_atomic_mem(entry)	((entry)->_atomic.mem)
#define eri_entry__get_atomic_size(entry)	(1 << (entry)->_op.args)

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
eri_noreturn void eri_entry__atomic_interleave (
			struct eri_entry *entry, uint64_t val);
#define eri_entry__restart(entry) \
  do { struct eri_entry *_entry = entry;				\
       _entry->_regs.rip = _entry->_start;				\
       eri_entry__leave (_entry); } while (0)

eri_returns_twice uint8_t _eri_entry__test_access (
		struct eri_entry *entry, uint64_t mem, uint64_t *done);
#define eri_entry__test_access(entry, mem, size, done) \
  ({ struct eri_entry *_entry = entry;					\
     uint64_t _mem = (uint64_t) (mem);					\
     uint64_t *_done = done;						\
     uint8_t _res;							\
     if (eri_cross (_entry->_map_range, _mem, size)			\
	 /* otherwise will be protected the guard page */		\
	&& _mem >= _entry->_map_range->start)				\
       {								\
	 if (_done) *_done = 0;						\
	 _res = 0;							\
       }								\
     else _res = _eri_entry__test_access (_entry, _mem, _done);		\
     _res; })
#define eri_entry__reset_test_access(entry) \
  do { eri_barrier (); (entry)->_test_access = 0; } while (0)

uint64_t eri_entry__copy_from (struct eri_entry *entry,
			       void *dst, const void *src, uint64_t size);
uint64_t eri_entry__copy_to (struct eri_entry *entry,
			     void *dst, const void *src, uint64_t size);
#define eri_entry__copy_from_obj(entry, dst, src) \
  (eri_entry__copy_from (entry, dst, src, sizeof *(dst)) == sizeof *(dst))
#define eri_entry__copy_to_obj(entry, dst, src) \
  (eri_entry__copy_to (entry, dst, src, sizeof *(dst)) == sizeof *(dst))

#define eri_entry__syscall(entry) \
  ({ struct eri_sys_syscall_args _args;					\
     eri_init_sys_syscall_args_from_registers (&_args,			\
					       &(entry)->_regs);	\
     eri_sys_syscall (&_args); })
uint64_t eri_entry__sys_syscall_interruptible (
	struct eri_entry *entry, struct eri_sys_syscall_args *args);
#define eri_entry__syscall_interruptible(entry) \
  ({ struct eri_entry *_entry = entry;					\
     struct eri_sys_syscall_args _args;					\
     eri_init_sys_syscall_args_from_registers (&_args, &_entry->_regs);	\
     eri_entry__sys_syscall_interruptible (_entry, &_args); })

uint64_t eri_entry__syscall_get_rt_sigprocmask (struct eri_entry *entry,
			struct eri_sigset *old_mask, struct eri_sigset *mask);
#define eri_entry__syscall_rt_sigprocmask_mask(entry) \
  (!! (entry)->_regs.rsi)
uint64_t eri_entry__syscall_set_rt_sigprocmask (
		struct eri_entry *entry, struct eri_sigset *old_mask);
uint64_t eri_entry__syscall_sigaltstack (
		struct eri_entry *entry, struct eri_stack *stack);
uint8_t eri_entry__syscall_rt_sigreturn (struct eri_entry *entry,
			struct eri_stack *stack, struct eri_sigset *mask);
#define eri_entry__syscall_validate_rt_sigpending(entry) \
  ((entry)->_regs.rsi > ERI_SIG_SETSIZE ? ERI_EINVAL : 0)
uint64_t eri_entry__syscall_get_rt_sigtimedwait (struct eri_entry *entry,
			struct eri_sigset *set, struct eri_timespec *timeout);
uint64_t eri_entry__syscall_get_signalfd (struct eri_entry *entry,
					  int32_t *flags);
uint64_t eri_entry__syscall_get_rw_iov (struct eri_entry *entry,
	struct eri_mtpool *pool, struct eri_iovec **iov, int32_t *iov_cnt);

struct eri_sigframe *eri_entry__setup_user_frame (
	struct eri_entry *entry, const struct eri_sigaction *act,
	struct eri_stack *stack, const struct eri_sigset *mask);

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
#define eri_entry__sig_test_op_ret(entry, frame) \
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

void eri_entry__sig_test_syscall_interrupted (
		struct eri_entry *entry, struct eri_mcontext *mctx);

#endif
