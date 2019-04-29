#ifndef ERI_COMMON_THREAD_H
#define ERI_COMMON_THREAD_H

#define _ERI_FOREACH_GPREG_NO_RBX_RSP(p, ...) \
  p (RAX, rax, ##__VA_ARGS__)						\
  p (RCX, rcx, ##__VA_ARGS__)						\
  p (RDX, rdx, ##__VA_ARGS__)						\
  p (RSI, rsi, ##__VA_ARGS__)						\
  p (RDI, rdi, ##__VA_ARGS__)						\
  p (RBP, rbp, ##__VA_ARGS__)						\
  p (R8, r8, ##__VA_ARGS__)						\
  p (R9, r9, ##__VA_ARGS__)						\
  p (R10, r10, ##__VA_ARGS__)						\
  p (R11, r11, ##__VA_ARGS__)						\
  p (R12, r12, ##__VA_ARGS__)						\
  p (R13, r13, ##__VA_ARGS__)						\
  p (R14, r14, ##__VA_ARGS__)						\
  p (R15, r15, ##__VA_ARGS__)

#define ERI_FOREACH_GPREG(p, ...) \
  _ERI_FOREACH_GPREG_NO_RBX_RSP (p, ##__VA_ARGS__)			\
  p (RBX, rbx, ##__VA_ARGS__)						\
  p (RSP, rsp, ##__VA_ARGS__)

#define ERI_FOREACH_REG(p, ...) \
  ERI_FOREACH_GPREG (p, ##__VA_ARGS__)					\
  p (RFLAGS, rflags, ##__VA_ARGS__)					\
  p (RIP, rip, ##__VA_ARGS__)

#ifndef __ASSEMBLER__

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
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

struct eri_registers
{
#define _ERI_DECLARE_REG(creg, reg)	uint64_t reg;
  ERI_FOREACH_REG (_ERI_DECLARE_REG)
};

#define eri_init_sys_syscall_args_from_registers(args, regs) \
  do {									\
    struct eri_sys_syscall_args *__args = args;				\
    struct eri_registers *_regs = regs;					\
    __args->nr = _regs->rax;						\
    __args->a[0] = _regs->rdi;						\
    __args->a[1] = _regs->rsi;						\
    __args->a[2] = _regs->rdx;						\
    __args->a[3] = _regs->r10;						\
    __args->a[4] = _regs->r8;						\
    __args->a[5] = _regs->r9;						\
  } while (0)

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

eri_returns_twice uint8_t _eri_entry__test_access (struct eri_entry *entry);
#define eri_entry__test_access(entry, mem, size) \
  ({ struct eri_entry *_entry = entry;					\
     eri_cross (_entry->_map_range, (uint64_t) mem, size)		\
	? 0 : _eri_entry__test_access (_entry); })
#define eri_entry__reset_test_access(entry) \
  do { eri_barrier (); (entry)->_test_access = 0; } while (0)

uint8_t eri_entry__copy_from (struct eri_entry *entry,
			      void *dst, const void *src, uint64_t size);
uint8_t eri_entry__copy_to (struct eri_entry *entry,
			    void *dst, const void *src, uint64_t size);

#define eri_entry__syscall(entry) \
  ({ struct eri_sys_syscall_args _args;					\
     eri_init_sys_syscall_args_from_registers (&_args,			\
					eri_entry__get_regs (entry));	\
     eri_sys_syscall (&_args); })
uint64_t eri_entry__sys_syscall_interruptible (
	struct eri_entry *entry, struct eri_sys_syscall_args *args);
#define eri_entry__syscall_interruptible(entry) \
  ({ struct eri_entry *_entry = entry;					\
     struct eri_sys_syscall_args _args;					\
     eri_init_sys_syscall_args_from_registers (&_args,			\
					eri_entry__get_regs (_entry));	\
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
eri_noreturn void _eri_entry__sig_op_ret (struct eri_entry *entry,
					  struct eri_sigframe *frame);
#define eri_entry__sig_test_op_ret(entry, frame) \
  do { struct eri_entry *_entry = entry;				\
       struct eri_sigframe *_frame = frame;				\
       eri_entry__set_signal (entry, &_frame->info, &_frame->ctx);	\
       if (_entry->_op.ret)						\
	 _eri_entry__sig_op_ret (_entry, _frame); } while (0)

#define eri_entry__sig_is_access_fault(entry, sig_info) \
  ({ struct eri_entry *_entry = entry;					\
     struct eri_siginfo *_sig_info = sig_info;				\
     eri_si_access_fault (_sig_info) && _entry->_test_access		\
	&& ! eri_within (_entry->_map_range, _sig_info->fault.addr); })
#define eri_entry__sig_access_fault(entry, mctx) \
  do {									\
    struct eri_entry *_entry = entry;					\
    struct eri_mcontext *_mctx = mctx;					\
    _mctx->rax = 0;							\
    _mctx->rbx = _entry->_access.rbx;					\
    _mctx->rsp = _entry->_access.rsp;					\
    _mctx->rbp = _entry->_access.rbp;					\
    _mctx->r12 = _entry->_access.r12;					\
    _mctx->r13 = _entry->_access.r13;					\
    _mctx->r14 = _entry->_access.r14;					\
    _mctx->r15 = _entry->_access.r15;					\
    _mctx->rip = _entry->_access.rip;					\
    _entry->_test_access = 0;						\
  } while (0)

void eri_entry__sig_test_syscall_interrupted (
		struct eri_entry *entry, struct eri_mcontext *mctx);

#define eri_init_mtpool_from_buf(buf, size, exec) \
  ({									\
    uint8_t *_buf = (void *) buf;					\
    uint64_t _size = size;						\
    eri_assert_syscall (mmap, _buf, _size,				\
	/* XXX: exec security */					\
	ERI_PROT_READ | ERI_PROT_WRITE | ((exec) ? ERI_PROT_EXEC : 0),	\
	ERI_MAP_FIXED | ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);	\
									\
    struct eri_mtpool *_pool = (void *) _buf;				\
    uint64_t _pool_size = eri_size_of (*_pool, 16);			\
    eri_assert (_size >= _pool_size);					\
    eri_assert_init_mtpool (_pool, _buf + _pool_size,			\
			    _size - _pool_size);			\
    _pool;								\
  })

#define eri_sig_valid(sig) \
  ({ int32_t _s1 = sig; _s1 > 0 && _s1 < ERI_NSIG; })
#define eri_sig_catchable(sig) \
  ({ int32_t _s2 = sig;							\
     eri_sig_valid (_s2) && _s2 != ERI_SIGKILL && _s2 != ERI_SIGSTOP; })

#define eri_set_sig_mask(dst, src) \
  do { struct eri_sigset _set = *(src);					\
       eri_sig_del_set (&_set, ERI_SIGKILL);				\
       eri_sig_del_set (&_set, ERI_SIGSTOP);				\
       *(dst) = _set; } while (0)

#define eri_atomic_slot(mem)		((mem) & ~0xf)
#define eri_atomic_slot2(mem, size)	eri_atomic_slot ((mem) + (size) - 1)

#define eri_atomic_cross_slot(mem, size) \
  ({ uint64_t _mem = mem;						\
     eri_atomic_slot (_mem) != eri_atomic_slot2 (_mem, size); })

#define eri_atomic_hash(slot, size)	(eri_hash (slot) % (size))

#define ERI_SIG_ACT_TERM	((void *) 1)
#define ERI_SIG_ACT_CORE	((void *) 2)
#define ERI_SIG_ACT_STOP	((void *) 3)

#define eri_sig_act_internal_act(act) \
  ({ void *_act = act;							\
     _act == ERI_SIG_ACT_TERM || _act == ERI_SIG_ACT_CORE		\
     || _act == ERI_SIG_ACT_STOP; })

eri_noreturn void eri_jump (void *rsp, void *rip,
			    void *rdi, void *rsi, void *rdx);

#endif

#endif
