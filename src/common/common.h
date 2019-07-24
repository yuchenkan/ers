#ifndef ERI_COMMON_COMMON_H
#define ERI_COMMON_COMMON_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/buf.h>
#include <lib/printf.h>
#include <lib/lock.h>
#include <lib/syscall.h>

#define ERI_OP_NOP		0
#define ERI_OP_SYSCALL		1
#define ERI_OP_SYNC_ASYNC	2

#define ERI_OP_ATOMIC_PUB_START	3
#define ERI_OP_ATOMIC_LOAD	3
#define ERI_OP_ATOMIC_STORE	4
#define ERI_OP_ATOMIC_INC	5
#define ERI_OP_ATOMIC_DEC	6
#define ERI_OP_ATOMIC_XCHG	7
#define ERI_OP_ATOMIC_CMPXCHG	8
#define ERI_OP_ATOMIC_ADD	9
#define ERI_OP_ATOMIC_SUB	10
#define ERI_OP_ATOMIC_ADC	11
#define ERI_OP_ATOMIC_SBB	12
#define ERI_OP_ATOMIC_NEG	13
#define ERI_OP_ATOMIC_AND	14
#define ERI_OP_ATOMIC_OR	15
#define ERI_OP_ATOMIC_XOR	16
#define ERI_OP_ATOMIC_NOT	17
#define ERI_OP_ATOMIC_BTC	18
#define ERI_OP_ATOMIC_BTR	19
#define ERI_OP_ATOMIC_BTS	20
#define ERI_OP_ATOMIC_XADD	21
#define ERI_OP_ATOMIC_PUB_END	22

#define ERI_OP_ATOMIC_XAND	256
#define ERI_OP_ATOMIC_X_OR	257
#define ERI_OP_ATOMIC_XXOR	258

#define ERI_FOREACH_PUB_OP(p, ...) \
  p (SYSCALL, ##__VA_ARGS__)						\
  p (SYNC_ASYNC, ##__VA_ARGS__)						\
									\
  p (ATOMIC_LOAD, ##__VA_ARGS__)					\
  p (ATOMIC_STORE ##__VA_ARGS__)					\
  p (ATOMIC_INC, ##__VA_ARGS__)						\
  p (ATOMIC_DEC, ##__VA_ARGS__)						\
  p (ATOMIC_XCHG, ##__VA_ARGS__)					\
  p (ATOMIC_CMPXCHG, ##__VA_ARGS__)					\
  p (ATOMIC_ADD, ##__VA_ARGS__)						\
  p (ATOMIC_SUB, ##__VA_ARGS__)						\
  p (ATOMIC_ADC, ##__VA_ARGS__)						\
  p (ATOMIC_SBB, ##__VA_ARGS__)						\
  p (ATOMIC_NEG, ##__VA_ARGS__)						\
  p (ATOMIC_AND, ##__VA_ARGS__)						\
  p (ATOMIC_OR, ##__VA_ARGS__)						\
  p (ATOMIC_XOR, ##__VA_ARGS__)						\
  p (ATOMIC_NOT, ##__VA_ARGS__)						\
  p (ATOMIC_BTC, ##__VA_ARGS__)						\
  p (ATOMIC_BTR, ##__VA_ARGS__)						\
  p (ATOMIC_BTS, ##__VA_ARGS__)						\
  p (ATOMIC_XADD, ##__VA_ARGS__)

#if 0

#define ERI_ATOMIC_XCHG8B	0x1013
#define ERI_ATOMIC_XCHG16B	0x1014
#endif

#define eri_op_is_pub_atomic(code) \
  ({ uint16_t _code = code;						\
     _code >= ERI_OP_ATOMIC_PUB_START && _code < ERI_OP_ATOMIC_PUB_END; })

struct eri_mtpool;

#define eri_build_path_len(path, name, id) \
  (eri_strlen (path) + 1 + eri_strlen (name) + eri_itoa_size (id))

void eri_build_path (const char *path, const char *name,
		     uint64_t id, char *buf);
eri_file_t eri_open_path (const char *path, const char *name,
			  uint64_t id, void *buf, uint64_t buf_size);

struct eri_buf_file
{
  eri_file_t file;
  void *buf;
};

void eri_malloc_open_path (struct eri_mtpool *pool,
	struct eri_buf_file *file, const char *path, const char *name,
	uint64_t id, uint64_t buf_size);
void eri_free_close (struct eri_mtpool *pool, struct eri_buf_file *file);

void eri_mkdir (const char *path);

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
  do { eri_sigset_t _set = *(src);					\
       eri_sig_del_set (&_set, ERI_SIGKILL);				\
       eri_sig_del_set (&_set, ERI_SIGSTOP);				\
       *(dst) = _set; } while (0)

#define eri_atomic_aligned(mem)		((mem) & ~0xf)
#define eri_atomic_aligned2(mem, size) \
  eri_atomic_aligned ((mem) + (size) - 1)

#define eri_atomic_cross_aligned(mem, size) \
  ({ uint64_t _mem = mem;						\
     eri_atomic_aligned (_mem) != eri_atomic_aligned2 (_mem, size); })

#define eri_atomic_hash(aligned, size)	(eri_hash (aligned) % (size))

#define _eri_atomic_x(op, rflags, ...) \
  do {									\
    uint64_t *_rflags = rflags;						\
    if (! _rflags) ERI_PASTE (eri_atomic_, op) (__VA_ARGS__, 0);	\
    else ERI_PASTE2 (eri_atomic_, op, _x) (__VA_ARGS__, _rflags, 0);	\
  } while (0)

#define _eri_atomic_cas(type, mem, op, val) \
  ({									\
    type *_mem = mem;							\
    type _t = eri_atomic_load (_mem, 0);				\
    while (! eri_atomic_compare_exchange (_mem, _t, _t op (val), 0))	\
      _t = eri_atomic_load (_mem, 0);					\
    _t;									\
  })

#define _ERI_DEFINE_DO_ATOMIC_TYPE(type) \
static uint8_t								\
ERI_PASTE (_eri_atomic_, type) (uint16_t code, type *mem,		\
			uint64_t val, void *old, uint64_t *rflags)	\
{									\
  switch (code)								\
    {									\
    case ERI_OP_ATOMIC_LOAD:						\
      *(type *) old = eri_atomic_load (mem, 0); break;			\
    case ERI_OP_ATOMIC_XCHG:						\
      *(type *) old = eri_atomic_exchange (mem, val, 0); break;		\
    case ERI_OP_ATOMIC_XADD:						\
      *(type *) old = val;						\
      _eri_atomic_x (xadd, rflags, mem, old);				\
      break;								\
    case ERI_OP_ATOMIC_STORE:						\
      eri_atomic_store (mem, val, 0); break;				\
    case ERI_OP_ATOMIC_INC:						\
      _eri_atomic_x (inc, rflags, mem); break;				\
    case ERI_OP_ATOMIC_DEC:						\
      _eri_atomic_x (dec, rflags, mem); break;				\
    case ERI_OP_ATOMIC_CMPXCHG:						\
      _eri_atomic_x (cmpxchg, rflags, mem, old, val); break;		\
    case ERI_OP_ATOMIC_ADD:						\
      _eri_atomic_x (add, rflags, mem, val);	break;			\
    case ERI_OP_ATOMIC_SUB:						\
      _eri_atomic_x (sub, rflags, mem, val);	break;			\
    case ERI_OP_ATOMIC_ADC:						\
      _eri_atomic_x (adc, rflags, mem, val);	break;			\
    case ERI_OP_ATOMIC_SBB:						\
      _eri_atomic_x (sbb, rflags, mem, val);	break;			\
    case ERI_OP_ATOMIC_NEG:						\
      _eri_atomic_x (neg, rflags, mem);	break;				\
    case ERI_OP_ATOMIC_AND:						\
      _eri_atomic_x (and, rflags, mem, val);	break;			\
    case ERI_OP_ATOMIC_OR:						\
      _eri_atomic_x (or, rflags, mem, val); break;			\
    case ERI_OP_ATOMIC_XOR:						\
      _eri_atomic_x (xor, rflags, mem, val);	break;			\
    case ERI_OP_ATOMIC_NOT:						\
      _eri_atomic_x (not, rflags, mem);	break;				\
    case ERI_OP_ATOMIC_BTC:						\
      _eri_atomic_x (btc, rflags, mem, val);	break;			\
    case ERI_OP_ATOMIC_BTR:						\
      _eri_atomic_x (btr, rflags, mem, val);	break;			\
    case ERI_OP_ATOMIC_BTS:						\
      _eri_atomic_x (bts, rflags, mem, val);	break;			\
    case ERI_OP_ATOMIC_XAND:						\
      *(type *) old = _eri_atomic_cas (type, mem, &, val); break;	\
    case ERI_OP_ATOMIC_X_OR:						\
      *(type *) old = _eri_atomic_cas (type, mem, |, val); break;	\
    case ERI_OP_ATOMIC_XXOR:						\
      *(type *) old = _eri_atomic_cas (type, mem, ^, val); break;	\
    default: return 0;							\
    }									\
  return 1;								\
}

_ERI_DEFINE_DO_ATOMIC_TYPE (uint8_t)
_ERI_DEFINE_DO_ATOMIC_TYPE (uint16_t)
_ERI_DEFINE_DO_ATOMIC_TYPE (uint32_t)
_ERI_DEFINE_DO_ATOMIC_TYPE (uint64_t)

static eri_unused uint8_t
eri_atomic (uint16_t code, void *mem, uint8_t size,
	       uint64_t val, void *old, uint64_t *rflags)
{
  uint64_t dummy = 0;
  old = old ? : &dummy;

  /* XXX: cmpxchg16b */
  if (size == 1)
    return _eri_atomic_uint8_t (code, mem, val, old, rflags);
  else if (size == 2)
    return _eri_atomic_uint16_t (code, mem, val, old, rflags);
  else if (size == 4)
    return _eri_atomic_uint32_t (code, mem, val, old, rflags);
  else if (size == 8)
    return _eri_atomic_uint64_t (code, mem, val, old, rflags);
  return 0;
}

#define ERI_FOREACH_SIG_ACT_TYPE(p, ...) \
  p (IGNORE, ##__VA_ARGS__)						\
  p (TERM, ##__VA_ARGS__)						\
  p (CORE, ##__VA_ARGS__)						\
  p (STOP, ##__VA_ARGS__)						\
  p (LOST, ##__VA_ARGS__) /* e.g. lost SIGTRAP */			\
  p (USER, ##__VA_ARGS__)

enum
{
#define _ERI_SIG_ACT_TYPE(a)	ERI_PASTE (ERI_SIG_ACT_, a),
  ERI_FOREACH_SIG_ACT_TYPE (_ERI_SIG_ACT_TYPE)
  ERI_SIG_ACT_NUM
};

#define eri_sig_act_internal_act(act) \
  ({ uint8_t _act = (act)->type;					\
     _act == ERI_SIG_ACT_TERM || _act == ERI_SIG_ACT_CORE		\
     || _act == ERI_SIG_ACT_STOP || _act == ERI_SIG_ACT_LOST; })

struct eri_sig_act
{
  uint8_t type;
  struct eri_sigaction act;
  uint64_t ver;
};

static eri_unused uint8_t
eri_sig_digest_act (const struct eri_siginfo *info,
		    const struct eri_sigaction *act)
{
  int32_t sig = info->sig;
  void *action = act->act;

  /*
   * 1. the linux kernel implementation is like this.
   * 2. we depend on this to keep all sync signals recorded (ignored signal
   *    is not recorded currently).
   */
  if (eri_si_sync (info) && action == ERI_SIG_IGN) action = ERI_SIG_DFL;

  if (action == ERI_SIG_IGN)
    return ERI_SIG_ACT_IGNORE;

  if (action == ERI_SIG_DFL)
    {
      if (sig == ERI_SIGCHLD || sig == ERI_SIGCONT
	  || sig == ERI_SIGURG || sig == ERI_SIGWINCH)
	return ERI_SIG_ACT_IGNORE;
      if (sig == ERI_SIGHUP || sig == ERI_SIGINT || sig == ERI_SIGKILL
	  || sig == ERI_SIGPIPE || sig == ERI_SIGALRM
	  || sig == ERI_SIGTERM || sig == ERI_SIGUSR1
	  || sig == ERI_SIGUSR2 || sig == ERI_SIGIO
	  || sig == ERI_SIGPROF || sig == ERI_SIGVTALRM
	  || sig == ERI_SIGSTKFLT || sig == ERI_SIGPWR
	  || (sig >= ERI_SIGRTMIN && sig <= ERI_SIGRTMAX))
	return ERI_SIG_ACT_TERM;
      if (sig == ERI_SIGQUIT || sig == ERI_SIGILL || sig == ERI_SIGABRT
	  || sig == ERI_SIGFPE || sig == ERI_SIGSEGV || sig == ERI_SIGBUS
	  || sig == ERI_SIGSYS || sig == ERI_SIGTRAP
	  || sig == ERI_SIGXCPU || sig == ERI_SIGXFSZ)
	return ERI_SIG_ACT_CORE;
      if (sig == ERI_SIGTSTP || sig == ERI_SIGTTIN || sig == ERI_SIGTTOU)
	return ERI_SIG_ACT_STOP;

      eri_assert_unreachable ();
    }
  return ERI_SIG_ACT_USER;
}

static eri_unused int32_t
eri_common_get_mem_prot (int32_t prot)
{
  /* XXX: prot */
  if (prot & ERI_PROT_WRITE) prot |= ERI_PROT_READ;
  if (prot & ERI_PROT_READ) prot |= ERI_PROT_EXEC;
  return prot;
}

eri_noreturn void eri_jump (void *rsp, void *rip,
			    void *rdi, void *rsi, void *rdx);

struct eri_smaps_map
{
  struct eri_range range;
  int32_t prot;
  const char *path;
  uint8_t grows_down;
};

void eri_smaps_foreach_map (const char *smaps, struct eri_mtpool *pool,
	void (*proc) (const struct eri_smaps_map *, void *), void *args);

void eri_init_foreach_map (
	struct eri_mtpool *pool, const struct eri_range *map,
	void (*proc) (const struct eri_smaps_map *, void *), void *args);

#define ERI_FOREACH_ACCESS_TYPE(p, ...) \
  p (NONE, ##__VA_ARGS__)						\
  p (READ, ##__VA_ARGS__)						\
  p (WRITE, ##__VA_ARGS__)						\
  p (PROT_READ, ##__VA_ARGS__)						\
  p (PROT_WRITE, ##__VA_ARGS__)

#if 0
  p (EXEC, ##__VA_ARGS__)						\
  p (READ_MAP_ERR, ##__VA_ARGS__)					\
  p (WRITE_MAP_ERR, ##__VA_ARGS__)					\
  p (EXEC_MAP_ERR, ##__VA_ARGS__)
#endif

enum
{
#define _ERI_ACCESS_TYPE(a)	ERI_PASTE (ERI_ACCESS_, a),
  ERI_FOREACH_ACCESS_TYPE (_ERI_ACCESS_TYPE)
  ERI_ACCESS_START = ERI_ACCESS_READ,
  ERI_ACCESS_END = ERI_ACCESS_PROT_WRITE + 1
};

static eri_unused const char *
eri_access_type_str (uint8_t type)
{
  switch (type)
    {
#define _ERI_CASE_ACCESS_TYPE_STR(a) \
  case ERI_PASTE (ERI_ACCESS_, a):					\
    return ERI_STR (ERI_PASTE (ERI_ACCESS_, a));
    ERI_FOREACH_ACCESS_TYPE (_ERI_CASE_ACCESS_TYPE_STR)
    default: eri_assert_unreachable ();
    }
}

struct eri_access
{
  uint64_t addr;
  uint64_t size;
  uint64_t rip;
  uint8_t type;
};

static eri_unused void
eri_set_access (struct eri_access *acc, uint64_t addr,
		uint64_t size, uint64_t rip, uint8_t type)
{
  acc->addr = addr;
  acc->size = size;
  acc->rip = rip;
  acc->type = type;
}

#define eri_set_read(acc, addr, size, rip) \
  eri_set_access (acc, addr, size, rip, ERI_ACCESS_READ)
#define eri_set_write(acc, addr, size, rip) \
  eri_set_access (acc, addr, size, rip, ERI_ACCESS_WRITE)

static eri_unused void
eri_set_read_write (struct eri_access *acc,
		    uint64_t addr, uint64_t size, uint64_t rip)
{
  eri_set_read (acc, addr, size, rip);
  eri_set_write (acc + 1, addr, size, rip);
}

static eri_unused void
eri_append_access (struct eri_buf *buf, uint64_t addr,
		   uint64_t size, uint64_t rip, uint8_t type)
{
  struct eri_access acc = { addr, size, rip, type };
  eri_assert_buf_append (buf, &acc, 1);
}

static eri_unused uint64_t
eri_syscall_futex_check_user_addr (uint64_t user_addr, uint64_t page_size)
{
  if (user_addr % sizeof (int32_t)) return ERI_EINVAL;
  /* XXX: limit */
  if (user_addr + sizeof (int32_t) > ((1l << 47) - page_size))
    return ERI_EFAULT;
  return 0;
}

static eri_unused uint64_t
eri_syscall_futex_check_wake (uint32_t op, uint32_t mask,
			      uint64_t user_addr, uint64_t page_size)
{
  if (op & ERI_FUTEX_CLOCK_REALTIME) return ERI_ENOSYS;
  if (mask == 0) return ERI_EINVAL;
  return eri_syscall_futex_check_user_addr (user_addr, page_size);
}

static eri_unused uint64_t
eri_syscall_futex_check_wake2 (uint32_t op, uint32_t mask,
			       uint64_t *user_addr, uint64_t page_size)
{
  return eri_syscall_futex_check_wake (op, mask, user_addr[0], page_size)
	? : eri_syscall_futex_check_user_addr (user_addr[1], page_size);
}

static eri_unused uint16_t
eri_syscall_futex_atomic_code_from_wake_op (uint16_t op)
{
  switch (op)
    {
    case ERI_FUTEX_OP_SET: return ERI_OP_ATOMIC_XCHG;
    case ERI_FUTEX_OP_ADD: return ERI_OP_ATOMIC_XADD;
    case ERI_FUTEX_OP_OR: return ERI_OP_ATOMIC_X_OR;
    case ERI_FUTEX_OP_ANDN: return ERI_OP_ATOMIC_XAND; /* &= ~op_arg */
    case ERI_FUTEX_OP_XOR: return ERI_OP_ATOMIC_XXOR;
    default: eri_assert_unreachable ();
    }
}

static eri_unused uint64_t
eri_syscall_check_clock_id (int32_t id)
{
  return id == ERI_CLOCK_REALTIME || id == ERI_CLOCK_MONOTONIC
	 || id == ERI_CLOCK_PROCESS_CPUTIME_ID
	 || id == ERI_CLOCK_THREAD_CPUTIME_ID ? 0 : ERI_EINVAL;
}

static eri_unused uint64_t
eri_syscall_check_prlimit64_resource (int32_t resource)
{
  return resource < 0 || resource >= ERI_RLIMIT_NLIMITS ? ERI_EINVAL : 0;
}

static eri_unused uint64_t
eri_syscall_check_getrusage_who (int32_t who)
{
  return who != ERI_RUSAGE_SELF && who != ERI_RUSAGE_CHILDREN
	 && who != ERI_RUSAGE_THREAD ? ERI_EINVAL : 0;
}

#endif
