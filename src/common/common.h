#ifndef ERI_COMMON_COMMON_H
#define ERI_COMMON_COMMON_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/printf.h>
#include <lib/lock.h>
#include <lib/syscall.h>

struct eri_mtpool;

#define eri_build_path_len(path, name, id) \
  (eri_strlen (path) + 1 + eri_strlen (name) + eri_itoa_size (id))

void eri_build_path (const char *path, const char *name,
		     uint64_t id, char *buf);
eri_file_t eri_open_path (const char *path, const char *name,
			  uint64_t id, void *buf, uint64_t buf_size);

struct eri_buf_file
{
  struct eri_lock lock;
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
eri_common_syscall_get_mem_prot (int32_t prot)
{
  /* XXX: prot */
  if (prot & ERI_PROT_WRITE) prot |= ERI_PROT_READ;
  if (prot & ERI_PROT_READ) prot |= ERI_PROT_EXEC;
  return prot;
}

eri_noreturn void eri_jump (void *rsp, void *rip,
			    void *rdi, void *rsi, void *rdx);

#endif
