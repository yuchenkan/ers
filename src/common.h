#ifndef ERI_COMMON_H
#define ERI_COMMON_H

#include <stdint.h>

#include <compiler.h>
#include <lib/util.h>
#include <lib/lock.h>
#include <lib/syscall-common.h>

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

#define eri_build_path_len(path, name, id) \
  (eri_strlen (path) + 1 + eri_strlen (name) + eri_itoa_size (id))

void eri_build_path (const char *path, const char *name,
		     uint64_t id, char *buf);

void eri_mkdir (const char *path);

struct eri_sig_act
{
  struct eri_lock lock;
  struct eri_sigaction act;
};

void eri_sig_init_acts (struct eri_sig_act *sig_acts, eri_sig_handler_t hand);
void eri_sig_get_act (struct eri_sig_act *sig_acts, int32_t sig,
		      struct eri_sigaction *act);
void eri_sig_set_act (struct eri_sig_act *sig_acts, int32_t sig,
		      const struct eri_sigaction *act,
		      struct eri_sigaction *old_act);

#define ERI_SIG_ACT_TERM	((void *) 1)
#define ERI_SIG_ACT_CORE	((void *) 2)
#define ERI_SIG_ACT_STOP	((void *) 3)

#define eri_sig_act_internal_act(act) \
  ({ void *_act = act;							\
     _act == ERI_SIG_ACT_TERM || _act == ERI_SIG_ACT_CORE		\
     || _act == ERI_SIG_ACT_STOP; })

void eri_sig_digest_act (const struct eri_siginfo *info,
		const struct eri_sigset *mask, struct eri_sigaction *act);

#define ERI_DEFINE_THREAD_UTILS(thread_type) \
static eri_unused uint8_t						\
internal (struct thread_group *group, uint64_t addr)			\
{									\
  return addr >= group->map_start && addr < group->map_end;		\
}									\
									\
static eri_unused uint8_t						\
internal_range (struct thread_group *group,				\
		uint64_t addr, uint64_t size)				\
{									\
  return addr + size > group->map_start && addr < group->map_end;	\
}									\
									\
static eri_unused uint8_t						\
copy_from_user (thread_type *th,					\
		void *dst, const void *src, uint64_t size)		\
{									\
  if (! src) return 0;							\
  if (internal_range (th->group, (uint64_t) src, size)) return 0;	\
  return do_copy_from_user (th->ctx, dst, src, size);			\
}									\
									\
static eri_unused uint8_t						\
copy_to_user (thread_type *th,						\
	      void *dst, const void *src, uint64_t size)		\
{									\
  if (! dst) return 0;							\
  if (internal_range (th->group, (uint64_t) dst, size)) return 0;	\
  return do_copy_to_user (th->ctx, dst, src, size);			\
}									\
									\
static eri_unused uint8_t						\
force_copy_from_user (thread_type *th,					\
		      void *dst, const void *src, uint64_t size)	\
{									\
  if (internal_range (th->group, (uint64_t) src, size)) src = 0;	\
  return do_force_copy_from_user (th->ctx, dst, src, size);		\
}									\
									\
static eri_unused uint8_t						\
force_copy_to_user (thread_type *th,					\
		    void *dst, const void *src, uint64_t size)		\
{									\
  if (internal_range (th->group, (uint64_t) dst, size)) dst = 0;	\
  return do_force_copy_to_user (th->ctx, dst, src, size);		\
}									\
									\
static eri_unused uint8_t						\
sig_access_fault (struct thread_context *th_ctx,			\
		  struct eri_siginfo *info, struct eri_ucontext *ctx,	\
		  uint8_t force)					\
{									\
  if (! eri_si_access_fault (info)					\
      || ctx->mctx.rip != (force					\
			? th_ctx->force_access : th_ctx->access))	\
    return 0;								\
									\
  ctx->mctx.rip = th_ctx->access_fault;					\
  return 1;								\
}

#define ERI_IF_SYSCALL(name, nr, op, ...) \
  if ((nr) == ERI_PASTE (__NR_, name)) op (name, ##__VA_ARGS__);

#define eri_atomic_slot(mem)		((mem) & ~0xf)
#define eri_atomic_slot2(mem, size)	eri_atomic_slot ((mem) + (size) - 1)

#define eri_atomic_cross_slot(mem, size) \
  ({ uint64_t _mem = mem;						\
     eri_atomic_slot (_mem) != eri_atomic_slot2 (_mem, size); })

#define eri_atomic_hash(slot, size)	(eri_hash (slot) % (size))

#include <compiler.h>
#include <lib/printf.h>
#include <lib/syscall.h>

#define _eri_log(level, fmt, ...) \
  eri_assert_printf ("[" ERI_STR (level) " %s:%u(%s)%lu]\t" fmt,	\
		     __FILE__, __LINE__, __FUNCTION__,			\
		     eri_assert_syscall (gettid), ##__VA_ARGS__)

static eri_unused uint8_t eri_enable_debug = 0;
extern uint8_t eri_global_enable_debug;
#define eri_debug(fmt, ...) \
  do {									\
    if (eri_enable_debug || eri_global_enable_debug)			\
      _eri_log (DEBUG, fmt, ##__VA_ARGS__);				\
  } while (0)

#define eri_info(fmt, ...)	_eri_log (INFO, fmt, ##__VA_ARGS__)

#define eri_debug_stop() \
  eri_assert_syscall (kill, eri_assert_syscall (getpid), ERI_SIGSTOP)

#define eri_dump_maps() \
  do {									\
    eri_file_t _file;							\
    uint8_t _buf[1024];							\
    eri_assert_fopen ("/proc/self/maps", 1, &_file, 0, 0);		\
    uint64_t _len;							\
    do									\
      {									\
        eri_assert_fread (_file, _buf, sizeof _buf, &_len);		\
        eri_assert_fwrite (ERI_STDOUT, _buf, _len, 0);			\
      }									\
    while (_len == sizeof _buf);					\
  } while (0)

#endif
