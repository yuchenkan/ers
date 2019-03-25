#ifndef ERI_COMMON_H
#define ERI_COMMON_H

#include <stdint.h>

#include <compiler.h>
#include <entry.h>

#include <lib/util.h>
#include <lib/lock.h>
#include <lib/syscall-common.h>
#include <lib/printf.h>

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

#define eri_sig_valid(sig) \
  ({ int32_t _s1 = sig; _s1 > 0 && _s1 < ERI_NSIG; })
#define eri_sig_catchable(sig) \
  ({ int32_t _s2 = sig;							\
     eri_sig_valid (_s2) && _s2 != ERI_SIGKILL && _s2 != ERI_SIGSTOP; })

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

struct eri_sigframe *eri_sig_setup_user_frame (struct eri_sigframe *frame,
		const struct eri_sigaction *act, struct eri_stack *stack,
		const struct eri_sigset *mask, void *copy, void *args);

eri_noreturn void eri_sig_act (struct eri_sigframe *frame, void *act);

#define ERI_DEFINE_THREAD_UTILS(thread_type, thread_group_type) \
static eri_unused uint8_t						\
internal (thread_group_type *group, uint64_t addr)			\
{									\
  return addr >= group->map_start && addr < group->map_end;		\
}									\
									\
static eri_unused uint8_t						\
internal_range (thread_group_type *group,				\
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
sig_access_fault (struct thread_context *th_ctx,			\
		  struct eri_siginfo *info, struct eri_ucontext *ctx)	\
{									\
  if (! eri_si_access_fault (info) || ctx->mctx.rip != th_ctx->access)	\
    return 0;								\
									\
  ctx->mctx.rip = th_ctx->access_fault;					\
  return 1;								\
}

#define ERI_IF_SYSCALL(name, nr, op, ...) \
  if ((nr) == ERI_PASTE (__NR_, name)) op (name, ##__VA_ARGS__);

uint8_t eri_common_syscall_rt_sigprocmask_get (
		struct eri_entry_scratch_registers *sregs,
		const struct eri_sigset *old_mask, struct eri_sigset *mask,
		void *copy, void *args);
void eri_common_syscall_rt_sigprocmask_set (
		struct eri_entry_scratch_registers *sregs,
		const struct eri_sigset *old_mask, void *copy, void *args);

uint8_t eri_common_syscall_rt_sigaction_get (
		struct eri_entry_scratch_registers *sregs,
		struct eri_sigaction *act, void *copy, void *args);
void eri_common_syscall_rt_sigaction_set (
		struct eri_entry_scratch_registers *sregs,
		const struct eri_sigaction *old_act, void *copy, void *args);

void eri_common_syscall_sigaltstack (
		struct eri_entry_scratch_registers *sregs, uint64_t rsp,
		struct eri_stack *stack,
		void *copy_from, void *copy_to, void *args);

struct eri_common_syscall_rt_sigreturn_args
{
  struct eri_entry_thread_entry *entry;
  struct eri_entry_thread_context *th_ctx;
  struct eri_entry_extra_registers *eregs;

  const struct eri_stack *stack;

  struct eri_sigset *mask;
  struct eri_stack *sig_alt_stack;

  void *copy;
  void *args;
};

uint8_t eri_common_syscall_rt_sigreturn (
		struct eri_common_syscall_rt_sigreturn_args *args);

#define eri_common_rt_sigpending_valid_sig_set_size(size) \
  ((size) <= ERI_SIG_SETSIZE) /* XXX: from kernel source */

#define eri_atomic_slot(mem)		((mem) & ~0xf)
#define eri_atomic_slot2(mem, size)	eri_atomic_slot ((mem) + (size) - 1)

#define eri_atomic_cross_slot(mem, size) \
  ({ uint64_t _mem = mem;						\
     eri_atomic_slot (_mem) != eri_atomic_slot2 (_mem, size); })

#define eri_atomic_hash(slot, size)	(eri_hash (slot) % (size))

void eri_serialize_uint8 (eri_file_t file, uint8_t v);
uint8_t eri_unserialize_uint8 (eri_file_t file);
uint8_t eri_unserialize_uint8_or_eof (eri_file_t file, uint8_t *v);

void eri_serialize_uint16 (eri_file_t file, uint16_t v);
uint16_t eri_unserialize_uint16 (eri_file_t file);
void eri_serialize_int32 (eri_file_t file, int32_t v);
int32_t eri_unserialize_int32 (eri_file_t file);
void eri_serialize_uint64 (eri_file_t file, uint64_t v);
uint64_t eri_unserialize_uint64 (eri_file_t file);

void eri_serialize_uint8_array (eri_file_t file,
				const uint8_t *arr, uint64_t size);
void eri_unserialize_uint8_array (eri_file_t file,
				  uint8_t *arr, uint64_t size);
void eri_unserialize_skip_uint8_array (eri_file_t file, uint64_t size);

void eri_serialize_sigset (eri_file_t file, const struct eri_sigset *set);
void eri_unserialize_sigset (eri_file_t file, struct eri_sigset *set);

void eri_serialize_stack (eri_file_t file, const struct eri_stack *set);
void eri_unserialize_stack (eri_file_t file, struct eri_stack *set);

void eri_serialize_siginfo (eri_file_t file, const struct eri_siginfo *info);
void eri_unserialize_siginfo (eri_file_t file, struct eri_siginfo *info);

enum
{
  ERI_INIT_RECORD,
  ERI_INIT_MAP_RECORD,
  ERI_ASYNC_RECORD,
  ERI_SYNC_RECORD
};

#define eri_serialize_mark(file, mark) \
  eri_serialize_uint8 (file, mark)
#define eri_unserialize_mark(file) \
  eri_unserialize_uint8 (file)

struct eri_init_record
{
  uint64_t ver;

  uint64_t rdx;
  uint64_t rsp;
  uint64_t rip;

  struct eri_sigset sig_mask;
  struct eri_stack sig_alt_stack;
  int32_t user_pid;

  uint64_t start;
  uint64_t end;

  uint64_t atomic_table_size;
};

void eri_serialize_init_record (eri_file_t file,
				const struct eri_init_record *rec);
void eri_unserialize_init_record (eri_file_t file,
				  struct eri_init_record *rec);

struct eri_init_map_record
{
  uint64_t start, end;
  uint8_t prot;
  uint8_t grows_down;

  uint8_t data_count;
};

void eri_serialize_init_map_record (eri_file_t file,
				    const struct eri_init_map_record *rec);
void eri_unserialize_init_map_record (eri_file_t file,
				      struct eri_init_map_record *rec);

enum
{
  ERI_SYSCALL_RESULT_MAGIC,
  ERI_SYSCALL_IN_MAGIC,
  ERI_SYSCALL_OUT_MAGIC,
  ERI_SYSCALL_CLONE_MAGIC,
  ERI_SYSCALL_RT_SIGPENDING_MAGIC,
  ERI_SYSCALL_KILL_MAGIC,
  ERI_SYNC_ASYNC_MAGIC,
  ERI_ATOMIC_MAGIC
};

#define eri_serialize_magic(file, magic) \
  eri_serialize_uint16 (file, magic)
#define eri_unserialize_magic(file) \
  eri_unserialize_uint16 (file)

struct eri_signal_record
{
  uint64_t in;
  struct eri_siginfo info;
};

void eri_serialize_signal_record (eri_file_t file,
				  const struct eri_signal_record *rec);
void eri_unserialize_signal_record (eri_file_t file,
				    struct eri_signal_record *rec);

struct eri_syscall_clone_record
{
  uint64_t out;
  uint64_t result;
  uint64_t id;
};

void eri_serialize_syscall_clone_record (eri_file_t file,
			const struct eri_syscall_clone_record *rec);
void eri_unserialize_syscall_clone_record (eri_file_t file,
			struct eri_syscall_clone_record *rec);

struct eri_syscall_rt_sigpending_record
{
  uint64_t result;
  uint64_t in;
  struct eri_sigset set;
};

void eri_serialize_syscall_rt_sigpending_record (eri_file_t file,
			const struct eri_syscall_rt_sigpending_record *rec);
void eri_unserialize_syscall_rt_sigpending_record (eri_file_t file,
			struct eri_syscall_rt_sigpending_record *rec);

struct eri_syscall_kill_record
{
  uint64_t out;
  uint64_t result;
  uint64_t in;
};

void eri_serialize_syscall_kill_record (eri_file_t file,
			const struct eri_syscall_kill_record *rec);
void eri_unserialize_syscall_kill_record (eri_file_t file,
			struct eri_syscall_kill_record *rec);

struct eri_atomic_record
{
  uint8_t updated;
  uint64_t ver[2];
  uint64_t val;
};

void eri_serialize_atomic_record (eri_file_t file,
				  const struct eri_atomic_record *rec);
void eri_unserialize_atomic_record (eri_file_t file,
				    struct eri_atomic_record *rec);

#include <compiler.h>
#include <lib/printf.h>
#include <lib/syscall.h>

#define _eri_log(level, fmt, ...) \
  eri_printf ("[" ERI_STR (level) " %s:%u(%s)%lu]\t" fmt,		\
	      __FILE__, __LINE__, __FUNCTION__,				\
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
    uint8_t _buf[1024];							\
    eri_file_t _file = eri_assert_fopen ("/proc/self/maps", 1, 0, 0);	\
    uint64_t _len;							\
    do									\
      {									\
        eri_assert_fread (_file, _buf, sizeof _buf, &_len);		\
        eri_assert_fwrite (ERI_STDOUT, _buf, _len, 0);			\
      }									\
    while (_len == sizeof _buf);					\
  } while (0)

#endif
