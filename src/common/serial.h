#ifndef ERI_COMMON_SERIAL_H
#define ERI_COMMON_SERIAL_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/printf.h>

#include <common/common.h>

void eri_serialize_uint8 (eri_file_t file, uint8_t v);
uint8_t eri_try_unserialize_uint8 (eri_file_t file, uint8_t *v);
uint8_t eri_unserialize_uint8 (eri_file_t file);
uint8_t eri_unserialize_uint8_or_eof (eri_file_t file, uint8_t *v);

void eri_serialize_uint16 (eri_file_t file, uint16_t v);
uint8_t eri_try_unserialize_uint16 (eri_file_t file, uint16_t *v);
uint16_t eri_unserialize_uint16 (eri_file_t file);
void eri_serialize_int32 (eri_file_t file, int32_t v);
uint8_t eri_try_unserialize_int32 (eri_file_t file, int32_t *v);
int32_t eri_unserialize_int32 (eri_file_t file);
void eri_serialize_uint64 (eri_file_t file, uint64_t v);
uint8_t eri_try_unserialize_uint64 (eri_file_t file, uint64_t *v);
uint64_t eri_unserialize_uint64 (eri_file_t file);

void eri_serialize_uint8_array (eri_file_t file,
				const uint8_t *a, uint64_t size);
uint8_t eri_try_unserialize_uint8_array (eri_file_t file,
					 uint8_t *a, uint64_t size);
void eri_unserialize_uint8_array (eri_file_t file,
				  uint8_t *a, uint64_t size);
void eri_unserialize_skip_uint8_array (eri_file_t file, uint64_t size);

void eri_serialize_uint64_array (eri_file_t file,
				 const uint64_t *a, uint64_t size);
uint8_t eri_try_unserialize_uint64_array (eri_file_t file,
					  uint64_t *a, uint64_t size);
void eri_unserialize_uint64_array (eri_file_t file,
				   uint64_t *a, uint64_t size);

void eri_serialize_pair (eri_file_t file, struct eri_pair pair);
uint8_t eri_try_unserialize_pair (eri_file_t file, struct eri_pair *pair);
struct eri_pair eri_unserialize_pair (eri_file_t file);

void eri_serialize_sigset (eri_file_t file, const struct eri_sigset *set);
uint8_t eri_try_unserialize_sigset (eri_file_t file, struct eri_sigset *set);
void eri_unserialize_sigset (eri_file_t file, struct eri_sigset *set);

void eri_serialize_stack (eri_file_t file, const struct eri_stack *set);
uint8_t eri_try_unserialize_stack (eri_file_t file, struct eri_stack *set);
void eri_unserialize_stack (eri_file_t file, struct eri_stack *set);

void eri_serialize_siginfo (eri_file_t file, const struct eri_siginfo *info);
uint8_t eri_try_unserialize_siginfo (eri_file_t file,
				     struct eri_siginfo *info);
void eri_unserialize_siginfo (eri_file_t file, struct eri_siginfo *info);

void eri_serialize_sigaction (eri_file_t file,
			      const struct eri_sigaction *act);
uint8_t eri_try_unserialize_sigaction (eri_file_t file,
				       struct eri_sigaction *act);
void eri_unserialize_sigaction (eri_file_t file, struct eri_sigaction *act);

void eri_serialize_sig_act (eri_file_t file, const struct eri_sig_act *act);
uint8_t eri_try_unserialize_sig_act (eri_file_t file,
				     struct eri_sig_act *act);
void eri_unserialize_sig_act (eri_file_t file, struct eri_sig_act *act);

#define ERI_FOREACH_RECORD_MARK(p, ...) \
  p (INIT, ##__VA_ARGS__)						\
  p (INIT_MAP, ##__VA_ARGS__)						\
  p (ASYNC, ##__VA_ARGS__)						\
  p (SYNC, ##__VA_ARGS__)

enum
{
#define _ERI_RECORD_MARK(m)	ERI_PASTE2 (ERI_, m, _RECORD),
  ERI_FOREACH_RECORD_MARK (_ERI_RECORD_MARK)
  ERI_RECORD_MARK_NUM
};

static eri_unused const char *
eri_record_mark_str (uint8_t mark)
{
  switch (mark)
    {
#define _ERI_CASE_RECORD_MARK_STR(m) \
  case ERI_PASTE2 (ERI_, m, _RECORD):					\
    return ERI_STR (ERI_PASTE2 (ERI_, m, _RECORD));
    ERI_FOREACH_RECORD_MARK (_ERI_CASE_RECORD_MARK_STR)
    default: eri_assert_unreachable ();
    }
}

#define eri_serialize_mark(file, mark) \
  eri_serialize_uint8 (file, mark)
#define eri_try_unserialize_mark(file, mark) \
  eri_try_unserialize_uint8 (file, mark)
#define eri_unserialize_mark(file) \
  ({ uint8_t _mark;							\
     eri_assert (eri_try_unserialize_mark (file, &_mark)); _mark; })

struct eri_init_record
{
  uint64_t ver;

  uint64_t rdx;
  uint64_t rsp;
  uint64_t rip;

  struct eri_sigset sig_mask;
  struct eri_stack sig_alt_stack;
  int32_t user_pid;

  struct eri_range map_range;

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

struct eri_async_signal_record
{
  uint64_t in;
  struct eri_siginfo info;
  struct eri_sig_act act;
};

void eri_serialize_async_signal_record (eri_file_t file,
			const struct eri_async_signal_record *rec);
uint8_t eri_try_unserialize_async_signal_record (eri_file_t file,
			struct eri_async_signal_record *rec);
void eri_unserialize_async_signal_record (eri_file_t file,
			struct eri_async_signal_record *rec);

#define ERI_FOREACH_RECORD_MAGIC(p, ...) \
  p (SIGNAL, ##__VA_ARGS__)						\
  p (SYSCALL_RESULT, ##__VA_ARGS__)					\
  p (SYSCALL_IN, ##__VA_ARGS__)						\
  p (SYSCALL_OUT, ##__VA_ARGS__)					\
  p (SYSCALL_RES_IN, ##__VA_ARGS__)					\
  p (SYSCALL_RES_IO, ##__VA_ARGS__)					\
  p (SYSCALL_CLONE, ##__VA_ARGS__)					\
  p (SYSCALL_EXIT_CLEAR_TID, ##__VA_ARGS__)				\
  p (SYSCALL_RT_SIGACTION_SET, ##__VA_ARGS__)				\
  p (SYSCALL_RT_SIGACTION, ##__VA_ARGS__)				\
  p (SYSCALL_RT_SIGPENDING, ##__VA_ARGS__)				\
  p (SYSCALL_RT_SIGTIMEDWAIT, ##__VA_ARGS__)				\
  p (SYSCALL_READ, ##__VA_ARGS__)					\
  p (SYNC_ASYNC, ##__VA_ARGS__)						\
  p (ATOMIC, ##__VA_ARGS__)

enum
{
#define _ERI_RECORD_MAGIC(m)	ERI_PASTE2 (ERI_, m, _MAGIC),
  ERI_FOREACH_RECORD_MAGIC (_ERI_RECORD_MAGIC)
};

static eri_unused const char *
eri_record_magic_str (uint16_t magic)
{
  switch (magic)
    {
#define _ERI_CASE_RECORD_MAGIC_STR(m) \
  case ERI_PASTE2 (ERI_, m, _MAGIC):					\
    return ERI_STR (ERI_PASTE2 (ERI_, m, _MAGIC));
    ERI_FOREACH_RECORD_MAGIC (_ERI_CASE_RECORD_MAGIC_STR)
    default: eri_assert_unreachable ();
    }
}

#define eri_serialize_magic(file, magic) \
  eri_serialize_uint16 (file, magic)
#define eri_try_unserialize_magic(file, magic) \
  eri_try_unserialize_uint16 (file, magic)
#define eri_unserialize_magic(file) \
  ({ uint16_t _magic;							\
     eri_assert (eri_try_unserialize_magic (file, &_magic)); _magic; })

struct eri_atomic_record
{
  uint8_t updated;
  struct eri_pair ver;
  uint64_t val;
};

void eri_serialize_atomic_record (eri_file_t file,
				  const struct eri_atomic_record *rec);
uint8_t eri_try_unserialize_atomic_record (eri_file_t file,
					   struct eri_atomic_record *rec);
void eri_unserialize_atomic_record (eri_file_t file,
				    struct eri_atomic_record *rec);

struct eri_syscall_res_in_record
{
  uint64_t result;
  uint64_t in;
};

void eri_serialize_syscall_res_in_record (eri_file_t file,
			const struct eri_syscall_res_in_record *rec);
uint8_t eri_try_unserialize_syscall_res_in_record (eri_file_t file,
			struct eri_syscall_res_in_record *rec);
void eri_unserialize_syscall_res_in_record (eri_file_t file,
			struct eri_syscall_res_in_record *rec);

struct eri_syscall_res_io_record
{
  uint64_t out;
  uint64_t result;
  uint64_t in;
};

void eri_serialize_syscall_res_io_record (eri_file_t file,
			const struct eri_syscall_res_io_record *rec);
uint8_t eri_try_unserialize_syscall_res_io_record (eri_file_t file,
			struct eri_syscall_res_io_record *rec);
void eri_unserialize_syscall_res_io_record (eri_file_t file,
			struct eri_syscall_res_io_record *rec);

struct eri_syscall_clone_record
{
  /*
   * out is necessary even if failed because the version is
   * nevertheless increased.
   */
  uint64_t out;
  uint64_t result;
  uint64_t id;
};

void eri_serialize_syscall_clone_record (eri_file_t file,
			const struct eri_syscall_clone_record *rec);
uint8_t eri_try_unserialize_syscall_clone_record (eri_file_t file,
			struct eri_syscall_clone_record *rec);
void eri_unserialize_syscall_clone_record (eri_file_t file,
			struct eri_syscall_clone_record *rec);

struct eri_syscall_exit_clear_tid_record
{
  uint64_t out;
  struct eri_atomic_record clear_tid;
};

void eri_serialize_syscall_exit_clear_tid_record (eri_file_t file,
			const struct eri_syscall_exit_clear_tid_record *rec);
uint8_t eri_try_unserialize_syscall_exit_clear_tid_record (eri_file_t file,
			struct eri_syscall_exit_clear_tid_record *rec);
void eri_unserialize_syscall_exit_clear_tid_record (eri_file_t file,
			struct eri_syscall_exit_clear_tid_record *rec);

struct eri_syscall_rt_sigpending_record
{
  uint64_t result;
  uint64_t in;
  struct eri_sigset set;
};

void eri_serialize_syscall_rt_sigpending_record (eri_file_t file,
			const struct eri_syscall_rt_sigpending_record *rec);
uint8_t eri_try_unserialize_syscall_rt_sigpending_record (eri_file_t file,
			struct eri_syscall_rt_sigpending_record *rec);
void eri_unserialize_syscall_rt_sigpending_record (eri_file_t file,
			struct eri_syscall_rt_sigpending_record *rec);

struct eri_syscall_rt_sigtimedwait_record
{
  uint64_t result;
  uint64_t in;
  struct eri_siginfo info;
};

void eri_serialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			const struct eri_syscall_rt_sigtimedwait_record *rec);
uint8_t eri_try_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec);
void eri_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec);

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
