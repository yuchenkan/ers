#ifndef ERI_COMMON_SERIAL_H
#define ERI_COMMON_SERIAL_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/printf.h>

#define eri_build_path_len(path, name, id) \
  (eri_strlen (path) + 1 + eri_strlen (name) + eri_itoa_size (id))

void eri_build_path (const char *path, const char *name,
		     uint64_t id, char *buf);

void eri_mkdir (const char *path);

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
				const uint8_t *a, uint64_t size);
void eri_unserialize_uint8_array (eri_file_t file,
				  uint8_t *a, uint64_t size);
void eri_unserialize_skip_uint8_array (eri_file_t file, uint64_t size);

void eri_serialize_uint64_array (eri_file_t file,
				 const uint64_t *a, uint64_t size);
void eri_unserialize_uint64_array (eri_file_t file,
				   uint64_t *a, uint64_t size);

void eri_serialize_sigset (eri_file_t file, const struct eri_sigset *set);
void eri_unserialize_sigset (eri_file_t file, struct eri_sigset *set);

void eri_serialize_stack (eri_file_t file, const struct eri_stack *set);
void eri_unserialize_stack (eri_file_t file, struct eri_stack *set);

void eri_serialize_siginfo (eri_file_t file, const struct eri_siginfo *info);
void eri_unserialize_siginfo (eri_file_t file, struct eri_siginfo *info);

void eri_serialize_sigaction (eri_file_t file,
			      const struct eri_sigaction *act);
void eri_unserialize_sigaction (eri_file_t file, struct eri_sigaction *act);

void eri_serialize_ver_sigaction (eri_file_t file,
				  const struct eri_ver_sigaction *act);
void eri_unserialize_ver_sigaction (eri_file_t file,
				    struct eri_ver_sigaction *act);

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

struct eri_signal_record
{
  uint64_t in;
  struct eri_siginfo info;
  struct eri_ver_sigaction act;
};

void eri_serialize_signal_record (eri_file_t file,
				  const struct eri_signal_record *rec);
void eri_unserialize_signal_record (eri_file_t file,
				    struct eri_signal_record *rec);

enum
{
  ERI_SIGNAL_MAGIC,
  ERI_SYSCALL_RESULT_MAGIC,
  ERI_SYSCALL_IN_MAGIC,
  ERI_SYSCALL_OUT_MAGIC,
  ERI_SYSCALL_RESULT_IN_MAGIC,
  ERI_SYSCALL_CLONE_MAGIC,
  ERI_SYSCALL_RT_SIGACTION_SET_MAGIC,
  ERI_SYSCALL_RT_SIGACTION_MAGIC,
  ERI_SYSCALL_RT_SIGPENDING_MAGIC,
  ERI_SYSCALL_RT_SIGTIMEDWAIT_MAGIC,
  ERI_SYSCALL_KILL_MAGIC,
  ERI_SYSCALL_READ_MAGIC,
  ERI_SYSCALL_READV_MAGIC,
  ERI_SYNC_ASYNC_MAGIC,
  ERI_ATOMIC_MAGIC
};

#define eri_serialize_magic(file, magic) \
  eri_serialize_uint16 (file, magic)
#define eri_unserialize_magic(file) \
  eri_unserialize_uint16 (file)

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

struct eri_syscall_rt_sigtimedwait_record
{
  uint64_t result;
  uint64_t in;
  struct eri_siginfo info;
};

void eri_serialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			const struct eri_syscall_rt_sigtimedwait_record *rec);
void eri_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec);

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

struct eri_syscall_read_record
{
  uint64_t result;
  uint64_t in;
  uint8_t *buf;

  void *copy;
  void *args;
};

void eri_serialize_syscall_read_record (eri_file_t file,
			const struct eri_syscall_read_record *rec);
void eri_unserialize_syscall_read_record (eri_file_t file,
			struct eri_syscall_read_record *rec);

struct eri_syscall_readv_record
{
  uint64_t result;
  uint64_t in;
  struct eri_iovec *iov;

  void *copy;
  void *args;
};

void eri_serialize_syscall_readv_record (eri_file_t file,
			const struct eri_syscall_readv_record *rec);
void eri_unserialize_syscall_readv_record (eri_file_t file,
			struct eri_syscall_readv_record *rec);

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
