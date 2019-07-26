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
void eri_serialize_uint32 (eri_file_t file, uint32_t v);
uint8_t eri_try_unserialize_uint32 (eri_file_t file, uint32_t *v);
uint32_t eri_unserialize_uint32 (eri_file_t file);
void eri_serialize_int32 (eri_file_t file, int32_t v);
uint8_t eri_try_unserialize_int32 (eri_file_t file, int32_t *v);
int32_t eri_unserialize_int32 (eri_file_t file);
void eri_serialize_uint64 (eri_file_t file, uint64_t v);
uint8_t eri_try_unserialize_uint64 (eri_file_t file, uint64_t *v);
uint64_t eri_unserialize_uint64 (eri_file_t file);
void eri_serialize_int64 (eri_file_t file, int64_t v);
uint8_t eri_try_unserialize_int64 (eri_file_t file, int64_t *v);
int64_t eri_unserialize_int64 (eri_file_t file);

void eri_serialize_uint8_array (eri_file_t file,
				const uint8_t *a, uint64_t len);
uint8_t eri_try_unserialize_uint8_array (eri_file_t file,
					 uint8_t *a, uint64_t len);
void eri_unserialize_uint8_array (eri_file_t file,
				  uint8_t *a, uint64_t len);
void eri_unserialize_skip_uint8_array (eri_file_t file, uint64_t len);

void eri_serialize_uint64_array (eri_file_t file,
				 const uint64_t *a, uint64_t len);
uint8_t eri_try_unserialize_uint64_array (eri_file_t file,
					  uint64_t *a, uint64_t len);
void eri_unserialize_uint64_array (eri_file_t file,
				   uint64_t *a, uint64_t len);

void eri_serialize_str (eri_file_t file, const char *s, uint64_t len);
uint8_t eri_try_unserialize_str (eri_file_t file, char *s, uint64_t len);
void eri_unserialize_str (eri_file_t file, char *s, uint64_t len);

void eri_serialize_pair (eri_file_t file, struct eri_pair pair);
uint8_t eri_try_unserialize_pair (eri_file_t file, struct eri_pair *pair);
struct eri_pair eri_unserialize_pair (eri_file_t file);

void eri_serialize_sigset (eri_file_t file, const eri_sigset_t *set);
uint8_t eri_try_unserialize_sigset (eri_file_t file, eri_sigset_t *set);
void eri_unserialize_sigset (eri_file_t file, eri_sigset_t *set);

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

void eri_serialize_timespec (eri_file_t file,
			     const struct eri_timespec *timespec);
uint8_t eri_try_unserialize_timespec (eri_file_t file,
				      struct eri_timespec *timespec);
void eri_unserialize_timespec (eri_file_t file,
			       struct eri_timespec *timespec);

void eri_serialize_timeval (eri_file_t file,
			     const struct eri_timeval *timeval);
uint8_t eri_try_unserialize_timeval (eri_file_t file,
				      struct eri_timeval *timeval);
void eri_unserialize_timeval (eri_file_t file,
			       struct eri_timeval *timeval);

void eri_serialize_tms (eri_file_t file, const struct eri_tms *tms);
uint8_t eri_try_unserialize_tms (eri_file_t file, struct eri_tms *tms);
void eri_unserialize_tms (eri_file_t file, struct eri_tms *tms);

void eri_serialize_stat (eri_file_t file, const struct eri_stat *stat);
uint8_t eri_try_unserialize_stat (eri_file_t file, struct eri_stat *stat);
void eri_unserialize_stat (eri_file_t file, struct eri_stat *stat);

void eri_serialize_utsname (eri_file_t file,
			    const struct eri_utsname *utsname);
uint8_t eri_try_unserialize_utsname (eri_file_t file,
				     struct eri_utsname *utsname);
void eri_unserialize_utsname (eri_file_t file, struct eri_utsname *utsname);

void eri_serialize_rlimit (eri_file_t file,
			   const struct eri_rlimit *rlimit);
uint8_t eri_try_unserialize_rlimit (eri_file_t file,
				    struct eri_rlimit *rlimit);
void eri_unserialize_rlimit (eri_file_t file, struct eri_rlimit *rlimit);

void eri_serialize_rusage (eri_file_t file,
			   const struct eri_rusage *rusage);
uint8_t eri_try_unserialize_rusage (eri_file_t file,
				    struct eri_rusage *rusage);
void eri_unserialize_rusage (eri_file_t file, struct eri_rusage *rusage);

#define ERI_FOREACH_RECORD_MARK(p, ...) \
  p (INIT, ##__VA_ARGS__)						\
  p (INIT_MAP, ##__VA_ARGS__)						\
  p (ASYNC, ##__VA_ARGS__)						\
  p (SYSCALL_RESTART_OUT, ##__VA_ARGS__)				\
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

  uint64_t page_size;
  uint64_t brk;
  eri_sigset_t sig_mask;
  struct eri_stack sig_alt_stack;
  int32_t user_pid;

  struct eri_range map_range;

  uint64_t atomic_table_size;
};

void eri_serialize_init_record (eri_file_t file,
				const struct eri_init_record *rec);
void eri_unserialize_init_record (eri_file_t file,
				  struct eri_init_record *rec);

#define ERI_INIT_MAP_EMPTY	0
#define ERI_INIT_MAP_FILE	1
#define ERI_INIT_MAP_STACK	2

struct eri_init_map_record
{
  uint64_t start, end;
  uint8_t prot;
  uint8_t grows_down;

  uint8_t type;
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
  p (SYSCALL_EXIT, ##__VA_ARGS__)					\
  p (SYSCALL_RT_SIGACTION_SET, ##__VA_ARGS__)				\
  p (SYSCALL_RT_SIGACTION, ##__VA_ARGS__)				\
  p (SYSCALL_RT_SIGPENDING, ##__VA_ARGS__)				\
  p (SYSCALL_RT_SIGTIMEDWAIT, ##__VA_ARGS__)				\
  p (SYSCALL_STAT, ##__VA_ARGS__)					\
  p (SYSCALL_UNAME, ##__VA_ARGS__)					\
  p (SYSCALL_TIMES, ##__VA_ARGS__)					\
  p (SYSCALL_GETTIMEOFDAY, ##__VA_ARGS__)				\
  p (SYSCALL_CLOCK_GETTIME, ##__VA_ARGS__)				\
  p (SYSCALL_GETRLIMIT, ##__VA_ARGS__)					\
  p (SYSCALL_PRLIMIT64, ##__VA_ARGS__)					\
  p (SYSCALL_GETRUSAGE, ##__VA_ARGS__)					\
  p (SYSCALL_ACCEPT, ##__VA_ARGS__)					\
  p (SYSCALL_GETSOCKNAME, ##__VA_ARGS__)				\
  p (SYSCALL_FUTEX, ##__VA_ARGS__)					\
  p (SYSCALL_FUTEX_REQUEUE, ##__VA_ARGS__)				\
  p (SYSCALL_READ, ##__VA_ARGS__)					\
  p (SYSCALL_MMAP, ##__VA_ARGS__)					\
  p (SYSCALL_GETCWD, ##__VA_ARGS__)					\
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
    default: return "unknown";
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
  uint8_t ok;
  struct eri_pair ver;
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
  struct eri_syscall_res_in_record res;
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

struct eri_syscall_exit_record
{
  uint64_t out;
  struct eri_atomic_record clear_tid;
};

void eri_serialize_syscall_exit_record (eri_file_t file,
			const struct eri_syscall_exit_record *rec);
uint8_t eri_try_unserialize_syscall_exit_record (eri_file_t file,
			struct eri_syscall_exit_record *rec);
void eri_unserialize_syscall_exit_record (eri_file_t file,
			struct eri_syscall_exit_record *rec);

struct eri_syscall_rt_sigpending_record
{
  struct eri_syscall_res_in_record res;
  eri_sigset_t set;
};

void eri_serialize_syscall_rt_sigpending_record (eri_file_t file,
			const struct eri_syscall_rt_sigpending_record *rec);
uint8_t eri_try_unserialize_syscall_rt_sigpending_record (eri_file_t file,
			struct eri_syscall_rt_sigpending_record *rec);
void eri_unserialize_syscall_rt_sigpending_record (eri_file_t file,
			struct eri_syscall_rt_sigpending_record *rec);

struct eri_syscall_rt_sigtimedwait_record
{
  struct eri_syscall_res_in_record res;
  struct eri_siginfo info;
};

void eri_serialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			const struct eri_syscall_rt_sigtimedwait_record *rec);
uint8_t eri_try_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec);
void eri_unserialize_syscall_rt_sigtimedwait_record (eri_file_t file,
			struct eri_syscall_rt_sigtimedwait_record *rec);

struct eri_syscall_stat_record
{
  struct eri_syscall_res_in_record res;
  struct eri_stat stat;
};

void eri_serialize_syscall_stat_record (eri_file_t file,
			const struct eri_syscall_stat_record *rec);
uint8_t eri_try_unserialize_syscall_stat_record (eri_file_t file,
			struct eri_syscall_stat_record *rec);
void eri_unserialize_syscall_stat_record (eri_file_t file,
			struct eri_syscall_stat_record *rec);

struct eri_syscall_uname_record
{
  struct eri_syscall_res_in_record res;
  struct eri_utsname utsname;
};

void eri_serialize_syscall_uname_record (eri_file_t file,
			const struct eri_syscall_uname_record *rec);
uint8_t eri_try_unserialize_syscall_uname_record (eri_file_t file,
			struct eri_syscall_uname_record *rec);
void eri_unserialize_syscall_uname_record (eri_file_t file,
			struct eri_syscall_uname_record *rec);

struct eri_syscall_times_record
{
  struct eri_syscall_res_in_record res;
  struct eri_tms tms;
};

void eri_serialize_syscall_times_record (eri_file_t file,
			const struct eri_syscall_times_record *rec);
uint8_t eri_try_unserialize_syscall_times_record (eri_file_t file,
			struct eri_syscall_times_record *rec);
void eri_unserialize_syscall_times_record (eri_file_t file,
			struct eri_syscall_times_record *rec);

struct eri_syscall_gettimeofday_record
{
  struct eri_syscall_res_in_record res;
  struct eri_timeval time;
};

void eri_serialize_syscall_gettimeofday_record (eri_file_t file,
			const struct eri_syscall_gettimeofday_record *rec);
uint8_t eri_try_unserialize_syscall_gettimeofday_record (eri_file_t file,
			struct eri_syscall_gettimeofday_record *rec);
void eri_unserialize_syscall_gettimeofday_record (eri_file_t file,
			struct eri_syscall_gettimeofday_record *rec);

struct eri_syscall_clock_gettime_record
{
  struct eri_syscall_res_in_record res;
  struct eri_timespec time;
};

void eri_serialize_syscall_clock_gettime_record (eri_file_t file,
			const struct eri_syscall_clock_gettime_record *rec);
uint8_t eri_try_unserialize_syscall_clock_gettime_record (eri_file_t file,
			struct eri_syscall_clock_gettime_record *rec);
void eri_unserialize_syscall_clock_gettime_record (eri_file_t file,
			struct eri_syscall_clock_gettime_record *rec);

struct eri_syscall_getrlimit_record
{
  struct eri_syscall_res_in_record res;
  struct eri_rlimit rlimit;
};

void eri_serialize_syscall_getrlimit_record (eri_file_t file,
			const struct eri_syscall_getrlimit_record *rec);
uint8_t eri_try_unserialize_syscall_getrlimit_record (eri_file_t file,
			struct eri_syscall_getrlimit_record *rec);
void eri_unserialize_syscall_getrlimit_record (eri_file_t file,
			struct eri_syscall_getrlimit_record *rec);

struct eri_syscall_prlimit64_record
{
  uint64_t out;
  struct eri_syscall_res_in_record res;
  struct eri_rlimit rlimit;
};

void eri_serialize_syscall_prlimit64_record (eri_file_t file,
			const struct eri_syscall_prlimit64_record *rec);
uint8_t eri_try_unserialize_syscall_prlimit64_record (eri_file_t file,
			struct eri_syscall_prlimit64_record *rec);
void eri_unserialize_syscall_prlimit64_record (eri_file_t file,
			struct eri_syscall_prlimit64_record *rec);

struct eri_syscall_getrusage_record
{
  struct eri_syscall_res_in_record res;
  struct eri_rusage rusage;
};

void eri_serialize_syscall_getrusage_record (eri_file_t file,
			const struct eri_syscall_getrusage_record *rec);
uint8_t eri_try_unserialize_syscall_getrusage_record (eri_file_t file,
			struct eri_syscall_getrusage_record *rec);
void eri_unserialize_syscall_getrusage_record (eri_file_t file,
			struct eri_syscall_getrusage_record *rec);

struct eri_syscall_accept_record
{
  uint64_t out;
  struct eri_syscall_res_in_record res;

  uint32_t addrlen;
  struct eri_sockaddr_storage addr;
};

void eri_serialize_syscall_accept_record (eri_file_t file,
			const struct eri_syscall_accept_record *rec);
uint8_t eri_try_unserialize_syscall_accept_record (eri_file_t file,
			struct eri_syscall_accept_record *rec);
void eri_unserialize_syscall_accept_record (eri_file_t file,
			struct eri_syscall_accept_record *rec);

struct eri_syscall_getsockname_record
{
  struct eri_syscall_res_in_record res;

  uint32_t addrlen;
  struct eri_sockaddr_storage addr;
};

void eri_serialize_syscall_getsockname_record (eri_file_t file,
			const struct eri_syscall_getsockname_record *rec);
uint8_t eri_try_unserialize_syscall_getsockname_record (eri_file_t file,
			struct eri_syscall_getsockname_record *rec);
void eri_unserialize_syscall_getsockname_record (eri_file_t file,
			struct eri_syscall_getsockname_record *rec);

struct eri_syscall_futex_record
{
  struct eri_syscall_res_in_record res;
  struct eri_atomic_record atomic;
};

void eri_serialize_syscall_futex_record (eri_file_t file,
			const struct eri_syscall_futex_record *rec);
uint8_t eri_try_unserialize_syscall_futex_record (eri_file_t file,
			struct eri_syscall_futex_record *rec);
void eri_unserialize_syscall_futex_record (eri_file_t file,
			struct eri_syscall_futex_record *rec);

struct eri_syscall_futex_requeue_record
{
  struct eri_syscall_res_in_record res;
  uint8_t cmp;
  struct eri_atomic_record atomic;
};

void eri_serialize_syscall_futex_requeue_record (eri_file_t file,
			const struct eri_syscall_futex_requeue_record *rec);
uint8_t eri_try_unserialize_syscall_futex_requeue_record (eri_file_t file,
			struct eri_syscall_futex_requeue_record *rec);
void eri_unserialize_syscall_futex_requeue_record (eri_file_t file,
			struct eri_syscall_futex_requeue_record *rec);

#endif
