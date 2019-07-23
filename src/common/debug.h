#ifndef ERI_COMMON_DEBUG_H
#define ERI_COMMON_DEBUG_H

#include <stdarg.h>

#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/printf.h>
#include <lib/lock.h>
#include <lib/atomic.h>

#include <common/common.h>

struct eri_mtpool;

static eri_unused void
_eri_cvflog (uint8_t enabled, eri_file_t f, const char *fmt, va_list arg)
{
  if (! enabled || ! f) return;
  eri_assert_vfprintf (f, fmt, arg);
}

static eri_unused void
_eri_clog (uint8_t enabled, const char *fmt, ...)
{
  va_list arg;
  va_start (arg, fmt);
  _eri_cvflog (enabled, ERI_STDOUT, fmt, arg);
  va_end (arg);
}

static eri_unused uint8_t eri_enable_debug = 0;
uint8_t eri_global_enable_debug;
#define eri_enabled_debug() \
  (eri_enable_debug || eri_global_enable_debug)

#define _eri_debug(fmt, ...) \
  _eri_clog (eri_enabled_debug (), fmt, ##__VA_ARGS__)

#define _eri_fmt(level, fmt)	"[" ERI_STR (level) " %s:%u(%s)%lu]\t" fmt

#define _eri_unify_file(file) \
  ({ const char *_file = file;						\
     _file[0] == '.' && _file[1] == '/' ? _file + 2 : _file; })

#define _eri_stream(fn, level, fmt, ...) \
  fn (_eri_fmt (level, fmt), _eri_unify_file (__FILE__), __LINE__,	\
      __FUNCTION__, eri_assert_syscall (gettid), ##__VA_ARGS__)

#define eri_debug(fmt, ...) \
  _eri_stream (_eri_debug, DEBUG, fmt, ##__VA_ARGS__)

#define eri_info(fmt, ...) \
  _eri_stream (eri_printf, INFO, fmt, ##__VA_ARGS__)

#define ERI_LOG_PCTX	1
#define ERI_LOG_TEE	2

static eri_unused void
_eri_log (uint8_t enabled, eri_file_t file, uint32_t flags,
	  const char *fmt, const char *fmt_ctx, ...)
{
  va_list arg;
  va_start (arg, fmt_ctx);
  if (flags & ERI_LOG_PCTX)
    {
      if (flags & ERI_LOG_TEE)
	{
	  va_list tee;
	  va_copy (tee, arg);
	  _eri_cvflog (1, ERI_STDOUT, fmt_ctx, tee);
	  va_end (tee);
	}
      _eri_cvflog (enabled, file, fmt_ctx, arg);
    }
  else
    {
      va_arg (arg, uint64_t);
      va_arg (arg, const char *);
      va_arg (arg, uint32_t);
      va_arg (arg, const char *);
      if (flags & ERI_LOG_TEE)
	{
	  va_list tee;
	  va_copy (tee, arg);
	  _eri_cvflog (1, ERI_STDOUT, fmt, tee);
	  va_end (tee);
	}
      _eri_cvflog (enabled, file, fmt, arg);
    }
  va_end (arg);
}

uint64_t _eri_do_log_seq;
uint8_t eri_log_no_seq;
#define eri_do_log(enabled, file, flags, level, fmt, ...) \
  _eri_log (enabled, file, flags,					\
	    fmt, "[" ERI_STR (level) " %lu %s:%u(%s)]\t" fmt,		\
	    ! eri_log_no_seq						\
		? eri_atomic_fetch_inc (&_eri_do_log_seq, 0) : 0,	\
	    _eri_unify_file (__FILE__), __LINE__, __FUNCTION__,		\
	    ##__VA_ARGS__)

#define eri_log_tee()	(eri_global_enable_debug >= 9)

#define eri_log(file, fmt, ...) \
  do {									\
    eri_file_t _file = file;						\
    uint32_t _f = ERI_LOG_PCTX | (eri_log_tee () ? ERI_LOG_TEE : 0);	\
    eri_do_log (!! _file, _file, _f, DEBUG, fmt, ##__VA_ARGS__);	\
  } while (0)

#define eri_rlog(file, fmt, ...) \
  do {									\
    eri_file_t _file = file;						\
    uint32_t _f = eri_log_tee () ? ERI_LOG_TEE : 0;			\
    eri_do_log (!! _file, _file, _f, DEBUG, fmt, ##__VA_ARGS__);	\
  } while (0)

#define eri_log_info(log, fmt, ...) \
  eri_do_log (1, log, ERI_LOG_PCTX | ERI_LOG_TEE, INFO, fmt, ##__VA_ARGS__)

#define eri_logn(n, log, fmt, ...) \
  do {									\
    eri_file_t _log = log;						\
    eri_log (eri_global_enable_debug >= (n) ? _log : 0, fmt,		\
	     ##__VA_ARGS__);						\
  } while (0)

#define eri_log2(log, fmt, ...)	eri_logn (2, log, fmt, ##__VA_ARGS__)
#define eri_log3(log, fmt, ...)	eri_logn (3, log, fmt, ##__VA_ARGS__)
#define eri_log4(log, fmt, ...)	eri_logn (4, log, fmt, ##__VA_ARGS__)
#define eri_log5(log, fmt, ...)	eri_logn (5, log, fmt, ##__VA_ARGS__)
#define eri_log6(log, fmt, ...)	eri_logn (6, log, fmt, ##__VA_ARGS__)
#define eri_log7(log, fmt, ...)	eri_logn (7, log, fmt, ##__VA_ARGS__)
#define eri_log8(log, fmt, ...)	eri_logn (8, log, fmt, ##__VA_ARGS__)
#define eri_log9(log, fmt, ...)	eri_logn (9, log, fmt, ##__VA_ARGS__)

#define eri_rlogn(n, log, fmt, ...) \
  eri_rlog (eri_global_enable_debug >= (n) ? log : 0, fmt, ##__VA_ARGS__)

#define eri_rlog2(log, fmt, ...) \
  eri_rlogn (2, log, fmt, ##__VA_ARGS__)
#define eri_rlog3(log, fmt, ...) \
  eri_rlogn (3, log, fmt, ##__VA_ARGS__)
#define eri_rlog4(log, fmt, ...) \
  eri_rlogn (4, log, fmt, ##__VA_ARGS__)
#define eri_rlog5(log, fmt, ...) \
  eri_rlogn (5, log, fmt, ##__VA_ARGS__)
#define eri_rlog6(log, fmt, ...) \
  eri_rlogn (6, log, fmt, ##__VA_ARGS__)
#define eri_rlog7(log, fmt, ...) \
  eri_rlogn (7, log, fmt, ##__VA_ARGS__)
#define eri_rlog8(log, fmt, ...) \
  eri_rlogn (8, log, fmt, ##__VA_ARGS__)
#define eri_rlog9(log, fmt, ...) \
  eri_rlogn (9, log, fmt, ##__VA_ARGS__)

static eri_unused void
eri_open_log (struct eri_mtpool *pool, struct eri_buf_file *file,
	const char *log, const char *name, uint64_t id, uint64_t buf_size)
{
  if (! log) { file->file = 0; return; }

  eri_malloc_open_path (pool, file, log, name, id, buf_size);
}

static eri_unused void
eri_close_log (struct eri_mtpool *pool, struct eri_buf_file *file)
{
  if (file->file) eri_free_close (pool, file);
}

#define eri_debug_stop() \
  eri_assert_syscall (kill, eri_assert_syscall (getpid), ERI_SIGSTOP)

#define eri_log_assert(expr, log) \
  eri_log_info (log, "assert failed: %s", expr)
#define eri_lassert(log, exp) \
  eri_xassert (exp, eri_log_assert, log)

#define eri_lassert_syscall(log, name, ...) \
  ({ uint64_t _r = eri_syscall (name, ##__VA_ARGS__);			\
     if (eri_syscall_is_error (_r))					\
       eri_log (log, "syscall failed: %s %lx\n", ERI_STR (name), _r); })

#define eri_dump_maps() \
  do {									\
    uint8_t _buf[1024];							\
    eri_file_t _file = eri_assert_fopen ("/proc/self/maps", 1, 0, 0);	\
    uint64_t _len;							\
    do									\
      {									\
        eri_assert_fread (_file, _buf, sizeof _buf, &_len);		\
        eri_assert_fwrite (ERI_STDERR, _buf, _len, 0);			\
      }									\
    while (_len == sizeof _buf);					\
  } while (0)

#endif
