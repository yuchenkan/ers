#ifndef ERI_COMMON_DEBUG_H
#define ERI_COMMON_DEBUG_H

#include <stdarg.h>

#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/printf.h>
#include <lib/lock.h>

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
      va_arg (arg, const char *);
      va_arg (arg, uint32_t);
      va_arg (arg, const char *);
      if (flags & ERI_LOG_TEE)
	{
	  va_list tee;
	  va_copy (tee, arg);
	  _eri_cvflog (1, ERI_STDOUT, fmt, arg);
	  va_end (tee);
	}
      _eri_cvflog (enabled, file, fmt, arg);
    }
  va_end (arg);
}

#define eri_do_log(enabled, file, flags, level, fmt, ...) \
  _eri_log (enabled, file, flags,					\
	    fmt, "[" ERI_STR (level) " %s:%u(%s)]\t" fmt,		\
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
#define eri_log8(log, fmt, ...)	eri_logn (8, log, fmt, ##__VA_ARGS__)

#define eri_rlogn(n, log, fmt, ...) \
  eri_rlog (eri_global_enable_debug >= n ? log : 0, fmt, ##__VA_ARGS__)

#define eri_rlog2(log, fmt, ...) \
  eri_rlogn (2, log, fmt, ##__VA_ARGS__)
#define eri_rlog3(log, fmt, ...) \
  eri_rlogn (3, log, fmt, ##__VA_ARGS__)

static eri_unused void
eri_open_log (struct eri_mtpool *pool, struct eri_buf_file *file,
	const char *log, const char *name, uint64_t id, uint64_t buf_size)
{
  eri_init_lock (&file->lock, 0);
  if (! log) { file->file = 0; return; }

  eri_malloc_open_path (pool, file, log, name, id, buf_size);
}

static eri_unused void
eri_close_log (struct eri_mtpool *pool, struct eri_buf_file *file)
{
  if (file->file) eri_free_close (pool, file);
}

#define _eri_llog(fn, log, fmt, ...) \
  do {									\
    struct eri_buf_file *_blog = log;					\
    if (_blog) eri_assert_lock (&_blog->lock);				\
    fn (_blog ? _blog->file : 0, fmt, ##__VA_ARGS__);			\
    if (_blog) eri_assert_unlock (&_blog->lock);			\
  } while (0)

#define eri_llog(log, fmt, ...) \
  _eri_llog (eri_log, log, fmt, ##__VA_ARGS__)
#define eri_llog_info(log, fmt, ...) \
  _eri_llog (eri_log_info, log, fmt, ##__VA_ARGS__)

#define eri_debug_stop() \
  eri_assert_syscall (kill, eri_assert_syscall (getpid), ERI_SIGSTOP)

#define eri_log_assert(expr, log) \
  eri_log_info (log, "assert failed: " expr)
#define eri_lassert(log, exp) \
  eri_xassert (exp, eri_log_assert, log)

#define eri_lassert_syscall(log, name, ...) \
  eri_xassert_syscall (eri_log_assert, (log), name, ##__VA_ARGS__)

#endif
