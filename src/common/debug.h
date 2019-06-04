#ifndef ERI_COMMON_DEBUG_H
#define ERI_COMMON_DEBUG_H

#include <stdarg.h>

#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/printf.h>

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

#define _eri_stream(fn, level, fmt, ...) \
  fn (_eri_fmt (level, fmt), __FILE__, __LINE__, __FUNCTION__,		\
      eri_assert_syscall (gettid), ##__VA_ARGS__)

#define eri_debug(fmt, ...) \
  _eri_stream (_eri_debug, DEBUG, fmt, ##__VA_ARGS__)

#define eri_info(fmt, ...) \
  _eri_stream (eri_printf, INFO, fmt, ##__VA_ARGS__)

#define ERI_LOG_PCTX	1
#define ERI_LOG_TEE	2

static eri_unused void
_eri_log (uint8_t enabled, eri_file_t f, uint32_t flags,
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
	  _eri_cvflog (enabled, ERI_STDOUT, fmt_ctx, tee);
	  va_end (tee);
	}
      _eri_cvflog (enabled, f, fmt_ctx, arg);
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
	  _eri_cvflog (enabled, ERI_STDOUT, fmt, arg);
	  va_end (tee);
	}
      _eri_cvflog (enabled, f, fmt, arg);
    }
  va_end (arg);
}

#define eri_do_log(enabled, file, flags, level, fmt, ...) \
  _eri_log (enabled, file, flags,					\
	    fmt, "[" ERI_STR (level) " %s:%u(%s)]\t" fmt,		\
	    __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define eri_log_tee()	(eri_global_enable_debug >= 9)

#define eri_log(log, fmt, ...) \
  do {									\
    typeof (log) _log = log;						\
    uint32_t _f = ERI_LOG_PCTX | (eri_log_tee () ? ERI_LOG_TEE : 0);	\
    eri_do_log (!! _log, log, _f, DEBUG, fmt, ##__VA_ARGS__);	\
  } while (0)

#define eri_log_raw(log, fmt, ...) \
  do {									\
    typeof (log) _log = log;						\
    uint32_t _f = eri_log_tee () ? ERI_LOG_TEE : 0;			\
    eri_do_log (!! _log, log, _f, DEBUG, fmt, ##__VA_ARGS__);		\
  } while (0)

#define eri_log_info(log, fmt, ...) \
  eri_do_log (1, log, ERI_LOG_PCTX | ERI_LOG_TEE, INFO, fmt, ##__VA_ARGS__)

#define eri_debug_stop() \
  eri_assert_syscall (kill, eri_assert_syscall (getpid), ERI_SIGSTOP)

#define eri_lassert(exp)	eri_xassert (exp, eri_info)

#endif
