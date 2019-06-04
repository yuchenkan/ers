#ifndef ERI_COMMON_DEBUG_H
#define ERI_COMMON_DEBUG_H

#include <stdarg.h>

#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/printf.h>

static eri_unused void
_eri_cvfdebug (uint8_t enabled, eri_file_t f, const char *fmt, va_list arg)
{
  if (! enabled) return;
  eri_assert_vfprintf (f, fmt, arg);
}

static eri_unused void
_eri_cdebug (uint8_t enabled, const char *fmt, ...)
{
  va_list arg;
  va_start (arg, fmt);
  _eri_cvfdebug (enabled, ERI_STDOUT, fmt, arg);
  va_end (arg);
}

static eri_unused uint8_t eri_enable_debug = 0;
uint8_t eri_global_enable_debug;
#define eri_enabled_debug() \
  (eri_enable_debug || eri_global_enable_debug)

#define _eri_debug(fmt, ...) \
  _eri_cdebug (eri_enabled_debug (), fmt, ##__VA_ARGS__)

#define _eri_fmt(level, fmt)	"[" ERI_STR (level) " %s:%u(%s)%lu]\t" fmt

#define _eri_log(fn, level, fmt, ...) \
  fn (_eri_fmt (level, fmt), __FILE__, __LINE__, __FUNCTION__,		\
      eri_assert_syscall (gettid), ##__VA_ARGS__)

#define eri_debug(fmt, ...) \
  _eri_log (_eri_debug, DEBUG, fmt, ##__VA_ARGS__)

#define eri_info(fmt, ...) \
  _eri_log (eri_printf, INFO, fmt, ##__VA_ARGS__)

#define ERI_DEBUG_PCTX	1
#define ERI_DEBUG_TEE	2

static eri_unused void
_eri_fdebug (uint8_t enabled, eri_file_t f, uint32_t flags,
	     const char *fmt, const char *fmt_ctx, ...)
{
  va_list arg;
  va_start (arg, fmt_ctx);
  if (flags & ERI_DEBUG_PCTX)
    {
      if (flags & ERI_DEBUG_TEE)
	{
	  va_list tee;
	  va_copy (tee, arg);
	  _eri_cvfdebug (enabled, ERI_STDOUT, fmt_ctx, tee);
	  va_end (tee);
	}
      _eri_cvfdebug (enabled, f, fmt_ctx, arg);
    }
  else
    {
      va_arg (arg, const char *);
      va_arg (arg, uint32_t);
      va_arg (arg, const char *);
      if (flags & ERI_DEBUG_TEE)
	{
	  va_list tee;
	  va_copy (tee, arg);
	  _eri_cvfdebug (enabled, ERI_STDOUT, fmt, arg);
	  va_end (tee);
	}
      _eri_cvfdebug (enabled, f, fmt, arg);
    }
  va_end (arg);
}

#define eri_fdebug(enabled, file, pctx, fmt, ...) \
  _eri_fdebug (enabled, file, pctx, fmt, "[DEBUG %s:%u(%s)]\t" fmt,	\
	       __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define eri_debug_stop() \
  eri_assert_syscall (kill, eri_assert_syscall (getpid), ERI_SIGSTOP)

#define eri_lassert(exp)	eri_xassert (exp, eri_info)

#endif
