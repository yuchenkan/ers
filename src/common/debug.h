#ifndef ERI_COMMON_DEBUG_H
#define ERI_COMMON_DEBUG_H

#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/printf.h>

#define _eri_log(level, fmt, ...) \
  eri_printf ("[" ERI_STR (level) " %s:%u(%s)%lu]\t" fmt,		\
	      __FILE__, __LINE__, __FUNCTION__,				\
	      eri_assert_syscall (gettid), ##__VA_ARGS__)

static eri_unused uint8_t eri_enable_debug = 0;
uint8_t eri_global_enable_debug;
#define eri_debug(fmt, ...) \
  do {									\
    if (eri_enable_debug || eri_global_enable_debug)			\
      _eri_log (DEBUG, fmt, ##__VA_ARGS__);				\
  } while (0)

#define eri_info(fmt, ...)	_eri_log (INFO, fmt, ##__VA_ARGS__)

#define eri_debug_stop() \
  eri_assert_syscall (kill, eri_assert_syscall (getpid), ERI_SIGSTOP)

#endif
