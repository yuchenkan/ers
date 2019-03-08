#ifndef ERI_COMMON_H
#define ERI_COMMON_H

#include <stdint.h>

struct eri_common_args
{
  const char *config;
  const char *path;

  uint64_t page_size;

  uint64_t stack_size;
  uint64_t file_buf_size;
};

#include <compiler.h>
#include <lib/util.h>
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
