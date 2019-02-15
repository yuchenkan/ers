#ifndef ERI_COMMON_H
#define ERI_COMMON_H

#include <stdint.h>

struct eri_common_args
{
  const char *config;
  uint64_t page_size;

  const char *path;
  uint64_t buf_size;
  uint64_t stack_size;
  uint64_t file_buf_size;

  uint64_t buf;
};

#include <lib/printf.h>

#define eri_debug(fmt, ...) \
  eri_assert_gprintf ("[%s:%u]\t%s\t" fmt,				\
		      __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define eri_debug_stop() \
  eri_assert_syscall (kill, eri_assert_syscall (getpid), ERI_SIGSTOP)

#endif
