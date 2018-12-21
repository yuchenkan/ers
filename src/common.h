#ifndef ERI_COMMON_H
#define ERI_COMMON_H

#include <stdint.h>

#include "lib/malloc.h"

struct eri_common
{
  const char *config;
  uint64_t page_size;

  const char *path;
  uint64_t buf_size;
  uint64_t stack_size;
  uint64_t file_buf_size;

  uint64_t buf;
};

struct eri_daemon
{
  int32_t pid;
};

struct eri_daemon *eri_daemon_start (uint8_t mt, struct eri_mtpool *pool,
				     uint64_t stack_size);
void eri_daemon_invoke (struct eri_daemon *daemon,
			void (*fn) (void *), void *data);
void eri_daemon_stop (uint8_t mt, struct eri_daemon *daemon);

#endif
