#include <stddef.h>
#include <stdint.h>

#include "syscall.h"

#define assert(exp) do if (!(exp)) *((char *) NULL) = 0; while (0)

#ifndef alloca
#define alloca __builtin_alloca
#endif

__attribute__ ((visibility ("hidden")))
void it_printf(const char *fmt, ...);

#define read(fd, buf, size) \
  assert(SYSCALL(read, fd, buf, size) == size)
