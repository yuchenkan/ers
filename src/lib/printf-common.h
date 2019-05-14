#ifndef ERI_LIB_PRINTF_COMMON_H
#define ERI_LIB_PRINTF_COMMON_H

#include <stdarg.h>
#include <stdint.h>

#include <lib/util.h>

struct eri_buf;
struct eri_lock;

typedef uint64_t eri_file_t;
#define eri_file_buf_t			uint8_t __attribute__ ((aligned (16)))

#define _ERI_FILE_RAW			1

#define eri_raw_file_from_fd(fd) \
  ((eri_file_t) ((fd) << 4 | _ERI_FILE_RAW))

#define ERI_STDIN			eri_raw_file_from_fd (0)
#define ERI_STDOUT			eri_raw_file_from_fd (1)
#define ERI_STDERR			eri_raw_file_from_fd (2)

#endif
