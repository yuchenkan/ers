#ifndef ERI_COMMON_COMMON_H
#define ERI_COMMON_COMMON_H

#include <stdint.h>

#include <lib/util.h>

#define eri_build_path_len(path, name, id) \
  (eri_strlen (path) + 1 + eri_strlen (name) + eri_itoa_size (id))

void eri_build_path (const char *path, const char *name,
		     uint64_t id, char *buf);

void eri_mkdir (const char *path);

#endif
