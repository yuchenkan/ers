#ifndef ERI_COMMON_COMMON_H
#define ERI_COMMON_COMMON_H

#include <stdint.h>

#include <lib/util.h>
#include <lib/printf.h>

struct eri_mtpool;

#define eri_build_path_len(path, name, id) \
  (eri_strlen (path) + 1 + eri_strlen (name) + eri_itoa_size (id))

void eri_build_path (const char *path, const char *name,
		     uint64_t id, char *buf);
eri_file_t eri_open_path (const char *path, const char *name,
			  uint64_t id, void *buf, uint64_t buf_size);

struct eri_buf_file
{
  eri_file_t file;
  void *buf;
};

void eri_malloc_open_path (struct eri_mtpool *pool,
	struct eri_buf_file *file, const char *path, const char *name,
	uint64_t id, uint64_t buf_size);
void eri_free_close (struct eri_mtpool *pool, struct eri_buf_file *file);

void eri_mkdir (const char *path);

#endif
