#ifndef ERI_COMMON_H
#define ERI_COMMON_H

#include <stddef.h>

#include "lib/util.h"
#include "lib/printf.h"

static inline char
eri_itoc (char i)
{
  eri_assert (i >= 0 && i <= 15);
  return i < 10 ? '0' + i : 'a' + i - 10;
}

static inline char
eri_ctoi (char c)
{
  eri_assert ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
  return c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
}

struct eri_map_entry
{
  unsigned long start, end;
  char perms;
  const char *path;
};

void eri_dump_maps (eri_file_t file);
void eri_process_maps (void (*proc) (const struct eri_map_entry *, void *),
		       void *data);

#define ERI_OPEN_WITHID 1
#define ERI_OPEN_READ 2
eri_file_t eri_open_path (const char *path, const char *name, int flags,
			  unsigned long id, char *buf, size_t buf_size);

#define ERI_MARK_NONE 0

#define ERI_MARK_INIT_MAP 1
#define ERI_MARK_INIT_STACK 2

struct eri_context
{
  char env[14 * 8 + 24 + 4];
  unsigned long unmap_start;
  size_t unmap_size;
};

void eri_save_mark (eri_file_t file, char mk);
char eri_load_mark (eri_file_t file);

/* flags: growsdown | zero | exec | write | read */
void eri_save_init_map (eri_file_t init, unsigned long start, unsigned long end, char flags);
void eri_save_init_map_data (eri_file_t init, const char *buf, size_t size);
void eri_load_init_map (eri_file_t init, unsigned long *start, unsigned long *end, char *flags);
void eri_load_init_map_data (eri_file_t init, char *buf, size_t size);
void eri_skip_init_map_data (eri_file_t init, size_t size);

void eri_save_init_context (eri_file_t init, const struct eri_context *ctx);
void eri_load_init_context (eri_file_t init, struct eri_context *ctx);

#endif
