#ifndef ERI_COMMON_H
#define ERI_COMMON_H

#include <stddef.h>

#include "lib/util.h"

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

void eri_dump_maps (int fd);
void eri_process_maps (void (*proc) (const struct eri_map_entry *, void *),
		       void *data);

#define ERI_OPEN_WITHID 1
#define ERI_OPEN_REPLAY 2
int eri_open_path (const char *path, const char *name, int flags, unsigned long id);

#define ERI_MARK_NONE 0

#define ERI_MARK_INIT_MAP 1
#define ERI_MARK_INIT_STACK 2

struct eri_context
{
  char env[14 * 8 + 24 + 4];
  unsigned long unmap_start;
  size_t unmap_size;
};

void eri_save_mark (int fd, char mk);
char eri_load_mark (int fd);

/* flags: growsdown | zero | exec | write | read */
void eri_save_init_map (int init, unsigned long start, unsigned long end, char flags);
void eri_save_init_map_data (int init, const char *buf, size_t size);
void eri_load_init_map (int init, unsigned long *start, unsigned long *end, char *flags);
void eri_load_init_map_data (int init, char *buf, size_t size);
void eri_skip_init_map_data (int init, size_t size);

void eri_save_init_context (int init, const struct eri_context *ctx);
void eri_load_init_context (int init, struct eri_context *ctx);

#define ERI_PROT_READ	0x1
#define ERI_PROT_WRITE	0x2
#define ERI_PROT_EXEC	0x4
#define ERI_MAP_PRIVATE		0x2
#define ERI_MAP_FIXED		0x10
#define ERI_MAP_ANONYMOUS	0x20
#define ERI_MAP_GROWSDOWN	0x100

#endif
