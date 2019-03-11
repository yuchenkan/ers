#ifndef ERI_RECORD_H
#define ERI_RECORD_H

#include <stdint.h>

#include <compiler.h>

#include <lib/syscall-common.h>

struct eri_packed eri_init_record
{
  uint64_t ver;

  uint64_t rdx;
  uint64_t rsp;
  uint64_t rip;

  struct eri_sigset sig_mask;

  uint64_t start;
  uint64_t end;
};

struct eri_packed eri_init_map_data_record
{
  uint64_t start, end;
  uint8_t data[0];
};

struct eri_packed eri_init_map_record
{
  uint64_t start, end;
  uint8_t perms;

  uint8_t data_count;
  struct eri_init_map_data_record data[0];
};

#define ERI_INIT_RECORD		0
#define ERI_INIT_MAP_RECORD	1
#define ERI_SYNC_RECORD		2
#define ERI_ASYNC_RECORD	3

struct eri_packed eri_marked_init_record
{
  uint8_t mark;
  struct eri_init_record rec;
};

struct eri_packed eri_marked_init_map_record
{
  uint8_t mark;
  struct eri_init_map_record rec;
};

#endif
