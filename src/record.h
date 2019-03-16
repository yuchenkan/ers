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

  uint64_t atomic_table_size;
};

struct eri_packed eri_init_map_data_record
{
  uint64_t start, end;
  uint8_t data[0];
};

struct eri_packed eri_init_map_record
{
  uint64_t start, end;
  uint8_t prot;
  uint8_t grows_down;

  uint8_t data_count;
  struct eri_init_map_data_record data[0];
};

enum
{
  ERI_SYSCALL_CLONE_MAGIC,
  ERI_SYNC_ASYNC_MAGIC,
  ERI_ATOMIC_MAGIC
};

struct eri_packed eri_syscall_clone_record
{
  uint8_t magic;
  uint64_t result;
  uint64_t id;
};

struct eri_packed eri_sync_async_record
{
  uint8_t magic;
  uint64_t steps;
};

struct eri_packed eri_atomic_record
{
  uint8_t magic;
  uint8_t updated;
  uint64_t ver[2];
  uint64_t val;
};

enum
{
  ERI_INIT_RECORD,
  ERI_INIT_MAP_RECORD,
  ERI_SYNC_RECORD,
  ERI_ASYNC_RECORD
};

#define _ERI_DEFINE_MARKED_RECORD(t) \
struct eri_packed ERI_PASTE2 (eri_marked_, t, _record)			\
{									\
  uint8_t mark;								\
  struct ERI_PASTE2 (eri_, t, _record) rec;				\
}

_ERI_DEFINE_MARKED_RECORD (init);
_ERI_DEFINE_MARKED_RECORD (init_map);

struct eri_packed eri_marked_signal_record
{
  uint8_t mark;
  struct eri_siginfo info;
};

_ERI_DEFINE_MARKED_RECORD (syscall_clone);
_ERI_DEFINE_MARKED_RECORD (sync_async);
_ERI_DEFINE_MARKED_RECORD (atomic);

#endif
