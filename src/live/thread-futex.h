#ifndef ERI_LIVE_FUTEX_H
#define ERI_LIVE_FUTEX_H

#include <stdint.h>

#include <lib/printf.h>

struct eri_mtpool;
struct eri_timespec;

struct eri_syscall_futex_record;
struct eri_syscall_futex_requeue_record;
struct eri_syscall_futex_lock_pi_record;
struct eri_syscall_futex_unclock_pi_record;

struct eri_live_thread_futex_group;
struct eri_live_thread_futex;

struct eri_live_signal_thread;

struct eri_live_thread_futex_group *eri_live_thread_futex__create_group (
				struct eri_mtpool *pool, uint64_t table_size,
				struct eri_live_atomic *atomic);
void eri_live_thread_futex__destroy_group (
				struct eri_live_thread_futex_group *group);

struct eri_live_thread_futex *eri_live_thread_futex__create (
				struct eri_live_thread_futex_group *group,
				struct eri_entry *entry, eri_file_t log);
void eri_live_thread_futex__set_tid (struct eri_live_thread_futex *th_ftx,
				     int32_t tid, int32_t user_tid);
void eri_live_thread_futex__destroy (struct eri_live_thread_futex *th_ftx);

struct eri_live_futex * eri_live_thread_futex__create_futex_pi (
					struct eri_live_thread_futex *th_ftx,
					uint64_t user_addr);

struct eri_live_thread_futex__wait_args
{
  uint64_t user_addr;
  int32_t cmp_arg;
  uint32_t mask;
  uint8_t abs_time;
  uint8_t clock_real_time;
  struct eri_timespec *timeout;

  struct eri_syscall_futex_record *rec;
};

void eri_live_thread_futex__wait (
			struct eri_live_thread_futex *th_ftx,
			struct eri_live_thread_futex__wait_args *args);
uint64_t eri_live_thread_futex__wake (
			struct eri_live_thread_futex *th_ftx,
			uint64_t user_addr, int32_t max, uint32_t mask);

struct eri_live_thread_futex__requeue_args
{
  uint64_t user_addr[2];
  int32_t wake_num;
  int32_t requeue_num;
  uint8_t cmp;
  int32_t cmp_arg;

  struct eri_syscall_futex_requeue_record *rec;
};

void eri_live_thread_futex__requeue (
			struct eri_live_thread_futex *th_ftx,
			struct eri_live_thread_futex__requeue_args *args);

struct eri_live_thread_futex__wake_op_args
{
  uint64_t user_addr[2];
  int32_t wake_num[2];

  uint8_t op;
  uint8_t cmp;
  int32_t op_arg;
  int32_t cmp_arg;

  struct eri_syscall_futex_record *rec;
};

void eri_live_thread_futex__wake_op (
			struct eri_live_thread_futex *th_ftx,
			struct eri_live_thread_futex__wake_op_args *args);

#endif
