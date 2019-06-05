#ifndef ERI_ANALYSIS_TRANSLATE_H
#define ERI_ANALYSIS_TRANSLATE_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/rbtree.h>
#include <lib/syscall-common.h>
#include <lib/printf.h>

struct eri_mtpool;

struct eri_trans;
struct eri_trans_active;

void *eri_trans_active_get_data (struct eri_trans_active *act);
void *eri_trans_active_get_trans_data (struct eri_trans_active *act);

void eri_trans_init_translate (void);

struct eri_translate_args
{
  struct eri_mtpool *pool;
  eri_file_t log;

  struct eri_range *map_range;
  uint64_t page_size;
  uint64_t max_inst_count;

  uint64_t rip;
  uint8_t tf;

  void *data;
  uint8_t (*copy) (void *, const void *, uint64_t,
		   struct eri_siginfo *, void *);
  void *copy_args;

  void *analysis;
};

struct eri_trans *eri_translate (struct eri_translate_args *args);
void eri_trans_destroy (struct eri_mtpool *pool, struct eri_trans *tr);

struct eri_trans_create_active_args
{
  struct eri_mtpool *pool;

  void *data;
  struct eri_trans *trans;
  uint8_t *stack;
  struct eri_registers *regs;
};

struct eri_trans_active *eri_trans_create_active (
				struct eri_trans_create_active_args *args);
void eri_trans_destroy_active (struct eri_mtpool *pool,
			       struct eri_trans_active *act);

eri_noreturn void eri_trans_enter_active (struct eri_trans_active *act);
uint8_t eri_trans_leave_active (struct eri_trans_active *act,
		struct eri_registers *regs, struct eri_siginfo *info);
uint8_t eri_trans_trace_regs (eri_file_t log, struct eri_trans_active *act,
		struct eri_mcontext *mctx, struct eri_registers *regs);

#endif
