#ifndef ERI_REPLAY_ANALYZER_H
#define ERI_REPLAY_ANALYZER_H

#include <stdint.h>

#include <lib/compiler.h>

struct eri_range;
struct eri_mtpool;
struct eri_entry;
struct eri_registers;
struct eri_siginfo;
struct eri_ucontext;

#ifndef eri_analyzer_type
# define eri_analyzer_type		void
#endif

#ifndef eri_analyzer_group_type
# define eri_analyzer_group_type	void
#endif

struct eri_analyzer_group__create_args
{
  struct eri_mtpool *pool;
  struct eri_range *map_range;

  const char *log;

  uint64_t page_size;
  uint64_t file_buf_size;
  uint32_t max_inst_count;
  uint64_t max_race_enter;

  int32_t *pid;
  void *error; /* noreturn void (*) (void *) */
};

eri_analyzer_group_type *eri_analyzer_group__create (
			struct eri_analyzer_group__create_args *args);
void eri_analyzer_group__destroy (eri_analyzer_group_type *group);

struct eri_analyzer__create_args
{
  eri_analyzer_group_type *group;
  eri_analyzer_type *parent;

  uint64_t id;
  struct eri_entry *entry;

  int32_t *tid;

  void *args;
};

eri_analyzer_type *eri_analyzer__create (
			struct eri_analyzer__create_args *args);
void eri_analyzer__destroy (eri_analyzer_type *analyzer);

eri_noreturn void eri_analyzer__enter (eri_analyzer_type *analyzer,
				       struct eri_registers *regs);

struct eri_analyzer__sig_handler_args
{
  eri_analyzer_type *analyzer;
  struct eri_siginfo *info;
  struct eri_ucontext *ctx;

  uint8_t (*handler) (struct eri_siginfo *, struct eri_ucontext *, void *);
  void *args;
};

void eri_analyzer__sig_handler (
			struct eri_analyzer__sig_handler_args *args);

void eri_analyzer__update_mm_prot (eri_analyzer_type *analyzer,
				   struct eri_range range, int32_t prot);
void eri_analyzer__update_access (eri_analyzer_type *analyzer,
				  struct eri_access *acc);

void eri_analyzer__race_before (eri_analyzer_type *analyzer,
				uint64_t key, uint64_t ver);
void eri_analyzer__race_after (eri_analyzer_type *analyzer,
			       uint64_t key, uint64_t ver);

#endif
