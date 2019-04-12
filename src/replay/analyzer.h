#ifndef ERI_REPLAY_ANALYZER_H
#define ERI_REPLAY_ANALYZER_H

#include <stdint.h>

#include <lib/compiler.h>

struct eri_range;
struct eri_mtpool;
struct eri_registers *regs;

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
};

eri_analyzer_group_type *eri_analyzer_group__create (
			struct eri_analyzer_group__create_args *args);
void eri_analyzer_group__destroy (eri_analyzer_group_type *group);

struct eri_analyzer__create_args
{
  eri_analyzer_group_type *group;
  uint8_t *stack;
};

eri_analyzer_type *eri_analyzer__create (
			struct eri_analyzer__create_args *args);
void eri_analyzer__destroy (eri_analyzer_type *analyzer);

eri_noreturn void eri_analyzer__enter (eri_analyzer_type *analyzer,
				       struct eri_registers *regs);

#endif
