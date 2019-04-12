#ifndef ERI_REPLAY_ANALYZER_H
#define ERI_REPLAY_ANALYZER_H

#include <stdint.h>

#include <lib/compiler.h>

struct eri_registers *regs;

#ifndef eri_analyzer_group_type
# define eri_analyzer_group_type	void
#endif

#ifndef eri_analyzer_type
# define eri_analyzer_type		void
#endif

eri_analyzer_group_type *eri_analyzer_group__create (struct eri_mtpool *pool);
void eri_analyzer_group__destroy (eri_analyzer_group_type *group);

eri_analyzer_type *eri_analyzer__create (eri_analyzer_group_type *group);
void eri_analyzer__destroy (eri_analyzer_type *analyzer);

eri_noreturn void eri_analyzer__enter (eri_analyzer_type *analyzer,
				       struct eri_registers *regs);

#endif
