#include "rtld.h"
#include "lib/printf.h"

void
tst_rtld (struct eri_rtld *rtld)
{
  eri_assert_printf ("tst_rtld: %lx %lx %lx %lx\n",
		     rtld->arg, rtld->cont,
		     rtld->map_start, rtld->map_end);
  rtld->arg -= 16;
}
