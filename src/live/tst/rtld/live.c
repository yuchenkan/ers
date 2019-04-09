#include <lib/printf.h>
#include <lib/util.h>
#include <live/rtld.h>

int32_t a;
int32_t b = 1;
static int32_t c = 1;
static int32_t d;

void
start (struct eri_live_rtld_args *rtld)
{
  eri_assert_printf ("start: %lx %lx %lx %lx\n",
		     rtld->rsp, rtld->rip,
		     rtld->map_start, rtld->map_end);
  eri_assert (a == 0);
  eri_assert (b == 1);
  eri_assert (c == 1);
  eri_assert (d == 0);
}
