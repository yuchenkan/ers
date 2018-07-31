#include "printf.h"

int main ()
{
  eri_printf ("");
  eri_printf ("%%\n");
  eri_printf ("%u%lx\n", 1, (unsigned long) 12345);
  eri_printf ("%u%s%x\n", 1, "test", 12345);
  eri_printf ("x%luy%s%sz%xa b c%%\n", (unsigned long) 1, "test", "", 12345);
  return 0;
}
