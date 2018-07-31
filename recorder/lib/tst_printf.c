#include "printf.h"

int main ()
{
  ers_printf ("");
  ers_printf ("%%\n");
  ers_printf ("%u%lx\n", 1, (unsigned long) 12345);
  ers_printf ("%u%s%x\n", 1, "test", 12345);
  ers_printf ("x%luy%s%sz%xa b c%%\n", (unsigned long) 1, "test", "", 12345);
  return 0;
}
