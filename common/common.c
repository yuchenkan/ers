#include <stdarg.h>

#include "common.h"

struct iovec
{
  void* iov_base;
  size_t iov_len;
};

static const char digits[] = "0123456789abcdef";

static char *itoa(uint64_t num, char *endp, unsigned int base)
{
  do
    *--endp = digits[num % base];
  while (num /= base);
  return endp;
}

static void it_vprintf(const char *fmt, va_list arg)
{
  struct iovec iov[64];
  int niov = 0;
  while (*fmt)
  {
    assert(niov < sizeof iov / sizeof iov[0]);

    if (*fmt == '%')
    {
      ++fmt;
      if (*fmt == 'u' || *fmt == 'x' || *fmt == 'l')
      {
        uint64_t num;
        if (*fmt == 'l')
        {
          ++fmt;
          assert(*fmt == 'u' || *fmt == 'x');
          num = (uint64_t) va_arg(arg, uint64_t);
        }
        else
          num = (uint64_t) va_arg(arg, unsigned);

        char *buf = (char *) alloca(3 * sizeof (uint64_t));
        char *endp = buf + 3 * sizeof (uint64_t);

        char *cp = itoa(num, endp, *fmt == 'x' ? 16 : 10);

        if (*fmt == 'x')
          while (endp - cp < sizeof (uint64_t) * 2)
            *--cp = '0';

        iov[niov].iov_base = cp;
        iov[niov].iov_len = endp - cp;
      }
      else if (*fmt == '%')
      {
        iov[niov].iov_base = (void *) fmt;
        iov[niov].iov_len = 1;
      }
      else if (*fmt == 's')
      {
        iov[niov].iov_base = (void *) va_arg(arg, void *);
        iov[niov].iov_len = __builtin_strlen(iov[niov].iov_base);
      }
      else
        assert(0);
      ++fmt;
    }
    else
    {
      iov[niov].iov_base = (void *) fmt;
      while (*fmt && *fmt != '%')
        ++fmt;
      iov[niov].iov_len = fmt - (const char *) iov[niov].iov_base;
    }
    ++niov;
  }

  SYSCALL(writev, 1, iov, niov);
}

__attribute__ ((visibility ("hidden")))
void it_printf(const char *fmt, ...)
{
  va_list arg;

  va_start (arg, fmt);
  it_vprintf (fmt, arg);
  va_end (arg);
};
