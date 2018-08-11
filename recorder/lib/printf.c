#include "util.h"
#include "printf.h"
#include "syscall.h"

#define S_IRUSR	0400	/* Read by owner.  */
#define S_IWUSR	0200	/* Write by owner.  */
#define S_IXUSR	0100	/* Execute by owner.  */

#define O_RDONLY	00
#define O_WRONLY	01
#define O_CREAT		0100
#define O_TRUNC		01000

int
ers_fopen (const char *path, char r, int *fd)
{
  unsigned long res = ERS_SYSCALL (open, path,
				   r ? O_RDONLY : O_WRONLY | O_TRUNC | O_CREAT,
				   S_IRUSR | S_IWUSR);
  if (ERS_SYSCALL_ERROR_P (res)) return 1;

  *fd = (long) res;
  return 0;
}

int
ers_fclose (int fd)
{
  return ERS_SYSCALL_ERROR_P (ERS_SYSCALL (close, fd));
}

int
ers_fwrite (int fd, const char *buf, int size)
{
  int c = 0;
  while (c != size)
    {
      unsigned long res = ERS_SYSCALL (write, fd, buf, size - c);
      if (ERS_SYSCALL_ERROR_P (res)) return 1;
      c += (int) res;
    }
  return 0;
}

int
ers_fread (int fd, char *buf, int size, int *len)
{
  int c = 0;
  while (c != size)
    {
      unsigned long res = ERS_SYSCALL (read, fd, buf, size);
      if (ERS_SYSCALL_ERROR_P (res)) return 1;
      if (res == 0) break;
      c += (int) res;
    }
  *len = c;
  return 0;
}

struct iovec
{
  void *base;
  size_t len;
};

static const char digits[] = "0123456789abcdef";

int
ers_vfprintf (int fd, const char *fmt, va_list arg)
{
  const char *p;
  int s = 1;
  for (p = fmt; *p; ++p)
    if (*p == '%') s += 2;

  struct iovec *iov = (struct iovec *) __builtin_alloca (s * sizeof (struct iovec));
  int niov = 0;
  while (*fmt)
    {
      ers_assert (niov < s);
      if (*fmt == '%')
	{
	  ++fmt;
	  if (*fmt == 'u' || *fmt == 'x' || *fmt == 'l')
	    {
	      int l = *fmt == 'l' ? sizeof (unsigned long) : sizeof (unsigned);

	      unsigned long num;
	      if (*fmt == 'l')
		{
		  ++fmt;
		  ers_assert (*fmt == 'u' || *fmt == 'x');
		  num = (unsigned long) va_arg (arg, unsigned long);
		}
	      else num = (unsigned long) va_arg (arg, unsigned);

	      unsigned char base = *fmt == 'x' ? 16 : 10;

	      char *buf = (char *) __builtin_alloca (3 * sizeof num);
	      char *endp = buf + 3 * sizeof num;

	      char *cp = endp;
	      do
		*--cp = digits[num % base];
	      while (num /= base);

	      if (*fmt == 'x')
		while (endp - cp < l * 2) *--cp = '0';

	      iov[niov].base = cp;
	      iov[niov].len = endp - cp;
	    }
	  else if (*fmt == '%')
	    {
	      iov[niov].base = (void *) fmt;
	      iov[niov].len = 1;
	    }
	  else if (*fmt == 's')
	    {
	      iov[niov].base = (void *) va_arg (arg, char *);
	      iov[niov].len = ers_strlen (iov[niov].base);
	    }
	  else ers_assert (0);
	  ++fmt;
	}
      else
	{
	  iov[niov].base = (void *) fmt;
	  while (*fmt && *fmt != '%') ++fmt;
	  iov[niov].len = fmt - (const char *) iov[niov].base;
	}
      ++niov;
    }

  return ERS_SYSCALL_ERROR_P (ERS_SYSCALL (writev, fd, iov, niov));
}

int
ers_fprintf (int fd, const char *fmt, ...)
{
  va_list arg;
  va_start (arg, fmt);
  int res = ers_vfprintf (fd, fmt, arg);
  va_end (arg);
  return res;
}

int
ers_vprintf (const char *fmt, va_list arg)
{
  return ers_vfprintf (1, fmt, arg);
}

int
ers_printf (const char *fmt, ...)
{
  va_list arg;
  va_start (arg, fmt);
  int res = ers_vprintf (fmt, arg);
  va_end (arg);
  return res;
}
