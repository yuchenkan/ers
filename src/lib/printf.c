#include "util.h"
#include "printf.h"
#include "syscall.h"

#include <asm/unistd.h>

#define S_IRUSR	0400	/* Read by owner.  */
#define S_IWUSR	0200	/* Write by owner.  */
#define S_IXUSR	0100	/* Execute by owner.  */

#define O_RDONLY	00
#define O_WRONLY	01
#define O_CREAT		0100
#define O_TRUNC		01000

#define READ_NORMAL	1
#define READ_EOF	2

struct file
{
  int fd;
  size_t offset;

  char read;

  char *buf;
  size_t buf_size;
  size_t buf_offset;
  size_t buf_used;
};

int
eri_fopen (const char *path, char r, eri_file_t *file,
	   char *buf, size_t buf_size)
{
  unsigned long res = ERI_SYSCALL (
    open, path, r ? O_RDONLY : O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
  if (ERI_SYSCALL_ERROR_P (res)) return 1;

  if (! buf || ! buf_size)
    *file = _ERI_RAW_FILE_FROM_FD ((long) res);
  else
    {
      // eri_assert (((unsigned long) buf & 0xf) == 0);
      eri_assert (buf_size >= sizeof (struct file));

      struct file *f = (struct file *) buf;
      eri_memset (f, 0, sizeof *f);
      f->fd = (long) res;
      f->read = !! r;
      f->buf = (char *) buf + sizeof *f;
      f->buf_size = buf_size - sizeof *f;

      *file = (eri_file_t) f;
    }
  return 0;
}

#define FTYPE(file) ((long) file & 0xf)

#define FRAW_P(file) (FTYPE (file) == _ERI_FILE_RAW)
#define FRAW_FD(file) ((long) file >> 4)

struct iovec
{
  char *base;
  size_t len;
};

static void
advance (char vec, long *buf, long *size, size_t adv)
{
  if (! vec)
    {
      *buf += adv;
      *size -= adv;
    }
  else
    {
      struct iovec *iov = (struct iovec *) *buf;
      while (adv)
	if (iov->len > adv)
	  {
	    iov->base += adv;
	    iov->len -= adv;
	    adv = 0;
	  }
	else
	  {
	    adv -= iov->len;
	    iov->base += iov->len;
	    iov->len = 0;
	    ++iov;
	    --*size;
	  }
      *buf = (long) iov;
    }
}

static int
ifwrite (int nr, int fd, long buf, long size, long offset, size_t *len)
{
  size_t wrote = 0;
  while (size)
    {
      unsigned long res = ERI_SYSCALL_NCS (nr, fd, buf, size, offset + wrote);
      if (ERI_SYSCALL_ERROR_P (res)
	  && res != -ERI_EAGAIN && res != -ERI_EINTR)
	{
	  if (len) *len = wrote;
	  return res;
	}

      wrote += res;
      advance (nr == __NR_writev || nr == __NR_pwritev, &buf, &size, res);
    }
  if (len) *len = wrote;
  return 0;
}

static void
write_file_update (struct file *f, size_t wrote)
{
  size_t left = f->buf_used - wrote;
  if (left) eri_memmove (f->buf, f->buf + wrote, left);
  f->buf_used = left;
  f->buf_offset += wrote;
}

static int
file_pwrite (struct file *f)
{
  size_t wrote;
  int res = ifwrite (__NR_pwrite64, f->fd, (long) f->buf,
		     f->buf_used, f->buf_offset, &wrote);
  write_file_update (f, wrote);
  return res;
}

int
eri_frelease (eri_file_t file, int *fd)
{
  if (file == 0) *fd = -1;
  else if (FRAW_P (file)) *fd = FRAW_FD (file);
  else
    {
      struct file *f = (struct file *) file;
      if (f->fd >= 0 && ! f->read && f->buf_used)
	{
	  int res = file_pwrite (f);
	  if (res != 0) return res;
	}
      *fd = f->fd;
      f->fd = -1;
    }
  return 0;
}

int
eri_fclose (eri_file_t file)
{
  if (! file) return 1;

  if (FRAW_P (file))
    return ERI_SYSCALL_ERROR_P (ERI_SYSCALL (close, FRAW_FD (file)));

  struct file *f = (struct file *) file;
  if (f->fd < 0) return 1;

  if (! f->read && f->buf_used)
    {
      int res = file_pwrite (f);
      if (res != 0) return res;
    }

  int res = ERI_SYSCALL_ERROR_P (ERI_SYSCALL (close, f->fd));
  if (res == 0)
    eri_memset (f, 0, sizeof *f);
  return res;
}

int
eri_fseek (eri_file_t file, long offset, int whence, unsigned long *res_offset)
{
  if (! file) return 1;

  if (FRAW_P (file))
    {
      unsigned long res = ERI_SYSCALL (lseek, FRAW_FD (file), offset, whence);
      if (ERI_SYSCALL_ERROR_P (res)) return 1;
      if (res_offset) *res_offset = res;
      return 0;
    }

  struct file *f = (struct file *) file;
  unsigned long new_offset = whence == ERI_SEEK_SET ? offset : f->offset + offset;
  if (f->read)
    {
      if (new_offset < f->buf_offset || new_offset > f->buf_offset + f->buf_used)
        {
	  f->buf_offset = new_offset;
	  f->buf_used = 0;
        }
      f->read = READ_NORMAL;
    }
  else
    {
      if (new_offset < f->buf_offset || new_offset > f->buf_offset + f->buf_used)
	{
	  int res = file_pwrite (f);
	  if (res != 0) return res;

	  f->buf_offset = new_offset;
	}

      f->buf_used = new_offset - f->buf_offset;
    }

  f->offset = new_offset;
  if (res_offset) *res_offset = f->offset;
  return 0;
}

int
eri_fwrite (eri_file_t file, const char *buf, size_t size, size_t *len)
{
  if (! file) return 1;

  if (FRAW_P (file))
    return ifwrite (__NR_write, FRAW_FD (file), (long) buf, size, 0, len);

  struct file *f = (struct file *) file;

  eri_assert (f->offset >= f->buf_offset
	      && f->offset <= f->buf_offset + f->buf_used);

  if (size + f->buf_used < f->buf_size)
    {
      eri_memcpy (f->buf + f->buf_used, buf, size);
      f->buf_used += size;
      f->offset += size;
      if (len) *len = size;
      return 0;
    }

  struct iovec iov[2] = { { f->buf, f->buf_used }, { (char *) buf, size} };
  int res = ifwrite (__NR_pwritev, f->fd, (long) iov, 2, f->buf_offset, 0);
  eri_assert (f->buf_used >= iov[0].len && size >= iov[1].len);
  write_file_update (f, f->buf_used - iov[0].len);
  f->buf_offset += size - iov[1].len;
  f->offset += size - iov[1].len;

  if (len) *len = size - iov[1].len;
  return res;
}

static int
ifread (int nr, int fd, long buf, long size, long offset, size_t *len)
{
  size_t read = 0;
  while (size)
    {
      unsigned long res = ERI_SYSCALL_NCS (nr, fd, buf, size, offset + read);
      if (ERI_SYSCALL_ERROR_P (res)
	  && res != -ERI_EAGAIN && res != -ERI_EINTR)
	{
	  if (len) *len = read;
	  return 1;
	}

      if (res == 0) break;

      read += res;
      advance (nr == __NR_readv || nr == __NR_preadv, &buf, &size, res);
    }
  if (len) *len = read;
  return 0;
}

int
eri_fread (eri_file_t file, char *buf, size_t size, size_t *len)
{
  if (! file) return 1;

  if (FRAW_P (file))
    {
      size_t read;
      int res = ifread (__NR_read, FRAW_FD (file), (long) buf, size, 0, &read);
      if (len) *len = read;
      else if (res == 0 && read != size) return 1;
      return 0;
    }

  struct file *f = (struct file *) file;

  eri_assert (f->offset >= f->buf_offset
	      && f->offset <= f->buf_offset + f->buf_used);

  if (f->buf_offset + f->buf_used >= f->offset + size)
    {
      eri_memcpy (buf, f->buf + (f->offset - f->buf_offset), size);
      f->offset += size;
      if (len) *len = size;
      return 0;
    }
  else if (f->read == READ_EOF)
    {
      size = f->buf_offset + f->buf_used - f->offset;
      eri_memcpy (buf, f->buf + (f->offset - f->buf_offset), size);
      f->offset += size;
      if (len) *len = size;
      return ! len;
    }

  struct iovec iov[2] = { { buf, size }, { f->buf, f->buf_size } };
  size_t read;
  int res = ifread (__NR_preadv, f->fd, (long) iov, 2, f->offset, &read);
  f->offset += size - iov[0].len;
  f->buf_offset = f->offset;
  f->buf_used = f->buf_size - iov[1].len;
  if (res == 0 && read != size + f->buf_size) f->read = READ_EOF;

  if (len) *len = size - iov[0].len;
  else if (res == 0 && iov[0].len) return 1;
  return res;
}

static const char digits[] = "0123456789abcdef";

int
eri_vfprintf (eri_file_t file, const char *fmt, va_list arg)
{
  if (! file) return 1;

  const char *p;
  int s = 2;
  for (p = fmt; *p; ++p)
    if (*p == '%') s += 2;

  struct iovec *iov = __builtin_alloca (s * sizeof (struct iovec));
  int niov = 1;
  while (*fmt)
    {
      eri_assert (niov < s);
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
		  eri_assert (*fmt == 'u' || *fmt == 'x');
		  num = (unsigned long) va_arg (arg, unsigned long);
		}
	      else num = (unsigned long) va_arg (arg, unsigned);

	      unsigned char base = *fmt == 'x' ? 16 : 10;

	      char *buf = __builtin_alloca (3 * sizeof num);
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
	      iov[niov].len = eri_strlen (iov[niov].base);
	    }
	  else eri_assert (0);
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

  if (FRAW_P (file))
    return ifwrite (__NR_writev, FRAW_FD (file), (long) (iov + 1), niov - 1, 0, 0);

  struct file *f = (struct file *) file;

  size_t size = 0;
  int i;
  for (i = 1; i < niov; ++i) size += iov[i].len;

  if (size + f->buf_used < f->buf_size)
    {
      for (i = 1; i < niov; ++i)
	{
	  eri_memcpy (f->buf + f->buf_used, iov[i].base, iov[i].len);
	  f->buf_used += iov[i].len;
	}
      f->offset += size;
      return 0;
    }

  iov[0].base = f->buf;
  iov[0].len = f->buf_used;
  size_t wrote;
  int res = ifwrite (__NR_pwritev, f->fd, (long) iov, niov, f->buf_offset, &wrote);
  size_t buf_wrote = f->buf_used - iov[0].len;
  write_file_update (f, buf_wrote);
  f->buf_offset += wrote - buf_wrote;
  f->offset += wrote - buf_wrote;
  return res;
}

int
eri_fprintf (eri_file_t file, const char *fmt, ...)
{
  va_list arg;
  va_start (arg, fmt);
  int res = eri_vfprintf (file, fmt, arg);
  va_end (arg);
  return res;
}

int
eri_vprintf (const char *fmt, va_list arg)
{
  return eri_vfprintf (ERI_STDOUT, fmt, arg);
}

int
eri_printf (const char *fmt, ...)
{
  va_list arg;
  va_start (arg, fmt);
  int res = eri_vprintf (fmt, arg);
  va_end (arg);
  return res;
}

int
eri_file_foreach_line (const char *path, struct eri_buf *buf,
		       void (*proc) (const void *, size_t, void *), void *data)
{
  int res;

  eri_file_t f;
  if ((res = eri_fopen (path, 1, &f, 0, 0)) != 0)
    return res;

  eri_assert (buf->off == 0 && buf->size != 0);
  while (1)
    {
      const char *d = 0;
      while (1)
	{
	  size_t l;
	  if ((res = eri_fread (f, (char *) buf->buf + buf->off, buf->size - buf->off, &l)) != 0)
	    return res;
	  buf->off += l;

	  if ((d = eri_strntok (buf->buf, '\n', buf->off)) || buf->off != buf->size)
	    break;

	  eri_buf_reserve (buf, buf->size);
	}

      const char *s = buf->buf;
      if (d != 0)
	{
	  do
	    {
	      proc (s, d - s, data);
	      s = d + 1;
	    }
	  while ((d = eri_strntok (s, '\n', (char *) buf->buf + buf->off - s)));
	}

      if (buf->off != buf->size)
	{
	  if (s < (char *) buf->buf + buf->off)
	    proc (s, (char *) buf->buf + buf->off - s, data);
	  buf->off = 0;
	  break;
	}

      buf->off = (char *) buf->buf + buf->off - s;
      eri_memmove (buf->buf, s, buf->off);
    }
  return eri_fclose (f);
}
