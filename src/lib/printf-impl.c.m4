/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#include <lib/util.h>
#include <lib/buf.h>
#include <m4_printf_h>
#include <m4_syscall_h>

#define READ_NORMAL	1
#define READ_EOF	2

struct file
{
  int32_t fd;
  uint64_t offset;

  uint8_t read;

  uint8_t *buf;
  uint64_t buf_size;
  uint64_t buf_offset;
  uint64_t buf_used;
};

int32_t
m4_ns(fopen) (const char *path, uint8_t r, eri_file_t *file,
	      void *buf, uint64_t buf_size)
{
  uint64_t res = m4_ns(sys_open) (path, r);
  if (eri_syscall_is_error (res)) return 1;

  if (! buf || ! buf_size)
    *file = eri_raw_file_from_fd (res);
  else
    {
      /* eri_assert (((uint64_t) buf & 0xf) == 0); */
      eri_assert (buf_size >= sizeof (struct file));

      struct file *f = (struct file *) buf;
      eri_memset (f, 0, sizeof *f);
      f->fd = (int32_t) res;
      f->read = !! r;
      f->buf = (uint8_t *) buf + sizeof *f;
      f->buf_size = buf_size - sizeof *f;

      *file = (eri_file_t) f;
    }
  return 0;
}

#define ftype(file) (file & 0xf)

#define fraw(file) (ftype (file) == _ERI_FILE_RAW)
#define fraw_fd(file) (file >> 4)

static void
advance (uint8_t vec, uint64_t *buf, uint64_t *size, uint64_t adv)
{
  if (! vec)
    {
      *buf += adv;
      *size -= adv;
    }
  else
    {
      struct eri_iovec *iov = (struct eri_iovec *) *buf;
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
      *buf = (uint64_t) iov;
    }
}

static int32_t
ifwrite (int32_t nr, int32_t fd,
	 uint64_t buf, uint64_t size, uint64_t offset, uint64_t *len)
{
  uint64_t wrote = 0;
  while (size)
    {
      uint64_t res = m4_ns(syscall_nr) (nr, fd, buf, size, offset + wrote);
      if (eri_syscall_is_error (res) && res != ERI_EINTR)
	{
	  if (len) *len = wrote;
	  return 1;
	}

      if (res == ERI_EINTR) continue;

      wrote += res;
      advance (nr == __NR_writev || nr == __NR_pwritev, &buf, &size, res);
    }
  if (len) *len = wrote;
  return 0;
}

static void
write_file_update (struct file *f, uint64_t wrote)
{
  uint64_t left = f->buf_used - wrote;
  if (left) eri_memmove (f->buf, f->buf + wrote, left);
  f->buf_used = left;
  f->buf_offset += wrote;
}

static int32_t
file_pwrite (struct file *f)
{
  uint64_t wrote;
  int32_t res = ifwrite (__NR_pwrite64, f->fd, (uint64_t) f->buf,
			 f->buf_used, f->buf_offset, &wrote);
  write_file_update (f, wrote);
  return res;
}

#if 0
int32_t
m4_ns(frelease) (eri_file_t file, int32_t *fd)
{
  if (file == 0) *fd = -1;
  else if (fraw (file)) *fd = fraw_fd (file);
  else
    {
      struct file *f = (struct file *) file;
      if (f->fd >= 0 && ! f->read && f->buf_used)
	{
	  int32_t res = file_pwrite (f);
	  if (res != 0) return res;
	}
      *fd = f->fd;
      f->fd = -1;
    }
  return 0;
}
#endif

int32_t
m4_ns(fclose) (eri_file_t file)
{
  if (! file) return 1;

  if (fraw (file))
    return eri_syscall_is_error (m4_ns(syscall) (close, fraw_fd (file)));

  struct file *f = (struct file *) file;
  if (f->fd < 0) return 1;

  if (! f->read && f->buf_used)
    {
      int32_t res = file_pwrite (f);
      if (res != 0) return res;
    }

  int32_t res = eri_syscall_is_error (m4_ns(syscall) (close, f->fd));
  if (res == 0)
    eri_memset (f, 0, sizeof *f);
  return res;
}

int32_t
m4_ns(fseek) (eri_file_t file, int64_t offset, uint8_t rel,
	      uint64_t *res_offset)
{
  if (! file) return 1;

  if (fraw (file))
    {
      uint64_t res = m4_ns(syscall) (lseek, fraw_fd (file), offset,
				     rel ? ERI_SEEK_CUR : ERI_SEEK_SET);
      if (eri_syscall_is_error (res)) return 1;
      if (res_offset) *res_offset = res;
      return 0;
    }

  struct file *f = (struct file *) file;
  uint64_t new_offset = rel ? f->offset + offset : offset;
  if (f->read)
    {
      if (new_offset < f->buf_offset
	  || new_offset > f->buf_offset + f->buf_used)
	{
	  f->buf_offset = new_offset;
	  f->buf_used = 0;
	}
      f->read = READ_NORMAL;
    }
  else
    {
      if (new_offset < f->buf_offset
	  || new_offset > f->buf_offset + f->buf_used)
	{
	  int32_t res = file_pwrite (f);
	  if (res != 0) return res;

	  f->buf_offset = new_offset;
	}

      f->buf_used = new_offset - f->buf_offset;
    }

  f->offset = new_offset;
  if (res_offset) *res_offset = f->offset;
  return 0;
}

int32_t
m4_ns(fwrite) (eri_file_t file, const void *buf, uint64_t size, uint64_t *len)
{
  if (! file) return 1;

  if (fraw (file))
    return ifwrite (__NR_write, fraw_fd (file),
		    (uint64_t) buf, size, 0, len);

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

  struct eri_iovec iov[2] = { { f->buf, f->buf_used }, { (void *) buf, size} };
  int32_t res = ifwrite (__NR_pwritev, f->fd,
			 (uint64_t) iov, 2, f->buf_offset, 0);
  eri_assert (f->buf_used >= iov[0].len && size >= iov[1].len);
  write_file_update (f, f->buf_used - iov[0].len);
  f->buf_offset += size - iov[1].len;
  f->offset += size - iov[1].len;

  if (len) *len = size - iov[1].len;
  return res;
}

static int32_t
ifread (int32_t nr, int32_t fd, uint64_t buf,
	uint64_t size, uint64_t offset, uint64_t *len)
{
  uint64_t read = 0;
  while (size)
    {
      uint64_t res = m4_ns(syscall_nr) (nr, fd, buf, size, offset + read);
      if (eri_syscall_is_error (res) && res != ERI_EINTR)
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

int32_t
m4_ns(fread) (eri_file_t file, void *buf, uint64_t size, uint64_t *len)
{
  if (! file) return 1;

  if (fraw (file))
    {
      uint64_t read;
      int32_t res = ifread (__NR_read, fraw_fd (file),
			    (uint64_t) buf, size, 0, &read);
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

  struct eri_iovec iov[2] = { { buf, size }, { f->buf, f->buf_size } };
  uint64_t read;
  int32_t res = ifread (__NR_preadv, f->fd,
			(uint64_t) iov, 2, f->offset, &read);
  f->offset += size - iov[0].len;
  f->buf_offset = f->offset;
  f->buf_used = f->buf_size - iov[1].len;
  if (res == 0 && read != size + f->buf_size) f->read = READ_EOF;

  if (len) *len = size - iov[0].len;
  else if (res == 0 && iov[0].len) return 1;
  return res;
}

int32_t
m4_ns(vfprintf) (eri_file_t file, const char *fmt, va_list arg)
{
  if (! file) return 1;

  const char *p;
  int32_t s = 2;
  for (p = fmt; *p; ++p)
    if (*p == '%') s += 2;

  struct eri_iovec *iov = __builtin_alloca (s * sizeof (struct eri_iovec));
  int32_t niov = 1;
  while (*fmt)
    {
      eri_assert (niov < s);
      if (*fmt == '%')
	{
	  ++fmt;
	  if (*fmt == 'u' || *fmt == 'x' || *fmt == 'l')
	    {
	      int32_t l = *fmt == 'l'
			    ? sizeof (uint64_t) : sizeof (uint32_t);

	      uint64_t num;
	      if (*fmt == 'l')
		{
		  ++fmt;
		  eri_assert (*fmt == 'u' || *fmt == 'x');
		  num = va_arg (arg, uint64_t);
		}
	      else num = (uint64_t) va_arg (arg, uint32_t);

	      uint8_t base = *fmt == 'x' ? 16 : 10;

	      char *buf = __builtin_alloca (3 * sizeof num);
	      char *endp = buf + 3 * sizeof num;

	      static const char digits[] = "0123456789abcdef";

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
	      iov[niov].base = va_arg (arg, char *);
	      iov[niov].len = eri_strlen (iov[niov].base);
	    }
	  else eri_assert_unreachable ();
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

  if (fraw (file))
    return ifwrite (__NR_writev, fraw_fd (file),
		    (uint64_t) (iov + 1), niov - 1, 0, 0);

  struct file *f = (struct file *) file;

  uint64_t size = 0;
  int32_t i;
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
  uint64_t wrote;
  int32_t res = ifwrite (__NR_pwritev, f->fd,
			 (uint64_t) iov, niov, f->buf_offset, &wrote);
  uint64_t buf_wrote = f->buf_used - iov[0].len;
  write_file_update (f, buf_wrote);
  f->buf_offset += wrote - buf_wrote;
  f->offset += wrote - buf_wrote;
  return res;
}

int32_t
m4_ns(fprintf) (eri_file_t file, const char *fmt, ...)
{
  va_list arg;
  va_start (arg, fmt);
  int32_t res = m4_ns(vfprintf) (file, fmt, arg);
  va_end (arg);
  return res;
}

int32_t
m4_ns(vprintf) (const char *fmt, va_list arg)
{
  return m4_ns(vfprintf) (ERI_STDOUT, fmt, arg);
}

int32_t
m4_ns(printf) (const char *fmt, ...)
{
  va_list arg;
  va_start (arg, fmt);
  int32_t res = m4_ns(vprintf) (fmt, arg);
  va_end (arg);
  return res;
}

int32_t
m4_ns(file_foreach_line) (const char *path, struct eri_buf *buf,
		void (*proc) (const char *, uint64_t, void *), void *data)
{
  int32_t res;

  eri_file_t f;
  if ((res = m4_ns(fopen) (path, 1, &f, 0, 0)) != 0)
    return res;

  eri_assert (buf->o == 0 && buf->n != 0);
  while (1)
    {
      const char *d = 0;
      while (1)
	{
	  uint64_t l;
	  if ((res = m4_ns(fread) (f, buf->buf + buf->o,
				   buf->n - buf->o, &l)) != 0)
	    return res;
	  buf->o += l;

	  if ((d = eri_strntok (buf->buf, '\n', buf->o))
	      || buf->o != buf->n)
	    break;

	  eri_buf_reserve (buf, buf->n);
	}

      const char *s = buf->buf;
      if (d != 0)
	{
	  do
	    {
	      proc (s, d - s, data);
	      s = d + 1;
	    }
	  while ((d = eri_strntok (s, '\n',
				   (char *) buf->buf + buf->o - s)));
	}

      if (buf->o != buf->n)
	{
	  if (s < (char *) buf->buf + buf->o)
	    proc (s, (char *) buf->buf + buf->o - s, data);
	  buf->o = 0;
	  break;
	}

      buf->o = (char *) buf->buf + buf->o - s;
      eri_memmove (buf->buf, s, buf->o);
    }
  return m4_ns(fclose) (f);
}
