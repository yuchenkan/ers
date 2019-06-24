#include <lib/buf.h>

int32_t
eri_buf_init (struct eri_buf *buf, eri_buf_alloc_t alloc, eri_buf_free_t free,
	      void *data, uint64_t n, uint64_t unit)
{
  buf->alloc = alloc;
  buf->free = free;
  buf->data = data;
  buf->n = n;
  buf->unit = unit;
  buf->buf = 0;
  buf->o = 0;

  return n ? alloc (data, n * unit, &buf->buf) : 0;
}

int32_t
eri_buf_fini (struct eri_buf *buf)
{
  return buf->buf ? buf->free (buf->data, buf->buf) : 0;
}

int32_t
eri_buf_reserve (struct eri_buf *buf, uint64_t n)
{
  uint64_t s = eri_max (buf->n, 1);
  while (s - buf->o < n) s *= 2;

  if (s != buf->n)
    {
      void *t = buf->buf;
      buf->n = s;

      int32_t res;
      if ((res = buf->alloc (buf->data, buf->n * buf->unit, &buf->buf)) != 0)
	return res;

      if (t)
	{
	  eri_memcpy (buf->buf, t, buf->o * buf->unit);
	  if ((res = buf->free (buf->data, t)) != 0)
	    return res;
	}
    }

  return 0;
}

int32_t
eri_buf_append (struct eri_buf *buf, const void *data, uint64_t n)
{
  int32_t res;
  if ((res = eri_buf_reserve (buf, n)) != 0)
    return res;

  eri_memcpy ((uint8_t *) buf->buf + eri_buf_off (buf), data, n * buf->unit);
  buf->o += n;
  return 0;
}

int32_t
eri_buf_concat (struct eri_buf *buf, const struct eri_buf *data)
{
  return eri_buf_append (buf, data->buf, data->o);
};

int32_t
eri_buf_shrink (struct eri_buf *buf)
{
  if (buf->n == buf->o) return 0;

  void *t = buf->buf;
  buf->n = buf->o;
  if (buf->n)
    {
      int32_t res;
      if ((res = buf->alloc (buf->data, buf->n * buf->unit, &buf->buf)) != 0)
	return res;

      eri_memcpy (buf->buf, t, buf->o * buf->unit);
    }
  else buf->buf = 0;
  return buf->free (buf->data, t);
}
