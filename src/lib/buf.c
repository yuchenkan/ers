#include "buf.h"

int32_t
eri_buf_init (struct eri_buf *buf, eri_buf_alloc_t alloc, eri_buf_free_t free,
	      void *data, uint64_t size)
{
  buf->alloc = alloc;
  buf->free = free;
  buf->data = data;
  buf->size = size;
  buf->buf = 0;
  buf->off = 0;

  buf->buf = data;
  return alloc ? alloc (data, size, &buf->buf) : 0;
}

int32_t
eri_buf_fini (struct eri_buf *buf)
{
  return buf->free ? buf->free (buf->data, buf->buf) : 0;
}

int32_t
eri_buf_reserve (struct eri_buf *buf, uint64_t size)
{
  uint64_t s = buf->size;
  while (buf->size - buf->off < size) buf->size *= 2;

  if (buf->size != s)
    {
      if (! buf->alloc) return 1;

      void *t = buf->buf;

      int32_t res;
      if ((res = buf->alloc (buf->data, buf->size, &buf->buf)) != 0)
	return res;

      eri_memcpy (buf->buf, t, buf->off);
      if (buf->free && (res = buf->free (buf->data, t)) != 0)
	return res;
    }

  return 0;
}

int32_t
eri_buf_append (struct eri_buf *buf, const void *data, uint64_t size)
{
  int32_t res;
  if ((res = eri_buf_reserve (buf, size)) != 0)
    return res;

  eri_memcpy ((uint8_t *) buf->buf + buf->off, data, size);
  buf->off += size;
  return 0;
}

int32_t
eri_buf_concat (struct eri_buf *buf, const struct eri_buf *data)
{
  return eri_buf_append (buf, data->buf, data->off);
};
