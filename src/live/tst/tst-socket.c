#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-util.h>
#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");

  int32_t fd = tst_assert_syscall (socket, ERI_AF_INET, ERI_SOCK_STREAM, 0);

  struct eri_sockaddr_in addr = {
    ERI_AF_INET, 0, { tst_bswap32 (ERI_INADDR_ANY) }
  };
  tst_assert_syscall (bind, fd, &addr, sizeof addr);

  struct eri_sockaddr_storage get_addr;
  uint32_t get_addrlen = sizeof addr;
  tst_assert_syscall (getsockname, fd, &get_addr, &get_addrlen);
  eri_assert (get_addrlen == sizeof addr);
  struct eri_sockaddr_in *get_addr_in = (void *) &get_addr;
  eri_assert (get_addr_in->family == addr.family);
  eri_assert (get_addr_in->addr.addr == addr.addr.addr);
  eri_info ("port: %u\n", get_addr_in->port);

  tst_assert_syscall (listen, fd, 8);

  tst_assert_syscall (close, fd);

  tst_assert_sys_exit (0);
}
