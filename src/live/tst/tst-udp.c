#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-util.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

uint8_t eri_aligned16 stack[1024 * 1024];

static struct eri_sockaddr_in addr;

static void
send (void *args)
{
  int32_t fd = tst_assert_syscall (socket, ERI_AF_INET,
				   ERI_SOCK_DGRAM, 0);

  char buf = 0x12;
  tst_assert_syscall (sendto, fd, &buf, 1, 0,
		      &addr, sizeof addr);
  struct eri_sockaddr_in srv_addr;
  uint32_t srv_addrlen = sizeof srv_addr;
  tst_assert_syscall (recvfrom, fd, &buf, 1, 0,
		      &srv_addr, &srv_addrlen);
  eri_assert (buf == 0x12);
  eri_assert (srv_addr.family == addr.family);
  eri_assert (srv_addr.port == addr.port);
  tst_assert_syscall (close, fd);
}

eri_noreturn void
tst_live_start (void)
{
  int32_t fd = tst_assert_syscall (socket, ERI_AF_INET,
				   ERI_SOCK_DGRAM, 0);

  struct eri_sockaddr_in srv_addr = {
    ERI_AF_INET, 0, { tst_bswap32 (ERI_INADDR_ANY) }
  };
  tst_assert_syscall (bind, fd, &srv_addr, sizeof srv_addr);
  uint32_t addrlen = sizeof addr;
  tst_assert_syscall (getsockname, fd, &addr, &addrlen);

  struct tst_live_clone_args args = {
    tst_stack_top (stack), 0, send
  };

  tst_assert_live_clone (&args);

  struct eri_sockaddr_in clt_addr;
  uint32_t clt_addrlen = sizeof clt_addr;

  char buf;
  eri_info ("recv\n");
  uint64_t n = tst_assert_syscall (recvfrom, fd, &buf, 1, 0,
				   &clt_addr, &clt_addrlen);
  eri_assert (n == 1);
  eri_info ("send\n");
  tst_assert_syscall (sendto, fd, &buf, 1, 0, &clt_addr, clt_addrlen);

  tst_assert_sys_futex_wait (&args.alive, 1, 0);

  tst_assert_syscall (close, fd);
  tst_assert_sys_exit (0);
}
