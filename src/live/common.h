#ifndef ERI_LIVE_COMMON_H
#define ERI_LIVE_COMMON_H

struct eri_live_sigaction
{
  struct eri_sigaction act;
  uint64_t ver;
};

#endif
