#ifndef ERI_CLONE_H
#define ERI_CLONE_H

struct eri_clone_desc
{
  void *child;

  long flags;
  void *cstack;
  int *ptid;
  int *ctid;
  void *tp;

  long replay_result;
};

#endif
