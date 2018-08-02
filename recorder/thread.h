#ifndef ERS_THREAD_H
#define ERS_THREAD_H 1

struct ers_thread
{
  struct ers_recorder *recorder;
  long external; // TODO
};

#endif
