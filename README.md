# Introducation

This is a deterministic record/replay framework for multi-threaded programs based on marking synchronization primitives. It's a pure user space library for the Linux-x86-64 platform running right above the kernel and below all other user space code. It provides API in the form of C macros to directly replace instructions and you may wrap the macros to provide C functions. The macros wrap the operation on the thread-local fields installed in the GS register by detouring the startup and clone. To detect the race condition between the threads, an analyzer is provided with a JIT compiler to support dynamic instrumentation.

# Background

The idea has been in my head for a quite long time. As a server-side programer and having experience in managing a full stack team, I see lots of inefficiencies in debugging and testing largely due to the nondeterminstic nature. I started to work on a demo of this project because I need to build a multi-paxos demo for a distributed storage system, which is critical and needs to be bug-free. The multi-paxos demo can also be found in my GitHub.

I hope to build a deterministic framework for the whole distributed system, and the very first step is to build an enviroment for the multi-threaded program. Essentially, the principle is same in both systems and the most difficult challenges also have to be handled in the multi-threaded environment. These challenges include sharing memory between different contexts and dealing with signals.

Also I hope to automatically enumerate execution cases identified by the different orders of running contexts. It's also possible to assign the probabilities of each cases by estimating the running speed. The common approach is adding pressure to the system so it may hit some corner cases. This approach is also not efficient as at most time they are testing the most common execution order, and even if a bug in a corner case is found, it's hard to reproduce. Further more it's very hard to estimate the coverage of the test. At the time I started to build this project, I was not aware of TLA+, but from my current limited knowledge about TLA+, I feel the model checking method in TLA+ is very similar. They both try to pick the next atomic action to cover the behavior of the system. The main difference is this is based on and used for the C code.

To make the recording in the deterministic record/replay efficient and make enumerating possible, we have to mark the synchronization primitivies. Along with other things, this provides a very precise input set for the system and matches much better with the model the developers use. This means it can greatly reduce the state space to be explored and provides a base to start the symbolic execution.

Although explicitly marking user code is not desired, using builtin atomic operations are encouraged, and most modifications can be limited within the C runtime. Besides, we may need further annotation to indicate the relations between processes or even machines if we want to make a distributed system deterministic and taking advantage of eliminating the recording of e.g. the internal traffics. Further more, we may also take advantage of undefined and unspecified behaviors to further reduce the state space, as done in the Valgrind. These behaviors are specfied by the language and system standard. For the user specifed behaviors, annotation is also needed, but this is too far away from this project.

# Quickstart

Use the following code to create the development environment.

```shell
mkdir src data
cat << EOF >src/Dockerfile
FROM fedora:28

RUN yum install -y git gcc m4 nodejs java librsvg2-tools graphviz
# RUN yum install -y vim gdb findutils procps
EOF
docker build src -t ers-dev
wget https://nchc.dl.sourceforge.net/project/plantuml/plantuml.jar -P data
docker run --privileged -v $(realpath ./data):/work -it ers-dev bash
```

Java, rsvg and graphviz are used for generating graphs in the doc. The nodejs and GCC needs to be new enough. The version installed by the above code is node 8.12.0 and gcc 8.3.1.

After entering the environment, clone, build and run test.

```shell
cd /work
git clone https://github.com/yuchenkan/ers.git
cd ers
bash make.sh
```

The make.sh will download and build the intel xed library at the first time to support encoding and decoding for the dynamic instrumentation JIT compiler in the analysis. This is the only 3rd part library required. Then it will build and test the ers, and it will also build the doc.

The build and test system for the ers source code is located under make folder. It's written in JavaScript. See the README inside the make folder for more info.

If everything goes well, the final result to support recording is inside build/src/ers. This includes public.h and live. But for the internal testing, the header and lib is inside build/src/live, which is almost the same but without further post process. The binary for replay and analysis are inside build/src/replay and build/src/analysis respectively.

Use the following code afterwards at /work/ers/src to build the src folder only.

```shell
make a=all
```

It's not easy to use this environment without the modification of C runtime. You may refer to the testing cases for the demostration. You may find most commands in the output of the build system. Use the following code to show all the commands.

```shell
node ../make/make.js -v -j 8 . ../build/src all
```

All the replayable and analyzable testing cases are listed in src/live/replay.g. See inside make folder for how to interpret these goal files. Taking the clone testing case as an example, use the following code to first record, replay and analyze the case, and then check the identity between the replay and analysis execution. Delete build/src folder to see the whole process.

```shell
make a=analysis/tst/tst-live-clone.diff
```

In the output, you should be able to find these commands.

```shell
cd live/tst && ERS_LIVE=../live ERS_DATA=tst-init-clone-data ./tst-init-clone
cd replay/tst &&  ERI_LOG_NO_SEQ=1 ERI_LOG=tst-live-clone-log ERS_DATA=../../live/tst/tst-init-clone-data ../replay
cd analysis/tst &&  ERI_LOG_NO_SEQ=1 ERI_LOG=tst-live-clone-log ERS_DATA=../../live/tst/tst-init-clone-data ../analysis
```

These are the commands used to record, replay and analyze respectively. They are executed at build/src. You may have already noticed that the log file of the deterministic record/replay is stored inside build/src/live/tst/tst-init-clone-data.

You may also find out how the live and tst-init-clone-data is built in the output. You may also read the goal files to know how these commands are constructed.

At the end of this artical, you can find part of the patch for the gLibc to get a sense of how this is used.

# Technical details

Before diving into the details, there are serveral design decisions I need to make clear. These decisions make the implementation of recording very complicated, and from my current view, it can be simiplified by loosening the assumptions.

First, I want to make it pure user space. Because with the existing kernel, we don't have support to monitor the atomic operations, we can't solve the problem solely based on the debug interface provided by the kernel, like PTRACE. Also to make the recording more efficient, PTRACE is completely not used in the implementation. Also because there is no direct support for atomic operations, I need to re-implement part of system calls having atomic operations in user space, such as futex, and exit with tid_address set. Further more, because I don't use the PTRACE, I need to be very careful to distinguish the synchronized and asynchronized signals. I have to prevent the synchronized signal accidently kill the process because it's being blocked. To achieve this, for each user thread, I create another signal thread to receive all the asynchronized signals and make the user thread always open to any signals.  

Second, I want to make the macros used to replace the instructions behave exactly like the original instructions with the only exception of length. This becomes extremely tricky when dealing with signals because the signals should not happen in the middle of the macros. Also due to that I need to make the user thread not blocking any signals, I need to implement the signal pending machanism in the user space.

Despite these complications, the general idea is simple. In the mutli-threaded system, the number of possible process memory state explodes due to the interleaving of instructions from different threads. Instead of catching the every exact memory state, we can only catch the order of memory accesses that really matters. In a race free environment, this means the order of accessing the shared memory.

For instance, consider the following two routines `r1` and `r2` running on two different threads.

```c
lock_t lock;

void r1 ()
{
  foo1 ();
  acquire (&lock);
  bar1 ();
  release (&lock);
}

void r2 ()
{
  foo2 ();
  acquire (&lock);
  bar2 ();
  release (&lock);
}
```

The developers may only be interested in which thread acquires the lock first between `r1` and `r2`, not the possible interleaving between `foo1` and `foo2`. In other word, it normally means `foo1` and `foo2` should be race-free and should only access their own private memory space. Therefore, for this example we may only need to record who get the lock first.

Meanwhile, we also need to prove there is no race condition between `foo1` and `foo2`, and this introduces the post-run analysis. In the analysis, we can record all memory accesses from `foo1` and `foo2`, and conservatively prove there is no race condition by showing there is no conflict memory access.

More specifically, let's consider a simple implementation of spin lock.

```c
int lock = 0;

void acquire ()
{
  while (atomic_compare_and_exchange (&lock, 0, 1))
    continue;
}

void release ()
{
  atomic_store (&lock, 0);
}
```

Here, the racy accesses are two atomic calls, which in turn calls, for example, `cmpxchg` and `mov` respectively. The memory accesses when the lock hold are protected and shall not be racy. Therefore we only need to record the order of accessing the lock, as shown below.

```c
void record_atomic (ptr)
{
  append (get_atomic_log (ptr), gettid ());
}

lock_t atomic_lock;

int atomic_compare_and_exchange (ptr, expected, desired)
{
  lock (&atomic_lock);
  record_atomic (ptr);
  int res = __atomic_compare_and_exchange (ptr, expected, desired);
  unlock (&atomic_lock);
  return res;
}

void atomic_store (ptr, val);
{
  lock (&atomic_lock);
  record_atomic (ptr);
  __atomic_store (ptr, val);
  unlock (&atomic_lock);
}
```

For two threads executing the following code.

```c
void thread ()
{
  while (1)
    {
	    acquire ();
	    foo ();
	    release ();
    }
}
```

The final log will be like: `t1 t1 t2 t1 t2...`

Here is another example with respect to the signals, a very simple and common usage of `SIGINT` to exit the process.

```c
int exit = 0;

void handle ()
{
  exit = 1;
}

void loop ()
{
  signal (SIGINT, handle);

  while (! atomic_load (&exit))
    foo ();
}
```

The key here is it does not matter when the signal is raised inside `foo`, it only matters how many times `foo` is executed. Therefore we only need to record this number, as below.

```c
void wrap (handle)
{
  append (get_thread_log (), SIGNAL);
  handle ();
}

void signal (sig, handle)
{
  __signal (sig, wrap, handle);
}

int atomic_load (ptr)
{
  append (get_thread_log (), ATOMIC);
  return __atomic_load (ptr);
}
```

The final log will be like: `ATOMIC ATOMIC ATOMIC SIGNAL`.

The signal handlers may also access the cpu context. This means it may also be synchronized by the value of registers. Therefore, the solution is to provide a universal wrap for any instructions to set barriers for signals. The implementation is also very tricky to handle jump or repeatable instructions.

# Example

Here is an example of how to modify the gLibc to use the lib. It only shows part of the patch.

Init:
```diff
diff --git a/sysdeps/x86_64/start.S b/sysdeps/x86_64/start.S
index 354d2e6ec7..8f5b11397c 100644
--- a/sysdeps/x86_64/start.S
+++ b/sysdeps/x86_64/start.S
@@ -55,7 +55,16 @@

 #include <sysdep.h>

+#include <ers/ers.h>
+
 ENTRY (_start)

+       ERS_INIT
+
        /* Clearing frame pointer is insufficient, use CFI.  */
        cfi_undefined (rip)
        /* Clear the frame pointer.  The ABI suggests this be done, to mark
```

This is actually more complicated because the `_start` may be called by `_dl_start_user`, in which case it's not the first instruction of the process and the `ERS_INIT` is already called in `_dl_start_user` and shall not be called more than once.

System call:

```diff
diff --git a/sysdeps/unix/sysv/linux/x86_64/clone.S b/sysdeps/unix/sysv/linux/x86_64/clone.S
index 34bebe0c00..05ed26f416 100644
--- a/sysdeps/unix/sysv/linux/x86_64/clone.S
+++ b/sysdeps/unix/sysv/linux/x86_64/clone.S
@@ -23,6 +23,8 @@
 #include <bits/errno.h>
 #include <asm-syntax.h>

+#include <ers/ers.h>
+
 /* The userland implementation is:
    int clone (int (*fn)(void *arg), void *child_stack, int flags, void *arg),
    the kernel entry is:
@@ -73,7 +75,7 @@ ENTRY (__clone)
        /* End FDE now, because in the child the unwind info will be
           wrong.  */
        cfi_endproc;
-       syscall
+       ERS_SYSCALL (0)
```

Atomic instruction:

```diff
diff --git a/sysdeps/unix/sysv/linux/x86_64/lowlevellock.S b/sysdeps/unix/sysv/linux/x86_64/lowlevellock.S
index 92561e1da0..a03468f266 100644
--- a/sysdeps/unix/sysv/linux/x86_64/lowlevellock.S
+++ b/sysdeps/unix/sysv/linux/x86_64/lowlevellock.S
@@ -23,6 +23,8 @@

 #include <stap-probe.h>

+#include <ers/ers.h>
+
        .text

 #ifdef __ASSUME_PRIVATE_FUTEX
@@ -90,10 +92,10 @@ __lll_lock_wait_private:

 1:     LIBC_PROBE (lll_lock_wait_private, 1, %rdi)
        movl    $SYS_futex, %eax
-       syscall
+       ERS_SYSCALL (0)

 2:     movl    %edx, %eax
-       xchgl   %eax, (%rdi)    /* NB:   lock is implied */
+       ERS_ATOMIC_XCHG (0, l, %eax, (%rdi))    /* NB:   lock is implied */

        testl   %eax, %eax
        jnz     1b
```

For the first parameter of the macros, 0 means % symbol is not escaped. When used in the asm extension, you need to use 1. Here is an example.

```c
#define ers_satomic_xchg(size, reg, mem) \
  ers_str (ERS_ATOMIC_XCHG (1, size, reg, mem))

#define _ers_exchange(ptr, val) \
  ({                                                                    \
    typeof (*(ptr)) __ers_ret = (typeof (__ers_ret)) (val);             \
    switch (sizeof __ers_ret)                                           \
      {                                                                 \
      case 1:                                                           \
        asm volatile (ers_satomic_xchg (b, %b1, %0)                     \
              : "+m" (*(ptr)), "+r" (__ers_ret) : : "memory");          \
        break;                                                          \
      case 2:                                                           \
        asm volatile (ers_satomic_xchg (w, %w1, %0)                     \
              : "+m" (*(ptr)), "+r" (__ers_ret) : : "memory");          \
        break;                                                          \
      case 4:                                                           \
        asm volatile (ers_satomic_xchg (l, %1, %0)                      \
              : "+m" (*(ptr)), "+r" (__ers_ret) : : "memory");          \
        break;                                                          \
      default:                                                          \
        asm volatile (ers_satomic_xchg (q, %q1, %0)                     \
              : "+m" (*(ptr)), "+r" (__ers_ret) : : "memory");          \
        break;                                                          \
      }                                                                 \
    __ers_ret;                                                          \
  })
```
