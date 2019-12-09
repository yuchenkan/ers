# Introducation
This is a deterministic record/replay framework for multi-threaded programs based on marking synchronization primitives. It's a pure user space library for the Linux-x86-64 platform running right above the kernel and below all other user space code. It provides API in the form of C macros to directly replace instructions and you may wrap the macros to provide C functions. The macros wrap the operation on the thread-local fields installed in the GS register by detouring the startup and clone.

# Background
The idea has been in my head for a quite long time. As a server-side programer and having experience in managing a full stack team, I see lots of inefficiencies in debugging and testing largely due to the nondeterminstic nature. I started to work on a demo of this project because I need to build a multi-paxos demo for a distributed storage system, which is crtical and needs to be bug-free. The multi-paxos demo can also be found in my GitHub.

I hope to build a deterministic framework for the whole distributed system, and the very first step is to build an enviroment for the multi-threaded program. Essentially, the principle is same in both systems and the most difficult challenges also have to be handled in the multi-threaded environment. These challenges include sharing memory between different contexts and dealing with signals.

Also I hope to automatically enumerate execution cases identified by the different orders of running contexts. It's also possible to assign the probabilities of each cases by estimating the running speed. The common approach is adding pressure to the system so it may hit some corner cases. This approach is also not efficient as at most time they are testing the most common execution order, and even if a bug in a corner case is found, it's hard to reproduce. Further more it's very hard to estimate the coverage of the test. At the time I started to build this project, I was not awaring of TLA, but from my current limited knowledge about TLA, I feel the checking method in TLA is very similar. They both try to pick the next atomic action to cover the behavior of the system. The main difference is this is based on and used for the C code.

To make the recording in the deterministici replay efficient and enumerating possible, we have to mark the synchronization primitivies. Along with other things, this provides a very precise input set for the system and matches much better with the model the developers use. This means it can greatly reduce the state space to be explored and provides a base to start the symbolic execution.

# Quickstart

TODO
