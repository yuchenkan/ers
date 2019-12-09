# Introducation

This is a deterministic record/replay framework for multi-threaded programs based on marking synchronization primitives. It's a pure user space library for the Linux-x86-64 platform running right above the kernel and below all other user space code. It provides API in the form of C macros to directly replace instructions and you may wrap the macros to provide C functions. The macros wrap the operation on the thread-local fields installed in the GS register by detouring the startup and clone. To detect the race condition between the threads, an analyzer is provided with a JIT compiler to support dynamic instrumentation.

# Background

The idea has been in my head for a quite long time. As a server-side programer and having experience in managing a full stack team, I see lots of inefficiencies in debugging and testing largely due to the nondeterminstic nature. I started to work on a demo of this project because I need to build a multi-paxos demo for a distributed storage system, which is crtical and needs to be bug-free. The multi-paxos demo can also be found in my GitHub.

I hope to build a deterministic framework for the whole distributed system, and the very first step is to build an enviroment for the multi-threaded program. Essentially, the principle is same in both systems and the most difficult challenges also have to be handled in the multi-threaded environment. These challenges include sharing memory between different contexts and dealing with signals.

Also I hope to automatically enumerate execution cases identified by the different orders of running contexts. It's also possible to assign the probabilities of each cases by estimating the running speed. The common approach is adding pressure to the system so it may hit some corner cases. This approach is also not efficient as at most time they are testing the most common execution order, and even if a bug in a corner case is found, it's hard to reproduce. Further more it's very hard to estimate the coverage of the test. At the time I started to build this project, I was not awaring of TLA, but from my current limited knowledge about TLA, I feel the checking method in TLA is very similar. They both try to pick the next atomic action to cover the behavior of the system. The main difference is this is based on and used for the C code.

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

# Technical details

TODO
