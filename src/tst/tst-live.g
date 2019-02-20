'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${goal}.c.o`, 'tst/tst-syscall.l', 'lib/tst-util.c.o', 'tst/tst-common-start.S.o', 'tst/tst-live-main.c.o', 'live-signal-thread.l', 'live-thread.l', 'helper.c.o', 'live-thread-recorder.c.o', 'lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: (_, f) => f });
