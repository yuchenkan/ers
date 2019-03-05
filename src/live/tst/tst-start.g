'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${goal}.c.o`, 'tst/tst-syscall.l', 'tst/tst-common-start.S.o', 'tst/tst-live-main.c.o',
	       'live-signal-thread.l', 'live-thread.l', 'helper.c.o', 'live-thread-recorder.c.o', 'lib/lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: (_, f) => f });
