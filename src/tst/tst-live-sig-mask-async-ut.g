'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${goal}.c.o`, 'live-signal-thread.S.o', 'tst/tst-common-start.S.o',
	       'lib/util.c.o', 'lib/syscall.S.o', 'lib/printf.c.o' ];
await this.invoke ('goal/link.g', { srcs, ldflags: (_, f) => f });
