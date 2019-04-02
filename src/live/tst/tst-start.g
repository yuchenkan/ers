'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${goal}.c.o`, 'tst/tst-start.S.o', 'tst/tst-live-main.c.o', 'tst/tst-lib.a',
	       'live-signal-thread.l', 'live-thread.l', 'helper.c.o', 'live-thread-recorder.c.o', 'lib/lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: (_, f) => f });
