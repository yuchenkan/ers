'use strict'; /* vim: set ft=javascript: */

const script = 'goals/link.g';
const srcs = [ `${goal}.c.o`, 'tst/tst-common-start.S.o', 'tst/tst-live-main.c.o', 'live-signal-thread.l', 'live-thread.l', 'helper.c.o', 'live-thread-recorder.c.o', 'lib.a' ];

await this.update ([ script ], async () => {
  await this.invoke (script, { srcs, ldflags: (_, f) => f });
});
