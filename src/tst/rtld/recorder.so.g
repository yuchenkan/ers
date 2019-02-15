'use strict'; /* vim: set ft=javascript: */

const script = 'goals/link.g';
const srcs = [ 'tst/rtld/recorder.S.o', 'tst/rtld/recorder.c.o', 'lib.a' ];

await this.update ([ script ].concat (srcs), async () => {
  await this.invoke (script, { srcs, ldflags: (_, f) => `${f} -shared` });
});
