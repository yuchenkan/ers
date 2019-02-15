'use strict'; /* vim: set ft=javascript: */

const script = 'goals/link.g';
const srcs = [ 'tst/tst-rtld.S.o' ];

await this.update ([ script ].concat (srcs), async () => {
  await this.invoke (script, { srcs, ldflags: f => `${f} -pie -Wl,-e,start` });
});
