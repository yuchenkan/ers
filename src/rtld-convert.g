'use strict'; /* vim: set ft=javascript: */

const script = 'goals/link.g';
const srcs = [ 'rtld-convert.c.o' ];

await this.update ([ script ].concat (srcs), async () => {
  await this.invoke (script, { srcs, ldflags: () => '' });
});
