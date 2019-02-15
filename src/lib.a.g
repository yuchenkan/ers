'use strict'; /* vim: set ft=javascript: */

const script = 'goals/archive.g';
const srcs = [ 'buf.c', 'lock.c', 'malloc.c', 'printf.c', 'util.c' ].map (s => `lib/${s}.o`).concat ([ 'lib/syscall.l' ]);
await this.update ([ script ].concat (srcs), async () => {
  await this.invoke (script, { srcs: srcs });
});
