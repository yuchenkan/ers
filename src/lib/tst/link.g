'use strict'; /* vim: set ft=javascript: */

const rand = 'lib/tst/tst/tst-rand.c.o';
const srcs = [ `${goal}.c.o`, rand ].concat ([ 'util.c', 'lock.S', 'buf.c', 'malloc.c', 'printf.c' ].map (s => `lib/tst/lib/${s}.o`));

await this.invoke ('goal/link.g', { srcs, ldflags: () => '' });
