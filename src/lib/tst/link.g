'use strict'; /* vim: set ft=javascript: */

const rand = 'lib/tst/tst/tst-rand.c.o';
const srcs = [ `${goal}.c.o`, rand ].concat ([ 'util', 'lock', 'buf', 'malloc', 'printf' ].map (s => `lib/tst/lib/${s}.c.o`));

await this.invoke ('goal/link.g', { srcs, ldflags: () => '' });
