'use strict'; /* vim: set ft=javascript: */

const rand = new Set ([ 'malloc' ].map (x => `lib/tst/tst-${x}`)).has (goal) ? [ 'lib/tst/tst/tst-rand.c.o' ] : [ ];
const srcs = [ `${goal}.c.o` ].concat(rand).concat ([ 'util', 'lock', 'buf', 'malloc', 'printf' ].map (s => `lib/tst/lib/${s}.c.o`));

await this.invoke ('goal/link.g', { srcs, ldflags: () => '' });
