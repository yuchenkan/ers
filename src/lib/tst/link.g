'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${goal}.c.o` ].concat ([ 'util', 'lock', 'buf', 'malloc', 'printf', 'tst-util' ].map (s => `lib/tst/lib/${s}.c.o`));

await this.invoke ('goal/link.g', { srcs, ldflags: () => '' });
