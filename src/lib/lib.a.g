'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'buf', 'lock', 'malloc', 'printf', 'util' ].map (s => `lib/${s}.c.o`).concat ([ 'lib/syscall.l' ]);
await this.invoke ('goal/archive.g', { srcs });
