'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'buf.c', 'lock.c', 'malloc.c', 'printf.c', 'util.c' ].map (s => `lib/${s}.o`).concat ([ 'lib/syscall.l' ]);
await this.invoke ('goal/archive.g', { srcs });
