'use strict'; /* vim: set ft=javascript: */

if (typeof src === 'undefined') var src = env.trim (goal);
let common = '-O3 -g -Wall -Werror -fmax-errors=32';
let flags = `${common} -fno-builtin -fno-tree-loop-distribute-patterns -fvisibility=hidden -mgeneral-regs-only -fPIE`;
if (typeof cflags !== 'undefined') flags = cflags (flags, common);

await this.invoke ('goal/gcc-depend.g', { src });
await env.run (`gcc -I . ${flags} -c -o ${goal} ${src}`);
