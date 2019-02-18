'use strict'; /* vim: set ft=javascript: */

const src = env.trim (goal);
let flags = '-g -Wall -Werror -fno-builtin -fno-tree-loop-distribute-patterns -fvisibility=hidden -mgeneral-regs-only -fPIC';
if (typeof cflags !== 'undefined') flags = cflags (flags);

await this.update ([ src ]);
await this.invoke ('goal/depend.g', { src });
await env.run (`gcc -I . ${flags} -c -o ${goal} ${src}`);
