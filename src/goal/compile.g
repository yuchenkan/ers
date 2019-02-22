'use strict'; /* vim: set ft=javascript: */

if (typeof src === 'undefined') var src = env.trim (goal);
let flags = '-O3 -g -Wall -Werror -fno-builtin -fno-tree-loop-distribute-patterns -fvisibility=hidden -mgeneral-regs-only -fPIC';
if (typeof cflags !== 'undefined') flags = cflags (flags, env.filter (flags, /^-(O(\d|fast|g|s)|g|Wall|Werror)/));

await this.invoke ('goal/gcc-depend.g', { src });
await env.run (`gcc -I . ${flags} -c -o ${goal} ${src}`);
