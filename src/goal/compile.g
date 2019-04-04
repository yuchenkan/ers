'use strict'; /* vim: set ft=javascript: */

if (typeof src === 'undefined') var src = env.trim (goal);
let tools = '-O3 -g -Wall -Werror -fmax-errors=32';
let flags = `${tools} -fno-builtin -fno-tree-loop-distribute-patterns -fvisibility=hidden ${await this.invoke ('goal/basic-cflags.g')}`;
if (typeof cflags !== 'undefined') flags = cflags (flags, tools);

await this.invoke ('goal/gcc-depend.g', { src });
await env.run (`gcc -I . ${flags} -c -o ${goal} ${src}`);
