'use strict'; /* vim: set ft=javascript: */

if (typeof src === 'undefined') var src = env.trim (goal);
let tools = '-O3 -g -Wall -Werror -fmax-errors=32';
let flags = `${tools} -D ERI_NO_CHECK -fno-builtin -fno-tree-loop-distribute-patterns -fvisibility=hidden ${await this.invoke ('goal/basic-cflags.g')}`;
if (typeof cflags !== 'undefined') flags = cflags (flags, tools);
if (typeof inc == 'undefined') var inc = undefined;

let incs = await this.invoke ('goal/gcc-depend.g', { src, inc });
await env.run (`gcc -I . ${incs} ${flags} -c -o ${goal} ${src}`);
