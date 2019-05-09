'use strict'; /* vim: set ft=javascript: */

const src = `${goal}.c`;
if (typeof inc == 'undefined') var inc = undefined;

let incs = await this.invoke ('goal/gcc-depend.g', { src, inc });
await env.run (`gcc -I . ${incs} -Wall -Werror -O3 -S -o ${goal}.s ${src}`);
await env.run (`grep __AS_DEFINE__ ${goal}.s | sed 's/__AS_DEFINE__/#define/g' >${goal}`);
