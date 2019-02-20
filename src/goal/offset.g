'use strict'; /* vim: set ft=javascript: */

const src = `${goal}.c`;
await this.invoke ('goal/gcc-depend.g', { src });
await env.run (`gcc -I . -Wall -Werror -O3 -S -o ${goal}.s ${src}`);
await env.run (`grep __AS_DEFINE__ ${goal}.s | sed 's/__AS_DEFINE__/#define/g' >${goal}`);
