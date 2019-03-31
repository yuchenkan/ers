'use strict'; /* vim: set ft=javascript: */

const src = 'public/public.h.in';
await this.update ([ src ]);

await this.invoke ('goal/gcc-depend.g', { src });
await env.run (`gcc -I . -x c -E -o ${env.trim (goal)} ${src}`);
await env.run (`grep m4_pub ${env.trim (goal)} >${goal}`);
