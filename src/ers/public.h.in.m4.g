'use strict'; /* vim: set ft=javascript: */

const src = 'public.h.in';
await this.update ([ src ]);

await this.invoke ('goal/gcc-depend.g', { src });
await env.run (`gcc -I . -x c -E -o ers/${src} ${src}`);
await env.run (`grep m4_pub ers/${src} >${goal}`);
