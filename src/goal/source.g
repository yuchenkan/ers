'use strict'; /* vim: set ft=javascript: */

const src = env.src (goal);
if (await this.update ([ src ])) await env.run (`cp ${src} ${goal}`);
