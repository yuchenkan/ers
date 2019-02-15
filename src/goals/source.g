'use strict'; /* vim: set ft=javascript: */

const src = env.src (goal);
await this.update ([ src ], async () => await env.run (`cp ${src} ${goal}`, true));
