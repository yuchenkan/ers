'use strict'; /* vim: set ft=javascript: */

const src = env.join (sub, goal);
await this.update ([ src ]);
await env.mkdir (env.dir (goal));
await env.run (`cp ${src} ${goal}`);
