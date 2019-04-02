'use strict'; /* vim: set ft=javascript: */

if (typeof src === 'undefined') var src = env.trim (goal);
if (typeof extra === 'undefined') var extra = [ ];
if (typeof environ === 'undefined') var environ = '';
if (typeof args === 'undefined') var args = '';

let bin = env.relative (env.dir (goal), src);
bin = bin.startsWith ('.') ? bin : `./${bin}`;
const base = env.base (goal);

await this.update ([ src ].concat (extra));
await env.mkdir (goal);
await env.run (`cd ${env.dir (goal)} && ${environ} ${bin} ${args} 2>&1 | awk '{ print; print >"/dev/stderr" }' | tee ${env.trim (base)}.log; test \${PIPESTATUS[0]} -eq 0 && touch ${base}`);
