'use strict'; /* vim: set ft=javascript: */

if (typeof src === 'undefined') var src = env.trim (goal);
if (typeof extra === 'undefined') var extra = [ ];
if (typeof environ === 'undefined') var environ = '';
if (typeof args === 'undefined') var args = '';

const base = env.base (src);
await this.update ([ src ].concat (extra));
await env.run (`cd ${env.dir (src)} && ${environ} ./${base} ${args} 2>&1 | awk '{ print; print >"/dev/stderr" }' | tee ${base}.log; test \${PIPESTATUS[0]} -eq 0 && touch ${env.base (goal)}`);
