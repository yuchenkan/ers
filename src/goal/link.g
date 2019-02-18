'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ ];
let flags = '-nostdlib -Wl,--no-undefined -Wl,--fatal-warnings';
if (typeof ldflags !== 'undefined') flags = ldflags (flags, `${flags} -Wl,-e,tst_start`);

await this.update (srcs.concat (extra));
await env.run (`gcc ${flags} -o ${goal} ${srcs.join (' ')}`);
if (typeof post !== 'undefined') await post ();
