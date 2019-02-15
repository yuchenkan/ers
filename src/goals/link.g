'use strict'; /* vim: set ft=javascript: */

let flags = '-nostdlib -Wl,--no-undefined -Wl,--fatal-warnings';
if (typeof ldflags !== 'undefined') flags = ldflags (flags, `${flags} -Wl,-e,tst_start`);

await this.update (srcs, async () => {
  await env.run (`gcc ${flags} -o ${goal} ${srcs.join (' ')}`);
});
