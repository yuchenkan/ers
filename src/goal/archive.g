'use strict'; /* vim: set ft=javascript: */

await this.update (srcs);
await env.run (`rm -f ${goal}`, true);
await env.run (`ar cr ${goal} ${srcs.join (' ')}`);
