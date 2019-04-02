'use strict'; /* vim: set ft=javascript: */

await this.invoke ('goal/local.g', { srcs, keep });
await this.invoke ('goal/assert-no-undefined.g');
/* XXX: Assert number of sections to avoid new unknown section.  */
await env.run (`(($(objdump -h ${goal} | wc -l) == 39))`);
