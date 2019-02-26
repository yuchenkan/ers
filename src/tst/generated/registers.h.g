'use strict'; /* vim: set ft=javascript: */

const script = 'tst/generated/registers.sh';
await this.update ([ script ]);

await env.run (`bash ${script} >${goal}.t && mv ${goal}.t ${goal}`);
