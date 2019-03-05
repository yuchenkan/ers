'use strict'; /* vim: set ft=javascript: */

const script = 'live/tst/tst-registers.sh';
await this.update ([ script ]);

await env.run (`bash ${script} >${goal}.t && mv ${goal}.t ${goal}`);
