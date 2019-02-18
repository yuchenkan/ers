'use strict'; /* vim: set ft=javascript: */

const src = `${goal}.m4`;
await this.update ([ src ]);
await env.run (`m4 -E -P ${src} >${goal}`);
