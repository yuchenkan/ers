'use strict'; /* vim: set ft=javascript: */

if (typeof args === 'undefined') var args = '';

let src = `live/tst/tst-init-${name}`;

await this.update ([ 'live/live', src ]);
await this.invoke ('tst/goal/out.g', { src, environ: `TST_PLAIN=1 ERS_LIVE=../../live/live`, args });
