'use strict'; /* vim: set ft=javascript: */

if (typeof src === 'undefined') var src = undefined;
if (typeof args === 'undefined') var args = undefined;

await this.update ([ 'live/live' ]);
await this.invoke ('goal/tst/out.g', { src, args, environ: 'ERS_LIVE=../live' });
