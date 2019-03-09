'use strict'; /* vim: set ft=javascript: */

if (typeof src === 'undefined') var src = undefined;
if (typeof args === 'undefined') var args = undefined;

await this.invoke ('goal/tst/out.g', {
  src, extra: [ 'live/live' ], environ: `ERS_LIVE=../live ERS_DATA=${env.base (env.trim (goal))}-data`, args
});
