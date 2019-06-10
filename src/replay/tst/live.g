'use strict'; /* vim: set ft=javascript: */

if (typeof list !== 'undefined') {
  if (typeof filter === 'undefined') var filter = x => true;
  return (await this.invoke ('live/tst/replay.g')).filter (filter);
}

if (typeof environ === 'undefined') var environ = '';

let live = `live/tst/tst-init-${name}`;
await this.update ([ `${live}.out` ]);
await env.run (`rm -rf ${env.trim (goal)}-log`, true);
await this.invoke ('tst/goal/out.g', { src, environ: `${environ} ERI_LOG=${env.trim (env.base (goal))}-log ERS_DATA=../../${live}-data` });
