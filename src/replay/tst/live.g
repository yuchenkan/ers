'use strict'; /* vim: set ft=javascript: */

if (typeof list !== 'undefined') {
  if (typeof filter === 'undefined') var filter = x => true;
  return (await this.invoke ('live/tst/replay.g')).filter (filter).map (x => `live-${x}`);
}

const pat = /^live-([^.]*)$/;
if (! name.match (pat)) return false;

let live = `live/tst/tst-init-${name.match (pat)[1]}`;
await this.update ([ `${live}.out` ]);
await this.invoke ('tst/goal/out.g', { src, environ: `ERS_DATA=../../${live}-data/` });
return true;
