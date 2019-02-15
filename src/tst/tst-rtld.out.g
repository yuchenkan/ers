'use strict'; /* vim: set ft=javascript: */

const script = 'goals/tst/out.g';

await this.update ([ script, 'tst/rtld/recorder' ], async () => {
  await this.invoke (script, { environ: 'ERS_RECORDER=rtld/recorder' });
});
