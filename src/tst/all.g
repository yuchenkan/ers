'use strict'; /* vim: set ft=javascript: */

const tsts = [ 'rtld', 'live-start', 'live-clone' ].concat ([ ...Array (6).keys () ].map (x => `live-exit-${x}`))
await this.update ([ 'tst/loop.sh' ].concat (tsts.map (t => `tst/tst-${t}.out`)));

//await this.update ([ 'tst/tst-live-clone.out' ]);
//await this.update ([ 'tst/tst-rtld.out', 'tst/tst-live-start.out' ]);
