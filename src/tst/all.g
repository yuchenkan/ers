'use strict'; /* vim: set ft=javascript: */

let tsts = [ 'rtld', 'live-start', 'live-clone', 'live-clear-tid', 'live-raise', 'live-sigaltstack' ];
tsts = tsts.concat ([ ...Array (6).keys () ].map (x => `live-exit-${x}`));
tsts = tsts.concat ([ 'syscall' ].map (t => `live-entry-${t}`));

await this.update ([ 'tst/loop.sh' ].concat (tsts.map (t => `tst/tst-${t}.out`)));

//await this.update ([ 'tst/tst-live-entry-syscall.out' ]);
