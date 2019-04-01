'use strict'; /* vim: set ft=javascript: */

let tsts = [ 'rtld', 'sig-mask-async-ut' ];
tsts = tsts.concat ([ 'main', 'syscall', 'sync-async', 'atomic', 'atomic-ext', 'sig-action' ].map (x => `sig-hand-${x}-ut`));

let commons = (await this.invoke ('live/tst/replay.g')).concat ([ 'sig-nest', 'signalfd' ]);

let entries = [ 'syscall', 'sync-async', 'sync-async-repeat' ];
entries = entries.concat ([ 'load', 'store', 'inc-dec', 'xchg', 'cmpxchg', 'cmp' ].map (x => `atomic-${x}`));

commons = commons.concat (entries.map (t => `entry-${t}`));

tsts = tsts.concat (commons.map (t => `main-${t}`)).concat (commons.map (t => `init-${t}`));

await this.update ([ 'live/tst/loop.sh' ].concat (tsts.map (t => `live/tst/tst-${t}.out`)));

//await this.update ([ 'tst/tst-live-sig-hand-sig-action-ut.out' ]);
