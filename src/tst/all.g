'use strict'; /* vim: set ft=javascript: */

let tsts = [ 'rtld' ];

let live = [ 'start', 'clone', 'clear-tid', 'raise', 'sig-ignore', 'sig-nest',
	     'sig-exit-group', 'sig-sig-mask', 'sig-sig-prepare-sync',
	     'sigaltstack', 'sigprocmask', 'sigpending', 'sigsuspend', 'sigtimedwait', 'signalfd',
	     'sig-mask-async-ut' ];

live = live.concat ([ 'main', 'syscall', 'sync-async', 'atomic', 'atomic-ext' ].map (x => `sig-hand-${x}-ut`));

live = live.concat ([ ...Array (6).keys () ].map (x => `exit-${x}`));

let entries = [ 'syscall', 'sync-async', 'sync-async-repeat' ];
entries = entries.concat ([ 'load', 'store', 'inc-dec', 'xchg', 'cmpxchg', 'cmp' ].map (x => `atomic-${x}`));

live = live.concat (entries.map (t => `entry-${t}`));

tsts = tsts.concat (live.map (t => `live-${t}`));

await this.update ([ 'tst/loop.sh' ].concat (tsts.map (t => `tst/tst-${t}.out`)));

//await this.update ([ 'tst/tst-live-sig-hand-atomic-ext-ut.out' ]);
