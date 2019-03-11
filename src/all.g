'use strict'; /* vim: set ft=javascript: */

await Promise.all (subs.map (s => this.invoke (`${s}/all.g`)).concat ([ this.update ([ 'dump-record' ]) ]));
