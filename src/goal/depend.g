'use strict'; /* vim: set ft=javascript: */

let deps = [ ];
let diff = [ src ];

while (diff.length) {
  await this.update (diff);
  deps = deps.concat (diff);
  diff = env.diff (await depend (diff), deps);
}
