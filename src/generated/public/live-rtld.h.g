'use strict'; /* vim: set ft=javascript: */

const rtld = goal.replace (/generated\/public\/live-rtld.h$/, 'live-rtld');
await this.update ([ 'live-convert', rtld ]);
await env.run (`./live-convert live-rtld ${rtld} ${goal}`);
