'use strict'; /* vim: set ft=javascript: */

const rtld = goal.replace (/generated\/public\/rtld.h$/, 'rtld');
await this.update ([ 'rtld-convert', rtld ]);
await env.run (`./rtld-convert rtld ${rtld} ${goal}`);
