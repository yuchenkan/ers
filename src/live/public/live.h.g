'use strict'; /* vim: set ft=javascript: */

const convert = 'live/convert';
const rtld = goal.replace (/public\/live.h$/, 'rtld');
await this.update ([ convert, rtld ]);
await env.run (`./${convert} header ${rtld} ${goal}`);
