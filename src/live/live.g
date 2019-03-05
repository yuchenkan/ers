'use strict'; /* vim: set ft=javascript: */

const convert = 'live/convert';
const header = `${goal.replace (/live$/, 'live-bin.h')}`;
await this.update ([ convert, `${goal}.so` ]);

await env.run (`./${convert} bin ${goal}.so ${goal} ${header}`);
