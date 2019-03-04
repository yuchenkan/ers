'use strict'; /* vim: set ft=javascript: */

const header = `${goal.replace (/live$/, 'generated/live.h')}`;
await this.update ([ 'live-convert', `${goal}.so` ]);

await env.mkdir (header);
await env.run (`./live-convert live ${goal}.so ${goal} ${header}`);
