'use strict'; /* vim: set ft=javascript: */

const convert = 'live/convert';
await this.update ([ convert, `${goal}.so` ]);

await env.run (`./${convert} bin ${goal}.so ${goal}`);
