'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'public.h', 'public/impl.h', 'public/common.h', 'public/entry-offsets.h', 'live/live', 'live/live.h' ];

await this.update (srcs);
await env.mkdir ('ers/public/_');
await env.mkdir ('ers/live/_');
await env.run (srcs.map (s => `cp ${s} ers/${s}`).join (' && '));
