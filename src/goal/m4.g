'use strict'; /* vim: set ft=javascript: */

const src = `${goal}.m4`;
const depend = async (diff) => {
  const inc = /\bm4_include\(`([^']*)'\)/;
  const deps = await Promise.all (diff.map (d => (async () => {
    let data = await env.read (d);
    return env.def (data.match (new RegExp (inc.source, 'g')), [ ]).map (i => i.match (inc)[1]);
  }) ()));
  return Array.from (new Set (deps.reduce ((a, c) => a.concat (c), [ ])));
}

await this.invoke ('goal/depend.g', { src, depend });
await env.run (`m4 -E -P ${src} >${goal}`);
