'use strict'; /* vim: set ft=javascript: */

const depend = async () => {
  await env.run (`gcc -I . -M -MG -MF ${goal}.d ${src}`);
  const data = await env.read (`${goal}.d`);
  return env.split (data.split (':')[1]).filter (x => x[0] !== '/');
}

let deps = await depend ();
await this.update (deps);

while (true) {
  let diff = env.diff (await depend (), deps);
  if (! diff.length) return;
  await this.update (diff);
  deps = deps.concat (diff);
}
