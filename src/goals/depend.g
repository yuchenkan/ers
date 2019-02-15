'use strict'; /* vim: set ft=javascript: */

const src = env.trim (goal);

do {
  let data = await env.read (goal, true);
  /* XXX x => x[0] !== '/' is too weak to determine if file is inside src directory */
  var opts = data != null ? env.split (`${data}`.split (':')[1]).filter (x => x[0] !== '/') : [ ];
} while (await this.update ([ src ].concat (opts), async () => {
    await env.run (`gcc -I . -M -MG -MF ${goal} ${src}`);
    return true;
  }, opts));
