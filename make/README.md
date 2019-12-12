# Background

This is here because I can't realize the requirement of the build system for this project by Make. From my view, Make is somewhat broken when facing complicated situation. To name a few, it handles file name matching in two different ways, it's not only inconsistent but also contains the gap between these two ways, meaning it can't handle every situation. It also can't handle the deleted file very well.

This is a replacement of Make for incremental build in a parallel way. It's designed to be simple yet flexible. It's implemented in JavaScript and JavaScript is powerful in making the implementation very concise.

# Usage

The whole build process essentially is traversing the dependant graph, processing the child node first. Here is a very simple example. We put make.js in the top folder, and three source files s1 s2 s3 in the src folder. We want to generate two intermediate files m1 and m2 by concatenating s1, s2 and s2, s3 respectively, and we want to generate the final result f by concatenating m1 and m2. We need a top level script called Goalfile and also provide a script for concatenating called cat.g. Therefore, we will have this tree structure.

```console
[root@ceffa7b358b0 make]# tree
.
|-- make.js
`-- src
    |-- Goalfile
    |-- cat.g
    |-- s1
    |-- s2
    `-- s3

1 directory, 6 files
```

We use this command to build at top folder. The option `-j` is same as Make. We build inside the build folder and the goal is g.

```shell
node make.js -j 4 src build g
```

For each node on the graph, make.js calls Goalfile with the it's name, which I call goal. At the top level in this example, make.js calls Goalfile with goal equals to g. Every configuration script can be view as the body of a JavaScript function, and make.js call this function `fn` in the following way.

```javascript
await fn.apply (this, [ env, goal ].concat (Object.keys (args).map (k => args[k])));
```

The argument `this` provide a convenient way for the script to call builtin functions with context, and `env` provide a set of utilities, and `args` is the additional arguments which will be explained later. The following is the utilities provided by `env`. The implementation is simplified.

```javascript
const env = {
  /* The name stands for default.  */
  def: (v, d, p) => v ? (p ? p (v) : v) : d,
  
  dir: path.dirname,
  base: path.basename,
  join: path.join,
  relative: path.relative,
  norm: p => path.normalize (path.relative ('.', p)),
  
  /* If e is not null, return true if f ends with e, otherwise return the extension of f.  */
  ext: (f, e) => e ? f.endsWith (`.${e}`) : f.split ('.').pop (),
  /* Return true if f ends with any extension in es.  */
  exts: (f, es) => ! es.every (e => ! env.ext (f, e)),
  /* Remove the extension.  */
  trim: s => s.split ('.').slice (0, -1).join ('.'),
  
  /* Split the string by white spaces and remove the line continuation symbol \\.  */
  split: s => s.split (/(\s+)/).filter (x => x.trim () !== '' && x !== '\\'),
  /* Split the string and filter by p, and then join back into the string by space.  */
  filter: (s, p) => env.split (s).map (x => x.match (p)).map (x => x === null ? '' : x[0]).join (' '),
  
  /* Return a set with the element which is in a but not in b.  */
  diff: (a, b) => a.filter (x => ! b.includes (x)),
  
  /* Run a command. Do not print the command if quiet is true and -v is not specified.  */
  run: async (cmd, quiet) => await util.promisify (child_process.exec) (cmd),
  /* Make directory for the file.  */
  mkdir: async file => await env.run (`mkdir -p ${env.dir (file)}`, true),
  /* Read file. When the file doesn't exist, if opt is true, return null, otherwise terminate the build.  */
  read: async (file, opt) => await util.promisify (fs.readFile) (file, 'utf8')
};
```

Now let's take a look at Goalfile. The argument `this` provide two functions `update` and `invoke`, the Goalfile uses both of them.

```javascript
'use strict';

if (new Set ([ 's1', 's2', 's3', 'cat.g' ]).has (env.base (goal))) return false;

if (env.base (goal) === 'm1') await this.invoke ('cat.g', { a: 's1', b: 's2' });
if (env.base (goal) === 'm2') await this.invoke ('cat.g', { a: 's2', b: 's3' });
if (env.base (goal) === 'g') await this.invoke ('cat.g', { a: 'm1', b: 'm2' });
```

Let's start from g. When the Goalfile is called with g, it calls `this.invoke` to call cat.g. You may have already noticed that cat.g is also handled by the Goalfile. This means you can also generate the script in your own way. Here, for cat.g, as well as s1, s2 and s3, the Goalfile returns false, meaning these files need to be copied from the source folder. Returning false is the only way to access the source folder and is the only builtin method to process a node. Except for the source files and the scripts, it's not necessary to have the goal name equals to some generated file.

Let's return back to the script being called. They are called exactly as the Goalfile with `this`, `env`, `goal` except we can specify some additional arguments as the second argument of `this.invoke` in the form of map. The map is expanded into the arguments for each key value pair. Let's take a look at cat.g to see how the arguments can be used.

```javascript
'use strict'

await this.update ([ a, b ]);
await env.run (`cat ${a} ${b} >${goal}`);
```

Here we can use `a`, `b` directly and they represent the dependencies. We call `this.update` first to build or update these dependencies and then we run the real command to generate the goal. When calling `this.invoke`, the update is implicitly done, but if you want to build the script parallelly with other dependencies, you may also specify it in an earlier `this.update`.

Therefore, for g, it updates m1 and m2 first, and similarly for m1 and m2, they update s1, s2 and s3, which are the source files, and then the they call the real concatenation.

The incrementality is done by storing the timestamp for each goal when successfully built, along with the dependencies in a database. The entry is preserved even if the goal is no longer needed, so it can handle the deletion of the source files in a consistent way. You may also specify the files to be treated as outdated by using `-p` option so it will always be built again. For example, you may specify `-p` with the script for running testing to test all the cases no matter if they are outdated.

By running the build command given above, you should see the following output, and the result should be in the build folder.

```console
[root@ceffa7b358b0 make]# node make.js -j 4 src build g
[info] cd build
[note] collecting goal stats...
[info] [0] cat s1 s2 >m1
[info] [1] cat s2 s3 >m2
[info] [2] cat m1 m2 >g
[note] all up-to-date
```

# Limitation

TODO
