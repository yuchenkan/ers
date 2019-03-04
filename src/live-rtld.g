'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${goal}.l` ];
const script = `${env.base (goal)}.ld`;
const ldflags = f => `${f} -pie -Wl,-Map,${goal}.map -Wl,-T,${script} -Wl,-e,eri_start -Wl,--gc-sections -Wl,-N`;

const post = async () => {
  await env.run (`objcopy -R .eh_frame -R .eh_frame_hdr -R .note.gnu.build-id -R .dynsym `
		+ `-R .dynstr -R .gnu.hash -R .rela.dyn -R .dynamic -R .got -R .got.plt ${goal}`);
}

await this.invoke ('goal/link.g', { srcs, extra : [ script ], ldflags, post });
