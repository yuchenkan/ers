/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/lock.h>
#include <lib/rbtree.h>
#include <lib/malloc.h>

#include <common/thread.h>

#include <analysis/xed.gen/xed-util.h>
#include <analysis/xed.gen/xed-interface.h>

#include <analysis/analyzer.h>

enum reg_loc_tag
{
  REG_LOC_REG,
  REG_LOC_LOCAL,
  REG_LOC_IMM
};

struct reg_loc
{
  enum reg_loc_tag tag;
  uint64_t val;
};

struct trace_reg
{
  uint64_t rip_off;
  uint8_t reg_idx;
  struct reg_loc loc;
};

enum
{
  /* XXX: depands on the order of ERI_FOREACH_REG */
#define DEF_REG_IDX(creg, reg)	ERI_PASTE (REG_IDX_, creg),
  ERI_FOREACH_REG (DEF_REG_IDX)
  REG_NUM,
  GPREG_NUM = REG_RFLAGS
};

struct block
{
  uint8_t *insts;
  uint64_t insts_len;

  struct trace_reg *trace_regs;
  uint64_t ntrace_regs;

  uint64_t final_locs[REG_NUM];
  struct eri_siginfo sig_info;

  uint64_t local_size;

  eri_aligned16 uint8_t buf[0];
};

struct trans_key
{
  uint64_t rip;
  uint8_t tf;
};

struct trans
{
  struct trans_key key;

  uint64_t ref_count;

  struct block *block;
  uint64_t wait;
  uint8_t done;
};

struct active
{
  struct eri_analyzer *al;
  struct trans *trans;
  uint64_t stack;
  uint64_t local[0];
};

struct eri_analyzer_group
{
  struct eri_mtpool *pool;
  struct eri_range *map_range;

  uint64_t page_size;
  uint32_t max_inst_count;

  int32_t *pid;

  struct eri_lock trans_lock;
  ERI_RBT_TREE_FIELDS (trans, struct trans)
};

static uint8_t
trans_key_less_than (struct eri_analyzer_group *g,
		     struct trans_key *k1, struct trans_key *k2)
{
  return k1->rip == k2->rip ? k1->tf < k2->tf : k1->rip < k2->rip;
}

ERI_DEFINE_RBTREE (static, trans, struct eri_analyzer_group,
		   struct trans, struct trans_key, trans_key_less_than)

struct eri_analyzer
{
  struct eri_analyzer_group *group;

  struct eri_entry *entry;
  int32_t *tid;

  struct eri_siginfo *sig_info;

  struct active *act;
};

struct eri_analyzer_group *
eri_analyzer_group__create (struct eri_analyzer_group__create_args *args)
{
  struct eri_analyzer_group *group
			= eri_assert_mtmalloc (args->pool, sizeof *group);
  group->pool = args->pool;
  group->map_range = args->map_range;
  group->page_size = args->page_size;
  group->max_inst_count = args->max_inst_count;
  group->pid = args->pid;
  eri_init_lock (&group->trans_lock, 0);
  ERI_RBT_INIT_TREE (trans, group);
  return group;
}

void
eri_analyzer_group__destroy (struct eri_analyzer_group *group)
{
  struct trans *t, *nt;
  ERI_RBT_FOREACH_SAFE (trans, group, t, nt)
    {
      trans_rbt_remove (group, t);
      eri_assert (t->ref_count == 0);
      eri_assert_mtfree (group->pool, t->block);
      eri_assert_mtfree (group->pool, t);
    }
  eri_assert_mtfree (group->pool, group);
}

struct eri_analyzer *
eri_analyzer__create (struct eri_analyzer__create_args *args)
{
  struct eri_analyzer_group *group = args->group;
  struct eri_analyzer *al = eri_assert_mtmalloc (group->pool, sizeof *al);
  al->group = group;
  al->entry = args->entry;
  al->tid = args->tid;
  al->sig_info = 0;
  al->act = 0;
  return al;
}

void
eri_analyzer__destroy (struct eri_analyzer *al)
{
  eri_assert_mtfree (al->group->pool, al);
}

#define INST_BYTES	XED_MAX_INSTRUCTION_BYTES

struct ir_node;
struct ir_def;

struct ir_def_pair
{
  struct ir_def *first, *second;
};

struct ir_local;

struct ir_host_locs
{
  uint32_t host_idxs;
  struct ir_local *local;
};

struct ir_def
{
  struct ir_node *node;

  uint64_t ridx;
  struct ir_host_locs locs;
};

struct ir_dep
{
  struct ir_def *def;
  uint64_t ridx;

  ERI_RBT_NODE_FIELDS (ir_dep)
};

struct ir_inst_reg
{
  struct ir_dep src;
  struct ir_def dst;

  const xed_operand_t *op;
};

struct ir_mem_regs
{
  struct ir_dep base;
  struct ir_dep index;
};

struct ir_inst_mem
{
  struct ir_mem_regs regs;
  const xed_operand_t *op;
};

struct ir_mem_args
{
  struct ir_def *base, *index;
  xed_reg_enum_t seg;
  xed_uint_t scale;
  xed_int64_t disp;
  uint32_t size;
  uint8_t addr;
};

struct ir_mem
{
  struct ir_mem_regs regs;
  xed_reg_enum_t seg;
  xed_uint_t scale;
  xed_int64_t disp;

  uint32_t size;
  uint8_t addr;
};

#define IR_NODE_TAGS(p, ...) \
  p (INST, inst, ##__VA_ARGS__)						\
  p (INST_NOP, inst_nop, ##__VA_ARGS__)					\
  p (INIT, init, ##__VA_ARGS__)						\
  p (END, end, ##__VA_ARGS__)						\
  p (ERR_END, err_end, ##__VA_ARGS__)					\
  p (STORE, store, ##__VA_ARGS__)					\
  p (LOAD, load, ##__VA_ARGS__)						\
  p (LOAD_IMM, load_imm, ##__VA_ARGS__)					\
  p (ZDECL, zdecl, ##__VA_ARGS__)					\
  p (DEC, dec, ##__VA_ARGS__)						\
  p (ADD, add, ##__VA_ARGS__)						\
  p (COND_BRANCH, cond_branch, ##__VA_ARGS__)				\

enum ir_node_tag
{
#define DEF_TAG(ctag, tag)	ERI_PASTE (IR_, tag),
  IR_NODE_TAGS (DEF_TAG)
};

struct ir_node
{
  enum ir_node_tag tag;

  struct ir_def seq;

  ERI_RBT_TREE_FIELDS (ir_dep)
  uint64_t deps;

  uint64_t sups;
  ERI_LST_NODE_FIELDS (ir_flat)

  union
    {
      struct
	{
	  xed_decoded_inst_t dec;
	  uint64_t rip;

	  struct ir_inst_reg regs[12];
	  struct ir_inst_mem mems[2];
	  uint8_t access_mem;
	  uint8_t relbr;

	  struct ir_dep memory;
	  struct ir_dep prev;
	} inst;
      struct
	{
	  struct ir_def regs[REG_NUM];
	  uint64_t rip;
	} init;
      struct
	{
	  struct ir_dep regs[REG_NUM];
	  struct ir_dep memory;
	  struct ir_dep prev;

	  struct eri_siginfo sig_info;
	  uint8_t len;
	  uint8_t bytes[INST_BYTES];
	} end;
      struct
	{
	  struct ir_mem dst;
	  struct ir_dep src;
	  struct ir_dep memory;
	} store;
      struct
	{
	  struct ir_def dst;
	  struct ir_mem src;
	  struct ir_dep prim;
	  struct ir_dep memory;
	} load;
      struct
	{
	  struct ir_def dst;
	  uint64_t src;
	} load_imm;
      struct
	{
	  struct ir_def dst;
	  struct ir_dep srcs[2];
	} bin;
      struct
	{
	  xed_iclass_enum_t iclass;
	  uint8_t addr;
	  struct ir_def dst;
	  struct ir_def dec;
	  struct ir_dep flags;
	  struct ir_dep cnt;
	  struct ir_dep taken;
	  struct ir_dep fall;
	} cond_branch;
    };
};

static uint8_t
ir_dep_less_than (struct ir_node *n, struct ir_dep *d1, struct ir_dep *d2)
{
  uint64_t n1 = d1->def->node->deps;
  uint64_t n2 = d2->def->node->deps;
  return n1 == n2 ? d1 < d2 : n1 < n2;
}

ERI_DEFINE_RBTREE1 (static, ir_dep, struct ir_node, struct ir_dep,
		    ir_dep_less_than)

struct ir_redun_node
{
  ERI_LST_NODE_FIELDS (ir_redun_node)
  void *tag;
  eri_aligned16 uint8_t buf[0];
};

struct ir_redun
{
  uint64_t key;
  ERI_LST_LIST_FIELDS (ir_redun_node)

  ERI_RBT_NODE_FIELDS (ir_redun)
};

ERI_DEFINE_LIST (static, ir_redun_node, struct ir_redun, struct ir_redun_node)

struct ir_alloc
{
  ERI_LST_NODE_FIELDS (ir_alloc)
  eri_aligned16 uint8_t buf[0];
};

struct ir_dag
{
  struct eri_mtpool *pool;

  struct ir_def reg_defs[REG_NUM];

  ERI_LST_LIST_FIELDS (ir_alloc)

  ERI_RBT_TREE_FIELDS (ir_redun)

  struct ir_def *init;
  struct ir_def *memory;
  struct ir_def *prev;
  struct ir_def *last;
};

ERI_DEFINE_LIST (static, ir_alloc, struct ir_dag, struct ir_alloc)
ERI_DEFINE_RBTREE (static, ir_redun, struct ir_dag,
		   struct ir_redun, uint64_t, eri_less_than)

struct ir_local
{
  uint64_t idx;
  ERI_RBT_NODE_FIELDS (ir_local)
};

struct ir_reg_def_loc
{
  struct ir_def *def;
  struct reg_loc loc;
};

struct ir_flattened
{
  struct ir_dag *dag;
  struct ir_def local;
  struct ir_def dummy;

  uint64_t ridx;
  ERI_LST_LIST_FIELDS (ir_flat)

  struct ir_def *hosts[REG_NUM];

  uint64_t local_size;
  ERI_RBT_TREE_FIELDS (ir_local)

  struct ir_reg_def_loc reg_def_locs[REG_NUM];
};

ERI_DEFINE_LIST (static, ir_flat, struct ir_flattened, struct ir_node)
ERI_DEFINE_RBTREE (static, ir_local, struct ir_flattened,
		   struct ir_local, uint64_t, eri_less_than)

struct ir_block
{
  struct eri_buf insts;
  struct eri_buf trace_regs;

  uint64_t final_locs[REG_NUM];
  struct eri_siginfo sig_info;

  uint64_t local_size;
};

static uint8_t
ir_reg_idx_from_reg_opt (xed_reg_enum_t reg)
{
  switch (xed_get_largest_enclosing_register (reg))
    {
#define CONV_XED_REG(creg, reg) \
  case ERI_PASTE (XED_REG_, creg): return ERI_PASTE (REG_IDX_, creg);
    ERI_FOREACH_REG (CONV_XED_REG)
    default: return REG_NUM;
    }
}

static uint8_t
ir_reg_idx_from_reg (xed_reg_enum_t reg)
{
  uint8_t reg_idx = ir_reg_idx_from_reg_opt (reg);
  eri_assert (reg_idx != REG_NUM);
  return reg_idx;
}

static xed_reg_enum_t
ir_reg_from_reg_idx_opt (uint8_t reg_idx, uint8_t size)
{
  switch (reg_idx)
    {
#define CONV_REG_IDX(creg, reg) \
  case ERI_PASTE (REG_IDX_, creg):					\
    if (size == 1)							\
      return ERI_PASTE (XED_REG_, ERI_PASTE (ERI_C, creg) (b));		\
    else if (size == 2)							\
      return ERI_PASTE (XED_REG_, ERI_PASTE (ERI_C, creg) (w));		\
    else if (size == 4)							\
      return ERI_PASTE (XED_REG_, ERI_PASTE (ERI_C, creg) (l));		\
    else if (size == 8)							\
      return ERI_PASTE (XED_REG_, ERI_PASTE (ERI_C, creg) (q));		\
    else return XED_REG_INVALID;

    ERI_FOREACH_GPREG (CONV_REG_IDX)
    case REG_IDX_RFLAGS:
      if (size == 2) return XED_REG_FLAGS;
      else if (size == 4) return XED_REG_EFLAGS;
      else if (size == 8) return XED_REG_RFLAGS;
      else return XED_REG_INVALID;
    case REG_IDX_RIP:
      if (size == 2) return XED_REG_IP;
      else if (size == 4) return XED_REG_EIP;
      else if (size == 8) return XED_REG_RIP;
      else return XED_REG_INVALID;
    default: return XED_REG_INVALID;
    }
}

static xed_reg_enum_t
ir_reg_from_reg_idx (uint8_t reg_idx, uint8_t size)
{
  xed_reg_enum_t reg = ir_reg_from_reg_idx_opt (reg_idx, size);
  eri_assert (reg != XED_REG_INVALID);
  return reg;
}

static void
ir_host_idxs_add (uint32_t *host_idxs, uint8_t host_idx)
{
  *host_idxs |= 1 << host_idx;
}

static void
ir_host_idxs_del (uint32_t *host_idxs, uint8_t host_idx)
{
  *host_idxs &= ~(1 << host_idx);
}

static uint8_t
ir_host_idxs_set (uint32_t host_idxs, uint8_t host_idx)
{
  return host_idxs & (1 << host_idx);
}

static uint8_t
ir_host_idxs_gpreg_num (uint32_t host_idxs)
{
  uint32_t g = host_idxs & ((1 << GPREG_NUM) - 1);
  /* https://stackoverflow.com/questions/109023/ */
  g = g - ((g >> 1) & 0x55555555);
  g = (g & 0x33333333) + ((g >> 2) & 0x33333333);
  return (((g + (g >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

static uint8_t
ir_host_idxs_get_reg_idx (uint32_t host_idxs)
{
  uint32_t g = host_idxs & ((1 << REG_NUM) - 1);
  return (__builtin_ffs (g) ? : REG_NUM + 1) - 1;
}

static uint8_t
ir_host_idxs_get_gpreg_idx (uint32_t host_idxs)
{
  uint32_t g = host_idxs & ((1 << GPREG_NUM) - 1);
  return (__builtin_ffs (g) ? : REG_NUM + 1) - 1;
}

static void *p
ir_alloc (struct ir_dag *dag, uint64_t size)
{
  struct ir_alloc *a = eri_assert_mtmalloc (dag->pool, size + sizeof *a);
  ir_alloc_append (dag, a);
  return a->buf;
}

static struct ir_def *
ir_define (struct ir_node *node, struct ir_def *def)
{
  def->node = node;
  def->ridx = 0;
  def->locs.host_idxs = 0;
  def->locs.local = 0;
  def->flags = 0;
  return def;
}

static void
ir_depand (struct ir_node *node, struct ir_dep *dep, struct ir_def *def)
{
  dep->def = def;
  if (! def) return;

  def->ridx = 0;
  ir_dep_rbt_insert (node, dep);
  node->deps = eri_max (node->deps, def->node->deps);
}

static struct ir_node *
ir_alloc_node (struct ir_dag *dag, enum ir_node_tag tag, uint64_t deps)
{
  struct ir_node *node = ir_alloc (dag, sizeof *node);
  node->tag = tag;
  ir_define (node, &node->seq);
  ERI_RBT_INIT_TREE (ir_dep, node);
  node->deps = deps;
  node->sups = 0;
  return node;
}

static struct ir_def *
ir_get_reg_def (struct ir_dag *dag, xed_reg_enum_t reg)
{
  return dag->reg_defs[ir_reg_idx_from_reg_opt (reg)];
}

static struct ir_def *
ir_get_reg_def_opt (struct ir_dag *dag, xed_reg_enum_t reg)
{
  return reg == XED_REG_INVALID ? 0 : ir_get_reg_def (dag, reg);
}

static void
ir_set_reg_def (struct ir_dag *dag, xed_reg_enum_t reg, struct ir_def *def)
{
  dag->reg_defs[ir_reg_idx_from_reg (reg)] = def;
}

static void
ir_copy_reg_def (struct ir_dag *dag, xed_reg_enum_t dst, xed_reg_enum_t src)
{
  ir_set_reg_def (dag, dst, ir_get_reg_def (dag, src));
}

static void
ir_access_mem (struct ir_dag *dag, struct ir_node *node, struct ir_dep *mem)
{
  ir_depand (node, mem, dag->memory);
  dag->memory = &node->seq;
}

static void
ir_do_end (struct ir_dag *dag, struct ir_node *node, enum ir_node_tag tag)
{
  if (! node) node = ir_alloc_node (dag, tag, 0);
  else
    {
      node->tag = tag;
      node->deps = 0;
      struct ir_dep *dep;
      while ((dep = ir_dep_rbt_get_first (node)))
	ir_dep_rbt_remove (node, dep);
    }

#define DEP_REG(creg, reg) \
  ir_depand (node, node->end.regs + ERI_PASTE (REG_IDX_, creg),	\
	     ir_get_reg_def (dag, ERI_PASTE (XED_REG_, creg)));
  ERI_FOREACH_REG (DEP_REG)

  ir_depand (node, &node->end.memory, dag->memory);
  ir_depand (node, &node->end.prev, dag->prev);
  dag->last = &node->seq;
}

static void
ir_end (struct ir_dag *dag, struct ir_node *node)
{
  ir_do_end (dag, node, IR_END);
}

static void
ir_err_end (struct ir_dag *dag, struct ir_node *node,
	    struct eri_siginfo *info, uint8_t len, uint8_t *bytes)
{
  ir_do_end (dag, node, IR_ERR_END);  

  if (info) node->end.sig_info = *info;
  else node->end.sig_info.sig = 0;
  node->end.len = len;
  if (bytes) eri_memcpy (node->end.bytes, bytes, len);
}

static uint64_t
ir_init_mem (struct ir_node *node, struct ir_mem *mem,
	     struct ir_mem_args *args)
{
  /* XXX: fold const */
  ir_depand (node, &mem->regs.base, args->base);
  ir_depand (node, &mem->regs.index, args->index);
  mem->seg = args->seg;
  mem->scale = args->scale;
  mem->disp = args->disp;
  mem->size = args->size;
  mem->addr = args->addr;
  return !! base + !! index;
}

static void
ir_create_store (struct ir_dag *dag,
		 struct ir_mem_args *dst, struct ir_def *src)
{
  struct ir_node *node = ir_alloc_node (dag, IR_STORE, 1);
  node->deps += ir_init_mem (mode, &node->store.dst, dst);
  ir_depand (node, &node->store.src, src);
  ir_access_mem (dag, node, &node->store.memory);
}

static struct ir_def *
ir_create_load (struct ir_dag *dag,
		struct ir_mem_args *src, struct ir_def *prim)
{
  struct ir_node *node = ir_alloc_node (dag, IR_LOAD, prim ? 2 : 1);
  node->deps += ir_init_mem (mode, &node->load.src, src);
  ir_depand (node, &node->load.prim, prim);
  ir_access_mem (dag, node, &node->load.memory);
  return ir_define (node, &node->load.dst);
}

static struct ir_def *
ir_create_binary (struct ir_dag *dag, enum ir_node_tag tag,
		  struct ir_def_pair *srcs)
{
  struct ir_node *node = ir_alloc_node (dag, tag, 3);
  ir_depand (node, node->bin.srcs, srcs->first);
  ir_depand (node, node->bin.srcs + 1, srcs->second);
  return ir_define (node, &node->bin.dst);
}

#define ir_eval(dag, type, tag, args) \
  ({									\
    struct ir_dag *_dag = dag;						\
    typeof (args) _args = args;						\
    uint64_t _key = ERI_PASTE (ir_hash_, tag) (				\
			eri_hash (ERI_PASTE (ir_eval_, tag)), _args);	\
    struct ir_redun_node *_re;						\
    struct ir_redun *_res = ir_redun_rbt_get (_dag, _key, ERI_RBT_EQ);	\
    if (! _res)								\
      {									\
	_res = ir_alloc (_dag, sizeof *_res);				\
	_res->key = _key;						\
	ERI_LST_INIT_LIST (ir_redun_node, _res);			\
	ir_redun_rbt_insert (_dag, _res);				\
      }									\
    else								\
      {									\
	ERI_LST_FOREACH (ir_redun_node, _res, _re)			\
	  if (_re->tag == ERI_PASTE (ir_eval_, tag)			\
	      && ERI_PASTE (ir_redun_, tag) ((void *) _re->buf, _args))	\
	    goto _ret;							\
      }									\
    _re = ir_alloc (_dag,						\
	sizeof *_re + eri_sizeof (*_args, 16) + sizeof (type));		\
    _re->tag = ERI_PASTE (ir_eval_, tag);				\
    *(typeof (_args)) _re->buf = *_args;				\
    *(type *) (_re->buf + eri_size_of (typeof (_args), 16))		\
			= ERI_PASTE (ir_eval_, tag) (_dag, _args); 	\
    ir_redun_node_lst_append (_res, _re);				\
  _ret:									\
    *(type *) (_re->buf + eri_size_of (typeof (_args), 16));		\
  })

#define ir_hash_scalar(k, a)	eri_hashs1 (k, *(a))
#define ir_redun_scalar(a1, a2)	(*(a1) == *(a2))

static uint64_t
ir_hash_def_pair (uint64_t key, struct ir_def_pair *args)
{
  return ir_hashs1 (key, args->first, args->second);
}

static uint8_t
ir_redun_def_pair (struct ir_def_pair *a1, struct ir_def_pair *a2)
{
  return a1->first == a2->first && a1->second == a2->second;
}

#define ir_hash_load_imm(k, a)		ir_hash_scalar (k, a)
#define ir_redun_load_imm(a1, a2)	ir_redun_scalar (a1, a2)

static struct ir_def * 
ir_eval_load_imm (struct ir_dag *dag, uint64_t *args)
{
  struct ir_node *node = ir_alloc_node (dag, IR_LOAD_IMM, 1);
  node->load_imm.src = *args;
  return ir_define (node, &node->load_imm.dst);
}

static struct ir_def *
ir_get_load_imm (struct ir_dag *dag, uint64_t imm)
{
  return ir_eval (dag, struct ir_def *, load_imm, &imm);
}

#define ir_hash_add(k, a)	ir_hash_def_pair (k, a)
#define ir_redun_add(a1, a2)	ir_redun_def_pair (a1, a2)

static struct ir_def *
ir_eval_add (struct ir_dag *dag, struct ir_def_pair *args)
{
  struct ir_node *a = args->first.node;
  struct ir_node *b = args->second.node;
  if (a->tag == IR_LOAD_IMM && b->tag == IR_LOAD_IMM)
    return ir_get_load_imm (dag, a->load_imm.src + b->load_imm.src);
  else if (a->tag == IR_LOAD_IMM && a->load_imm.src == 0)
    return args->second;
  else if (b->tag == IR_LOAD_IMM && b->load_imm.src == 0)
    return args->first;
  return ir_create_binary (dag, IR_ADD, args);
}

static struct ir_def *
ir_get_add (struct ir_dag *dag, struct ir_def *a, struct ir_def *b)
{
  struct ir_def_pair args = { a, b };
  return ir_eval (dag, struct ir_def *, add, &args);
}

struct ir_cond_branch_args
{
  xed_iclass_enum_t iclass;
  uint8_t addr;
  struct ir_def *flags, *cnt, *taken, *fall;
};

#define ir_cond_branch_loop(iclass) \
  ({ xed_iclass_enum_t *_iclass = iclass;				\
     _iclass == XED_ICLASS_LOOP || _iclass == XED_ICLASS_LOOPE		\
     || _iclass == XED_ICLASS_LOOPNE; })
#define ir_cond_branch_cnt_only(iclass) \
  ({ xed_iclass_enum_t *_iclass = iclass;				\
     _iclass == XED_ICLASS_JECXZ || _iclass == XED_ICLASS_JRCXZ		\
     || _iclass == XED_ICLASS_LOOP; })
#define ir_cond_branch_flags_cnt(iclass) \
  ({ xed_iclass_enum_t *_iclass = iclass;				\
     _iclass == XED_ICLASS_LOOPE || _iclass == XED_ICLASS_LOOPNE; })	\
#define ir_cond_branch_flags_only(iclass) \
  (! ir_cond_branch_cnt_only (iclass) && ! ir_cond_branch_flags_cnt (iclass))

static uint64_t
ir_hash_cond_branch (struct ir_cond_branch_args *args)
{
  xed_iclass_enum_t iclass = args->iclass;
  uint64_t key = eri_hashs (IR_COND_BRANCH, iclass);

  if (ir_cond_branch_loop (iclass))
    key = eri_hashs1 (key, args->addr);

  if (ir_cond_branch_cnt_only (iclass))
    key = eri_hashs1 (key, args->cnt);
  else if (ir_cond_branch_flags_cnt (iclass))
    key = eri_hashs1 (key, args->flags, args->cnt);
  else
    key = eri_hashs1 (key, args->flags);
  return eri_hashs1 (key, args->taken, args->fall);
}

static uint8_t
ir_redun_cond_branch (struct ir_cond_branch_args *a1,
		      struct ir_cond_branch_args *a2)
{
  if (a1->iclass != a2->iclass
      || a1->taken != a2->taken || a1->fall != a2->fall) return 0;
  if (ir_cond_branch_loop (iclass) && a1->addr != a2->addr) return 0;
  if (ir_cond_branch_cnt_only (a1->iclass))
    return a1->cnt == a2->cnt;
  else if (ir_cond_branch_flags_cnt (a1->iclass))
    return a1->flags == a2->flags && a1->cnt == a2->cnt;
  else return a1->flags == a2->flags;
}

static uint8_t
ir_cond_flags_taken (uint64_t flags, xed_iclass_enum_t iclass)
{
  xed_flag_set_t f = { .flag = flags };
  switch (iclass)
    {
    case XED_ICLASS_JB: return f.cf;
    case XED_ICLASS_JBE: return f.cf || f.zf;
    case XED_ICLASS_JL: return f.sf != f.of;
    case XED_ICLASS_JLE: return f.zf || f.sf != f.of;
    case XED_ICLASS_JNB: return ! f.cf;
    case XED_ICLASS_JNBE: return ! f.cf || ! f.zf;
    case XED_ICLASS_JNL: return f.sf == f.of;
    case XED_ICLASS_JNLE: return f.zf && f.sf == f.of;
    case XED_ICLASS_JNO: return ! f.of;
    case XED_ICLASS_JNP: return ! f.pf;
    case XED_ICLASS_JNS: return ! f.sf;
    case XED_ICLASS_JNZ: return ! f.zf;
    case XED_ICLASS_JO: return f.of;
    case XED_ICLASS_JP: return f.pf;
    case XED_ICLASS_JS: return f.sf;
    case XED_ICLASS_JZ: return f.zf;
    default: eri_assert_unreachable ();
    }
}

static struct ir_def_pair
ir_eval_cond_branch (struct ir_dag *dag, struct ir_cond_branch_args *args)
{
  xed_iclass_enum_t iclass = args->iclass;
  uint8_t addr = args->addr;
  struct ir_def *flags = args->flags;
  struct ir_def *cnt = args->cnt;
  struct ir_def *taken = args->taken;
  struct ir_def *fall = args->fall;

  struct ir_def_pair pair = { 0 };
  if (ir_cond_branch_cnt_only (iclass))
    {
      if (cnt->node->tag == IR_LOAD_IMM)
	{
	  uint64_t icnt = cnt->node->load_imm.src;
	  if (iclass == XED_ICLASS_JECXZ)
	    pair.first = ! (uint32_t) icnt ? taken : fall;
	  else if (iclass == XED_ICLASS_JRCXZ)
	    pair.first = ! icnt ? taken : fall;
	  else
	    pair.first = icnt ? taken : fall;

	  if (iclass == XED_ICLASS_LOOP)
	    pair.second = ir_get_load_imm (dag,
				addr == 4 ? (uint32_t) icnt - 1 : icnt - 1);
	  return pair;
	}
    }
  else if (ir_cond_branch_flags_cnt (iclass))
    {
      if (cnt->node->tag == IR_LOAD_IMM && flags->node->tag == IR_LOAD_IMM)
	{
	  uint64_t iflags = flags->node->load_imm.src;
	  uint64_t icnt = cnt->node->load_imm.src;
	  pair.first = icnt && ir_cond_flags_taken (iflags,
		iclass == XED_ICLASS_LOOPE ? XED_ICLASS_JZ : XED_ICLASS_JNZ)
			: taken : fall;
	  pair.second = ir_get_load_imm (dag,
				addr == 4 ? (uint32_t) icnt - 1 : icnt - 1);
	}
	return pair;
    }
  else
    {
      if (flags->node->tag == IR_LOAD_IMM)
	{
	  uint64_t iflags = flags->node->load_imm.src;
	  pair.first = ir_cond_flags_taken (flags, iclass) ? taken : fall;
	  return pair;
	}
    }

  /* XXX: no short-circuit evaluation */
  struct ir_node *node = ir_alloc_node (dag, IR_COND_BRANCH, 5);
  node->cond_branch.iclass = iclass;
  node->cond_branch.addr = addr;
  ir_define (node, &node->cond_branch.dst);
  pair.first = &node->cond_branch.dst;
  if (ir_cond_branch_loop (iclass))
    {
      ir_define (node, &node->cond_branch.dec);
      pair.second = &node->cond_branch.dec;
    }
  ir_depand (node, &node->cond_branch.cnt,
	     ! ir_cond_branch_flags_only (iclass) ? cnt : 0);
  ir_depand (node, &node->cond_branch.flags,
	     ! ir_cond_branch_cnt_only (iclass) ? flags : 0);
  ir_depand (node, &node->cond_branch.taken, taken);
  ir_depand (node, &node->cond_branch.fall, fall);
  return pair;
}

static struct ir_def_pair
ir_get_cond_branch (struct ir_dag *dag, struct ir_cond_branch_args *args)
{
  return ir_eval (dag, struct ir_def_pair, cond, args);
}

static struct ir_def *
ir_create_push (struct ir_dag *dag,
		struct ir_def *rsp, struct ir_def *src, uint8_t size)
{
  rsp = ir_get_add (dag, rsp, ir_get_load_imm (dag, -size));
  struct ir_mem_args dst = { rsp, 0, XED_REG_INVALID, 1, 0, size, 8 };
  ir_create_store (dag, &dst, src);
  return rsp;
}

static struct ir_def_pair
ir_create_pop (struct ir_dag *dag, struct ir_def *rsp, struct ir_def *prim)
{
  uint8_t size = prim ? 2 : 8;
  struct ir_mem_args src = { rsp, 0, XED_REG_INVALID, 1, 0, size, 8 };
  struct ir_def_pair pair = {
    ir_create_load (dag, &src, prim),
    ir_get_add (dag, rsp, ir_get_load_imm (dag, size))
  };
  return pair;
}

static uint8_t
ir_decode (struct eri_analyzer *al, struct ir_dag *dag, struct ir_node *node,
	   uint64_t rip, uint8_t len)
{
  uint8_t bytes[INST_BYTES];
  struct eri_siginfo info;
  eri_atomic_store (&al->sig_info, &info, 1);
  if (! eri_entry__copy_from (al->entry, bytes, (void *) rip, len))
    {
      ir_err_end (dag, node, &info, len, 0);
      return 1;
    }
  eri_atomic_store (&al->sig_info, 0, 1);

  xed_decoded_inst_t *dec = &node->inst.dec;
  xed_decoded_inst_zero (dec);
  xed_decoded_inst_set_mode (dec, XED_MACHINE_MODE_LONG_64,
			     XED_ADDRESS_WIDTH_64b);
  xed_error_enum_t err = xed_decode (dec, bytes, len);
  if (err == XED_ERROR_BUFFER_TOO_SHORT) return 0;

  if (err != XED_ERROR_NONE)
    ir_err_end (dag, node, 0, len, bytes);
  else
    node->inst.rip = rip + xed_decoded_inst_get_length (dec);
  return 1;
}

static struct ir_node *
ir_create_inst (struct eri_analyzer *al, struct ir_dag *dag, uint64_t rip)
{
  struct ir_node *node = ir_alloc_node (dag, IR_INST, 0);

  uint64_t page = al->group->page_size;
  uint8_t len = eri_min (eri_round_up (rip + 1, page) - rip, INST_BYTES);
  if (! ir_decode (al, dag, node, rip, len))
    ir_decode (al, dag, node, rip, INST_BYTES);

  if (node->tag == IR_ERR_END)
    {
      dag->last = &node->seq;
      return 0;
    }

  return node;
}

static void
ir_set_rip_from_inst (struct ir_dag *dag, struct ir_node *inst)
{
  ir_set_reg_def (dag, XED_REG_RIP, ir_get_load_imm (inst->inst.rip));
}

static void
ir_init_inst_operands (struct ir_node *node)
{
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i) node->inst.regs[i].op = 0;
  node->inst.mems[0].op = 0;
  node->inst.mems[1].op = 0;
  node->inst.access_mem = 0;
  node->inst.relbr = 0;
}

static uint64_t
ir_build_inst_mem_operand (struct ir_dag *dag, struct ir_node *node,
			   xed_decoded_inst_t *dec, const xed_operand_t *op)
{
  xed_operand_enum_t op_name = xed_operand_name (op);
  uint8_t i = op_name == XED_OPERAND_MEM1;
  struct ir_inst_mem *m = node->inst.mems + i;
  xed_reg_enum_t base = xed_decoded_inst_get_base_reg (dec, i);
  xed_reg_enum_t index = xed_decoded_inst_get_base_reg (dec, i);

  if (base == XED_REG_RIP) ir_set_rip_from_inst (dag, node);

  ir_depand (node, &m->regs.base, ir_get_reg_def_opt (dag, base));
  ir_depand (node, &m->regs.index, ir_get_reg_def_opt (dag, index));
  m->op = op;

  if (op_name != XED_OPERAND_AGEN) node->inst.access_mem = 1;
  return !! m->regs.base.def + !! m->regs.index.def;
}

static uint8_t
ir_inst_op_read (xed_decoded_inst_t *dec, const xed_operand_t *op)
{
  xed_operand_enum_t op_name = xed_operand_name (op);
  xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
  return xed_operand_read (op) || xed_get_register_width_bits (reg) < 32;
}

static void
ir_build_inst_operands (struct ir_dag *dag, struct ir_node *node)
{
  xed_decoded_inst_t *dec = &node->inst.dec;
  const xed_inst_t *inst = xed_decoded_inst_inst (dec);

  ir_init_inst_operands (node);

  uint64_t deps = 0;
  struct ir_inst_reg *inst_reg = node->inst.regs;
  uint8_t i;
  for (i = 0; i < xed_inst_noperands (inst); ++i)
    {
      const xed_operand_t *op = xed_inst_operand (inst, i);
      xed_operand_enum_t op_name = xed_operand_name (op);

      eri_assert (op_name != XED_OPERAND_SEG0);
      eri_assert (op_name != XED_OPERAND_SEG1);
      eri_assert (op_name != XED_OPERAND_INDEX);
      eri_assert (op_name != XED_OPERAND_OUTREG);

      if (op_name == XED_OPERAND_BASE0 || op_name == XED_OPERAND_BASE1
	  || (op_name >= XED_OPERAND_REG0 && op_name <= XED_OPERAND_REG8))
	{
	  xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
	  uint8_t reg_idx = ir_reg_idx_from_reg_opt (reg);
	  if (reg != XED_REG_RIP && reg_idx != REG_NUM)
	    {
	      ir_depand (node, &inst_reg->src, dag->reg_defs[reg_idx]);
	      if (ir_inst_op_read (dec, op)) ++deps;
	      (inst_reg++)->op = op;
	    }
	}
      else if (op_name == XED_OPERAND_MEM0 || op_name == XED_OPERAND_AGEN
	       || XED_OPERAND_MEM1)
	deps += ir_build_inst_mem_operand (dag, node, dec, op);
      else if (op_name == XED_OPERAND_RELBR)
	node->inst.relbr = 1;
      else
	eri_assert (op_name == XED_OPERAND_IMM0
		    || op_name == XED_OPERAND_IMM1);
    }

  for (inst_reg = node->inst.regs; inst_reg->op; ++inst_reg)
    {
      const xed_operand_t *op = inst_reg->op;

      if (xed_operand_written (op))
	{
	  ++deps;
	  ir_define (node, node->inst.regs[i].dst);
	}
    }
  node->deps = eri_max (node->deps, deps);
}

static void
ir_reg_idx_from_dec_op (struct xed_decoded_inst_t *dec,
			const xed_operand_t *op);
{
  return ir_reg_idx_from_reg (
		xed_decoded_inst_get_reg (dec, xed_operand_name (op)));
}

static void
ir_finish_inst (struct ir_dag *dag, struct ir_node *node)
{
  xed_decoded_inst_t *dec = &node->inst.dec;

  if (node->inst.access_mem)
    ir_access_mem (dag, node, &node->inst.memory);

  ir_depand (node, &node->inst.prev, dag->prev);
  dag->prev = &node->seq;

  struct ir_inst_reg *inst_reg;
  for (inst_reg = node->inst.regs; inst_reg->op; ++inst_reg)
    {
      const xed_operand_t *op = inst_reg->op;
      if (xed_operand_written (op))
	dag->reg_defs[ir_reg_idx_from_dec_op (dec, op)] = &inst_reg->dst;
    }
}

static void
ir_set_inst_nop (struct ir_node *inst, uint64_t rip)
{
  inst->deps = 0;
  inst->tag = IR_INST_NOP;
  inst->inst.rip = rip;
}

static void
ir_set_rip_from_reg (struct ir_dag *dag, xed_reg_enum_t src)
{
  ir_copy_reg_def (dag, XED_REG_RIP, src);
}

static void
ir_init_mem_args_from_inst_mem (struct ir_mem_args *args, 
				struct ir_node *inst, uint8_t i)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  struct ir_mem_regs *mem = &inst->inst.mems[i].regs;
  args->base = mem->base.def;
  args->index = mem->index.def;
  args->seg = xed_decoded_inst_get_seg_reg (dec, i);
  args->scale = xed_decoded_inst_get_scale (dec, i);
  args->disp = xed_decoded_inst_get_memory_displacement (dec, i);
  args->size = xed_decoded_inst_get_memory_operand_length (dec, i);
  args->addr = xed_decoded_inst_get_memop_address_width (dec, i) >> 3;
}

static void
ir_create_load_from_inst_mem (struct ir_dag *dag, struct ir_node *inst,
			      uint8_t i, struct ir_def *prim)
{
  struct ir_mem_args src;
  ir_init_mem_args_from_inst_mem (&src, inst, i);
  return ir_create_load (dag, &src, prim);
}

static void
ir_set_rip_from_mem (struct ir_dag *dag, struct ir_node *inst, uint8_t i)
{
  ir_set_reg_def (dag, XED_REG_RIP,
		  ir_create_load_from_inst_mem (dag, inst, i, 0));
}

static void
ir_set_uncond_rip (struct ir_dag *dag, struct ir_node *inst, uint8_t reg)
{
  if (reg)
    ir_set_rip_from_reg (dag,
	xed_decoded_inst_get_reg (&inst->inst.dec, XED_OPERAND_REG0));
  else
    ir_set_rip_from_mem (dag, inst, 0);
}

static void
ir_build_push (struct ir_dag *dag, xed_reg_enum_t src)
{
  ir_set_reg_def (dag, XED_REG_RSP, ir_create_push (dag,
	  ir_get_reg_def (dag, XED_REG_RSP), ir_get_reg_def (dag, src),
	  xed_get_register_width_bits (src) >> 3));
}

static void
ir_build_pop (struct ir_dag *dag, xed_reg_enum_t dst)
{
  struct ir_def *prim = xed_get_register_width_bits (dst) != 64;
			? ir_get_reg_def (dag, dst) : 0;
  struct ir_def_pair pair = ir_create_pop (dag,
		ir_get_reg_def (dag, XED_REG_RSP), prim);
  ir_set_reg_def (dag, dst, pair.first);
  ir_set_reg_def (dag, XED_REG_RSP, pair.second);
}

static void
ir_build_popf (struct ir_dag *dag, struct ir_node *inst)
{
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (&node->inst.dec);
  ir_build_pop (dag,
		iclass == XED_ICLASS_POPF ? XED_REG_FLAGS : XED_REG_RFLAGS);
  ir_end (dag, inst);
}

static void 
ir_build_uncond_branch (struct ir_dag *dag, struct ir_node *inst)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  if (inst->inst.relbr)
    {
      xed_int32_t disp = xed_decoded_inst_get_branch_displacement (dec);
      ir_set_inst_nop (inst, inst->inst.rip + disp);
      return;
    }

  ir_set_uncond_rip (dag, inst,
	xed_decoded_inst_get_iform_enum (dec) == XED_IFORM_JMP_GPRv);
  ir_end (dag, inst);
}

static void
ir_build_cond_branch (struct ir_dag *dag, struct ir_node *inst)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (dec);

  xed_operand_values_t *ops = xed_decoded_inst_operands (dec);

  xed_int32_t disp = xed_decoded_inst_get_branch_displacement (dec);
  uint64_t taken_rip = inst->inst.rip + disp;
  uint64_t fall_rip = inst->inst.rip;
  struct ir_def *taken = ir_get_load_imm (dag, taken_rip);
  struct ir_def *fall = ir_get_load_imm (dag, fall_rip);

  struct ir_cond_branch_args args = {
    iclass, xed_operand_values_get_effective_address_width (ops) >> 3,
    ir_get_reg_def (dag, XED_REG_RFLAGS),
    ir_get_reg_def (dag, XED_REG_RCX), taken, fall
  };
  struct ir_def_pair pair = ir_get_cond_branch (dag, &args);
  struct ir_def *rip = pair.first;
  if (pair.second)
    ir_set_reg_def (dag, XED_REG_RCX, pair.second);

  if (rip == taken || rip == fall)
    {
      ir_set_inst_nop (inst, rip == taken ? taken_rip : fall_rip);
      return;
    }

  ir_set_reg_def (dag, XED_REG_RIP, rip);
  ir_end (dag, inst);
}

static void
ir_build_call (struct ir_dag *dag, struct ir_node *inst)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  if (inst->inst.relbr)
    {
      xed_int32_t disp = xed_decoded_inst_get_branch_displacement (dec);
      ir_set_inst_nop (inst, inst->inst.rip + disp);
      ir_build_push (dag, XED_REG_RIP);
      return;
    }

  ir_set_uncond_rip (dag, inst,
	xed_decoded_inst_get_iform_enum (dec) == XED_IFORM_CALL_NEAR_GPRv);
  ir_build_push (dag, XED_REG_RIP);
  ir_end (dag, inst);
}

static void
ir_build_ret (struct ir_dag *dag, struct ir_node *inst)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  ir_build_pop (dag, XED_REG_RIP);
  ir_set_reg_def (dag, XED_REG_RSP, ir_get_add (dag,
	ir_get_reg_def (dag, XED_REG_RSP),
	ir_get_load_imm (dag, xed_decoded_inst_get_unsigned_immediate (dec))));
  ir_end (dag, inst);
}

static void
ir_mark_supports (struct ir_dag *dag, struct ir_node *node)
{
  if (node->sups++) return;

  struct ir_dep *dep;
  ERI_RBT_FOREACH (ir_dep, node, dep)
    ir_mark_supports (dag, dep->def->node);
}

static void
ir_flatten (struct ir_flattened *flat, struct ir_node *node)
{
  if (--node->sups) return;

  ++flat->ridx
  struct ir_dep *dep;
  ERI_RBT_FOREACH (ir_dep, node, dep)
    dep->ridx = dep->def->ridx;
  ERI_RBT_FOREACH (ir_dep, node, dep)
    dep->def->ridx = flat->ridx;

  ir_flat_lst_insert_front (flat, node);
  node->flattened = 1;

  ERI_RBT_FOREACH (ir_dep, node, dep)
    ir_flatten (dag, flat, dep->def->node);
}

static struct ir_local *
ir_alloc_local (struct ir_flattened *flat)
{
  struct ir_local *local = ir_alloc (flat->dag, sizeof *local);
  local->idx = flat->local_size++;
  return local;
}

static struct ir_local *
ir_get_local (struct ir_flattened *flat)
{
  struct ir_local *local = ir_local_rbt_get_first (flat);
  if (local)
    {
      ir_local_rbt_remove (flat, local);
      return local;
    }
  
  return ir_alloc_local (flat);
}

static void
ir_put_local (struct ir_flattened *flat, struct ir_local *local)
{
  ir_local_rbt_insert (flat, local);
}

static uint8_t
ir_inst_designated_reg (xed_decoded_inst_t *dec, const xed_operand_t *op)
{
  xed_category_enum_t cate = xed_decoded_inst_get_category (dec);
  xed_operand_visibility_enum_t vis = xed_operand_operand_visibility (op);
  return vis == XED_OPVIS_SUPPRESSED
	 || (vis == XED_OPVIS_IMPLICIT
	     && cate != XED_CATEGORY_BINARY && cate != XED_CATEGORY_LOGICAL
	     && cate != XED_CATEGORY_DATAXFER);
}

struct ir_enc_mem_args
{
  uint8_t base, index;
  xed_reg_enum_t seg;
  xed_uint_t scale;
  xed_int64_t disp;

  uint32_t size;
  uint8_t addr;
};

static uint8_t
ir_encode_nop (uint8_t *bytes)
{
  eri_assert (xed_encode_nop (bytes, 1) == XED_ERROR_NONE);
  return 1;
}

static uint8_t
ir_encode (uint8_t *bytes, xed_encoder_request_t *enc)
{
  uint8_t res;
  eri_assert (xed_encode (enc, bytes, INST_BYTES, &res) == XED_ERROR_NONE);
  return res;
}

static xed_reg_enum_t
ir_reg (uint8_t idx)
{
  return ir_reg_from_reg_idx_opt (idx, 8);
}

static void
ir_init_encode (xed_encoder_request_t *enc,
		xed_iclass_enum_t iclass, uint8_t op_size, uint8_t add_size)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
  xed_encoder_request_zero_set_mode (enc, &state);
  xed_encoder_request_set_iclass (enc, iclass);
  xed_encoder_request_set_effective_operand_width (&enc, op_size << 3);
  xed_encoder_request_set_effective_address_width (&enc, addr_size << 3);
}

static uint8_t
ir_encode_bin (uint8_t *bytes, xed_iclass_enum_t iclass,
	       uint8_t dst, uint8_t src)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_reg (dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG1, ir_reg (src));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_REG1);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_mov (uint8_t *bytes, uint8_t dst, uint8_t src)
{
  return ir_encode_bin (bytes, XED_ICLASS_MOV, dst, src);
}

static uint8_t
ir_min_width_unsigned (int64_t x, uint8_t mask)
{
  uint8_t res = xed_shortest_width_unsigned (x, mask & 0x7);
  eri_assert (res != 8 || mask & 0x8);
  return res;
}

static uint8_t
ir_min_width_signed (int64_t x, uint8_t mask)
{
  uint8_t res = xed_shortest_width_signed (x, mask & 0x7);
  eri_assert (res != 8 || mask & 0x8);
  return res;
}

static void
ir_encode_set_mem0 (xed_encorder_request_t *enc, struct ir_enc_mem_args *mem)
{
  xed_encoder_request_set_base0 (enc,
			ir_reg_from_reg_idx_opt (mem->base, mem->addr));
  xed_encoder_request_set_index (enc,
			ir_reg_from_reg_idx_opt (mem->index, mem->addr));
  xed_encoder_reguest_set_seg0 (enc, mem->seg);
  xed_encoder_reguest_set_scale (enc, mem->scale);
  xed_encoder_request_set_memory_displacement (enc, mem->disp,
				ir_min_width_signed (mem->disp, 0x7));
  xed_encoder_request_set_memory_operand_length (&enc, mem->size);
}

static uint8_t
ir_encode_load (uint8_t *bytes, uint8_t dst, struct ir_enc_mem_args *src)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, src->size, src->addr);

  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0,
			       ir_reg_from_reg_idx_opt (dst, src->size));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_mem0 (enc);
  ir_encode_set_mem0 (&enc, src);
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_MEM0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_load_imm (uint8_t *bytes, uint8_t dst, int64_t src)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, 8, 8);

  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_reg (dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_uimm0 (&enc, src,
				 ir_min_width_unsigned (src, 0x15));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_IMM0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_store (uint8_t *bytes, struct ir_enc_mem_args *dst, uint8_t src)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, dst->size, dst->addr);

  xed_encoder_request_set_mem0 (enc);
  ir_encode_set_mem0 (&enc, dst);
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_MEM0);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0,
			       ir_reg_from_reg_idx_opt (src, dst->size));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_REG0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_lea (uint8_t *bytes, uint8_t dst, struct ir_enc_mem_args *src)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, src->size, dst->addr);

  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0,
			       ir_reg_from_reg_idx (dst, src->size));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_agen (enc);
  ir_encode_set_mem0 (&enc, src);
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_AGEN);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_pushf (uint8_t *bytes)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_PUSHFQ, 8, 8);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_popf (uint8_t *bytes)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_POPFQ, 8, 8);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_cmov (uint8_t *bytes, xed_iclass_enum_t iclass,
		uint8_t dst, uint8_t src)
{
  return ir_encode_bin (bytes, iclass, dst, src);
}

static uint8_t
ir_encode_add (uint8_t *bytes, uint8_t dst, uint8_t src)
{
  return ir_encode_bin (bytes, XED_ICLASS_ADD, dst, src);
}

static uint8_t
ir_encode_jmp (uint8_t *bytes, uint8_t dst)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_JMP, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_reg (dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_cjmp_relbr (uint8_t *bytes, xed_iclass_enum_t iclass,
		      uint8_t addr, int32_t rel)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, 8, addr);
  xed_encoder_request_set_relbr (&enc);
  xed_encoder_request_set_branch_displacement (&enc, rel,
	ir_min_width_signed (rel, ir_cond_branch_loop (iclass) ? 0x1 : 0x7));
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_RELBR);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_inst (uint8_t *bytes, xed_decoded_inst_t *dec)
{
  xed_encoder_request_init_from_decode (dec);
  return ir_encode (bytes, dec);
}

static void
ir_emit_raw (struct ir_block *blk, uint8_t *bytes, uint8_t len)
{
  eri_assert_buf_append (&blk->insts, bytes, len);
}

#define ir_emit(what, blk, ...) \
  do {									\
    uint8_t _bytes[INST_BYTES];						\
    ir_emit_raw (blk, _bytes,						\
		 ERI_PASTE (ir_encode_, what) (_bytes, ##__VA_ARGS__));	\
  } while (0)

static void
ir_init_local_enc_mem_args (struct ir_flattened *flat, uint64_t idx,
			    struct ir_enc_mem_args *args)
{
  args->base = ir_local_host_idx (flat);
  args->index = REG_NUM;
  args->seg = XED_REG_INVALID;
  args->scale = 1;
  args->disp = idx * 8;
  args->size = 8;
  args->addr = 8;
}

static void
ir_move (struct ir_flattened *flat, struct ir_block *blk,
	 enum reg_loc_tag tag, uint64_t val, struct ir_host_locs *locs)
{
  struct ir_enc_mem_args mem;
  uint8_t idx = ir_host_idxs_get_gpreg_idx (locs->host_idxs);
  if (tag == REG_LOC_REG)
    {
      eri_assert (! ir_host_idxs_set (locs->host_idxs, val));
      ir_host_idxs_add (&locs->host_idxs, val);
      if (val == REG_IDX_RFLAGS)
	{
	  if (! locs->local)
	    {
	      eri_assert (idx != REG_NUM);
	      locs->local = ir_get_local (flat);
	      ir_init_local_enc_mem_args (flat, locs->local->idx, &mem);
	      ir_emit (store, blk, &mem, idx);
	    }
	  else ir_init_local_enc_mem_args (flat, locs->local->idx, &mem);
	  ir_emit (lea, blk, REG_IDX_RSP, &mem);
	  ir_emit (popf, blk);
	}
      else if (idx == REG_NUM)
	{
	  if (! locs->local)
	    {
	      eri_assert (ir_host_idxs_set (locs->host_idxs, REG_IDX_RFLAGS));

	      locs->local = ir_get_local (flat);
	      ir_init_local_enc_mem_args (flat, locs->local->idx + 1, &mem);
	      ir_emit (lea, blk, REG_IDX_RSP, &mem);
	      ir_emit (pushf, blk);
	    }
	  ir_init_local_enc_mem_args (flat, locs->local->idx, &mem);
	  ir_emit (load, blk, val, &mem);
	}
      else ir_emit (mov, blk, val, idx);
    }
  else
    {
      eri_assert (! locs->local);
      locs->local = (void *) val;
      if (idx == REG_NUM)
	{
	  ir_init_local_enc_mem_args (flat, locs->local + 1, &mem);
	  ir_emit (lea, blk, REG_IDX_RSP, &mem);
	  ir_emit (pushf, blk);
	}
      else
	{
	  ir_init_local_enc_mem_args (flat, locs->local, &mem);
	  ir_emit (store, blk, &mem, idx);
	}
    }
}

static void
ir_trace_update_reg_host_loc (struct ir_block *blk, uint8_t reg_idx,
			      enum reg_loc_tag tag, uint64_t val)
{
  struct trace_reg t = { blk->insts.off, reg_idx, { tag, val } };
  eri_assert_buf_append (&blk->insts, &t, sizeof t);
}

static void
ir_trace_update_rip_host_loc (struct ir_block *blk, uint64_t rip)
{
  ir_trace_update_reg_host_loc (blk, REG_IDX_RIP, REG_LOC_IMM, rip);
}

static void
ir_try_fix_reg_host_loc (struct ir_block *blk, uint8_t reg_idx,
			 struct ir_reg_def_loc *def_loc)
{
  struct ir_host_locs *locs = def_loc->def->locs;
  struct reg_loc *loc = &def_loc->loc;
  if ((loc->tag == REG_LOC_REG
       && ! ir_host_idxs_set (locs->host_idxs, loc->val))
      || (loc->tag == REG_LOC_LOCAL
	  && (! locs->local || locs->local->idx != loc->val)))
    {
      uint8_t host_idx = ir_host_idxs_get_reg_idx (locs->host_idxs);
      if (host_idx != REG_NUM)
	ir_trace_update_reg_host_loc (blk, reg_idx, REG_LOC_REG, host_idx);
      else
	ir_trace_update_reg_host_loc (blk, reg_idx,
				      REG_LOC_LOCAL, locs->local->idx);
    }
}

static void
ir_try_update_reg_host_loc (struct ir_flattened *flat, struct ir_block *blk,
			    struct ir_def *def)
{
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (flat->reg_def_locs[i].def == def)
      ir_try_fix_reg_host_loc (blk, i, flat->reg_def_locs + i);
}

static uint8_t
ir_local_host_idx (struct ir_flattened *flat)
{
  return ir_host_idxs_get_gpreg_idx (flat->local.locs.host_idxs);
}

static void
ir_set_host (struct ir_flattened *flat, struct ir_block *blk,
	     uint8_t idx, struct ir_def *def, uint32_t *free)
{
  struct ir_def *old = flat->hosts[i];
  if (old->ridx)
    {
      uint8_t num = ir_host_idxs_gpreg_num (old->locs.host_idxs);
      uint8_t i = ir_host_idxs_get_gpreg_idx (*free);
      if (num == 0 || (num == 1 && i == REG_NUM))
	ir_move (flat, blk, REG_LOC_LOCAL,
		 (uint64_t) ir_get_local (flat), &old->locs);
      else if (num == 1)
	{
	  ir_move (flat, blk, REG_LOC_REG, i, &old->locs);
	  ir_host_idxs_del (free, i);
	}
    }
  ir_host_idxs_del (&old->locs.host_idxs, idx);
  ir_try_update_reg_host_loc (flat, blk, old);

  if (def != &flat->dummy
      && (def->locs.host_idxs || def->locs.local))
    ir_move (flat, blk, REG_LOC_REG, idx, &def->locs);
  else ir_host_idxs_add (&def->locs.host_idxs, idx);
  flat->hosts[i] = def;
}

struct ir_ra
{
  uint8_t host_idx;
  struct ir_dep *dep;
  struct ir_def *def;
  uint8_t exclusive;
};

static void
ir_init_ra (struct ir_ra *a, uint8_t idx,
	    struct ir_dep *dep, struct ir_def *def)
{
  a->host_idx = idx;
  a->dep = dep;
  a->def = def;
  a->exclusive = 0;
}

static struct ir_ra *
ir_ra_gpreg_dep (struct ir_ra *a, struct ir_dep *dep)
{
  ir_init_ra (a, REG_NUM, dep, 0);
  return a + 1;
}

static struct ir_ra *
ir_ra_gpreg_dep_opt (struct ir_ra *a, struct ir_dep *dep)
{
  if (! dep->def) return a;
  return ir_ra_gpreg_dep (a, dep);
}

static struct ir_ra *
ir_ra_gpreg_def (struct ir_ra *a, struct ir_def *def)
{
  ir_init_ra (a, REG_NUM, 0, def);
  return a + 1;
}

static struct ir_ra *
ir_ra_gpreg_dep_def (struct ir_ra *a, struct ir_dep *dep, struct ir_def *def)
{
  ir_init_ra (a, REG_NUM, dep->def ? dep : 0, def);
  return a + 1;
}

static struct ir_ra *
ir_ra_desig_dep (struct ir_ra *a, uint8_t idx, struct ir_dep *dep)
{
  ir_init_ra (a, idx, dep, 0);
  return a + 1;
}

static struct ir_ra *
ir_ra_desig_dep_opt (struct ir_ra *a, uint8_t idx, struct ir_dep *dep)
{
  if (! dep->def) return a;
  return ir_ra_desig_dep (a, idx, dep);
}

static struct ir_ra *
ir_ra_desig_def (struct ir_ra *a, uint8_t idx, struct ir_def *def)
{
  ir_init_ra (a, idx, 0, def);
  return a + 1;
}

static struct ir_ra *
ir_ra_desig_dep_def (struct ir_ra *a, uint8_t idx,
		     struct ir_dep *dep, struct ir_def *def)
{
  ir_init_ra (a, idx, dep->def ? dep : 0, def);
  return a + 1;
}

static void
ir_assign_hosts (struct ir_flattened *flat, struct ir_block *blk,
		 struct ir_ra *ras, uint32_t n)
{
  uint32_t preps_mask = 0;
  uint8_t local = ir_local_host_idx (flat);
  eri_assert (local != REG_NUM);

  uint32_t i, j;
  for (i = 0; i < n && ! ir_host_idxs_set (preps_mask, REG_IDX_RSP); ++i)
    if (ras[i]->host_idx == REG_IDX_RFLAGS)
      {
	struct ir_host_locs *old = &flat->hosts[REG_IDX_RFLAGS]->locs;
	if (ras[i]->dep
	    || (! ir_host_idxs_gpreg_num (old->host_idxs) && ! old->local))
	  ir_host_idxs_add (&preps_mask, REG_IDX_RSP);
      }
    else eri_assert (ras[i]->host_idx != local);

  uint32_t deps_mask = 0;
  struct ir_ra deps[REG_NUM];

  for (i = 0; i < n; ++i)
    if (ras[i].dep && ras[i].host_idx != REG_NUM)
      {
	deps[ras[i].host_idx] = ras[i];
	ir_host_idxs_add (&deps_mask, ras[i].host_idx);
      }

  for (i = 0; i < n; ++i)
    if (ras[i].dep && ras[i].host_idx == REG_NUM)
      {
	struct ir_ra *a = ras + i;

	for (j = 0; j < REG_NUM; ++j)
	  {
	    struct ir_ra *e = deps + j;
	    if (ir_host_idxs_set (deps_mask, j) && e->dep->def == a->dep->def
		&& (! e->def || ! a->def) && ! e->exclusive && ! a->exclusive)
	      {
		a->host_idx = j;
		if (a->def) e->def = a->def;
	      }
	  }

	if (a->host_idx != REG_NUM) continue;

	uint32_t rms = preps_mask & deps_mask;
	a->host_idx = ir_host_idxs_get_gpreg_idx (
					a->dep->def->locs.host_idxs & ~rms);
	if (a->host_idx != REG_NUM)
	  {
	    deps[a->host_idx] = *a;
	    ir_host_idxs_add (&deps_mask, a->host_idx);
	    continue;
	  }

	uint8_t min;
	uint64_t min_ridx = -1;
	for (j = 0; j < GPREG_NUM && min_ridx; ++j)
	  {
	    if (j == local || ir_host_idxs_set (deps_mask, j)) continue;

	    if (ir_host_idxs_set (preps, j))
	      {
		min = j;
		min_ridx = 0;
	      }
	    else if (ir_host_idxs_gpreg_num (
			flat->hosts[i]->locs.host_idxs & ~rms) > 1)
	     {
		min = j;
		min_ridx = 0;
	     }
	    else if (flat->hosts[i]->ridx < min_ridx)
	      {
		min = j;
		min_ridx = flat->hosts[i]->ridx;
	      }
	  }
	eri_assert (min_ridx != -1);
	a->host_idx = min;
	deps[min] = *a;
	ir_host_idxs_add (&deps_mask, min);
      }

  uint32_t defs_mask = 0;
  struct ir_def *defs[REG_NUM];

  for (i = 0; i < n; ++i)
    if (ras[i].def && ras[i].host_idx != REG_NUM)
      {
	defs[ras[i].host_idx] = ras[i].def;
	ir_host_idxs_add (&def_mask, ras[i].host_idx);
      }

  for (i = 0; i < n; ++i)
    if (ras[i].def && ras[i].host_idx == REG_NUM)
      {
	uint8_t min;
	uint64_t min_rdx = -1;
	for (j = 0; j < GPREG_NUM && min_ridx; ++j)
	  {
	    if (j == local || ir_host_idxs_set (defs_mask, j)) continue;

	    if (ir_host_idxs_set (deps_mask, j))
	      {
		if (deps[j].dep->def->ridx < min_ridx
		    && ! deps[j].exclusive && ! ras[i].exclusive)
		  {
		    min = j;
		    min_ridx = deps[j].dep->def->ridx;
		  }
	      }
	    else if (ir_host_idxs_set (preps, j))
	      {
		min = j;
		min_ridx = 0;
	      }
	    else if (flat->hosts[i]->ridx < min_ridx)
	      {
		min = j;
		min_ridx = flat->hosts[i]->ridx;
	      }
	  }
	eri_assert (min_ridx != -1);
	ras[i].host_idx = min;
	defs[min] = ras[i].def;
	ir_host_idxs_add (&defs_mask, min);
      }

  uint32_t free;
  for (i = 0; i < REG_NUM; ++i)
    if (flat->hosts[i]->ridx == 0
	&& ! ir_host_idxs_set (preps_mask | deps_mask | defs_mask))
      ir_host_idxs_add (&free, i);

  if (ir_host_idxs_set (preps_mask, REG_IDX_RSP))
    ir_set_host (flat, blk, REG_IDX_RSP, &flat->dummy, &free);

  for (i = 0; i < REG_NUM; ++i)
    if (ir_host_idxs_set (deps_mask, i))
      {
	ir_set_host (flat, blk, i, deps[i].dep->def, &free);
	deps[i].dep->def->ridx = deps[i].dep->ridx;
      }

  for (i = 0; i < REG_NUM; ++i)
    if (ir_host_idxs_set (defs_mask, i))
      ir_set_host (flat, blk, i, defs[i], &free);
}

static void
ir_gen_inst (struct ir_flattened *flat,
	     struct ir_node *node, struct ir_block *blk)
{
  xed_decoded_inst_t *dec = &node->inst.dec;

  struct ir_ra ras[eri_length_of (node->inst.regs) + 4] = { { 0 } };
  struct ir_ra *a = ras;

  struct ir_inst_reg *inst_reg;
  for (inst_reg = node->inst.regs; inst_reg->op; ++inst_reg)
    {
      const xed_operand_t *op = inst_reg->op;
      xed_operand_enum_t op_name = xed_operand_name (op);

      ir_init_ra (a++, ir_inst_designated_reg (dec, op)
		      ? ir_reg_idx_from_dec_op (dec, op) : REG_NUM,
		  ir_inst_op_read (dec, op) ? &node->inst.regs[i].src : 0,
		  xed_operand_written (op) ? &node->inst.regs[i].dst : 0);
    }

  struct ir_dep *mems[] = {
    &node->inst.mems[0].regs.base, &node->inst.mems[0].regs.index,
    &node->inst.mems[1].regs.base
  };

  uint8_t i;
  for (i = 0; i < eri_length_of (mems); ++i)
    a = ir_ra_gpreg_dep_opt (a, mems[i]);

  ir_assign_hosts (flat, blk, ras, a - ras);

  xed_operand_values_t *ops = xed_decoded_inst_operands (dec);

  a = ras;
  for (inst_reg = node->inst.regs; inst_reg->op; ++inst_reg)
    {
      xed_operand_enum_t op_name = xed_operand_name (inst_reg->op);
      xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
      uint8_t size = xed_get_register_width_bits64 (reg) >> 3;
      xed_operand_values_set_operand_reg (ops, op_name,
				ir_reg_from_reg_idx ((a++)->host_idx, size));
    }

  xed_operand_t mem_op_names[] = {
    XED_OPERAND_BASE0, XED_OPERAND_INDEX, XED_OPERAND_BASE1
  };
  for (i = 0; i < eri_length_of (mems); ++i)
    if (mems[i]->def)
      xed_operand_values_set_operand_reg (ops, mem_op_names[i],
				ir_reg_from_reg_idx ((a++)->host_idx, 8));

  ir_emit (inst, blk, &node->inst.dec);

  for (inst_reg = node->inst.regs; inst_reg->op; ++inst_reg)
    {
      if (xed_operand_written (inst_reg->op))
	{
	  flat->reg_def_locs[i].def = def;
	  ir_try_fix_reg_host_loc (blk, i, flat->reg_def_locs + i);
	}
    }
  ir_trace_update_rip_host_loc (blk, node->inst.rip);
}

static void
ir_gen_inst_nop (struct ir_flattened *flat,
		 struct ir_node *node, struct ir_block *blk)
{
  ir_emit (nop, blk);
  ir_trace_update_rip_host_loc (blk, node->inst.rip);
}

#define ir_gen_init(...)

static void
ir_gen_end (struct ir_flattened *flat,
	    struct ir_node *node, struct ir_block *blk)
{
  struct ir_ra ras[REG_NUM];
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (i != REG_IDX_RIP)
      ir_init_ra (ras + i, i,
		  i == 0 ? node->end.regs + REG_IDX_RIP : 0, &flat->dummy);

  ir_assign_hosts (flat, blk, ras, REG_NUM);      

  struct ir_def *regs = node->end.regs;
  for (i = 0; i < REG_NUM; ++i)
    blk->final_locs[i] = regs[i].locs.local->idx;

  ir_emit (mov, blk, REG_IDX_RDX, ir_local_host_idx (flat));
  struct ir_enc_mem_args rsp = {
    .base = REG_IDX_RDX, .index = REG_NUM,
    .disp = __builtin_offsetof (struct active, stack)
		- __builtin_offsetof (struct active, local),
    .size = 8, .addr = 8
  };
  ir_emit (load, blk, REG_IDX_RDI, &rsp);
  ir_emit (load_imm, blk, REG_IDX_RSI, (uint64_t) analysis);
  ir_emit (load_imm, blk, REG_IDX_RCX, (uint64_t) eri_jump);
  ir_emit (jmp, blk, REG_IDX_RCX);
}

static void
ir_gen_err_end (struct ir_flattened *flat,
		struct ir_node *node, struct ir_block *blk)
{
  if (node->end.sig_info.sig) ir_gen_end (flat, node, blk);
  else ir_emit_raw (blk, node->end.bytes, node->end.len);
  blk->sig_info = node->end.sig_info;
}

static struct ir_ra *
ir_init_mem_ras (struct ir_mem *mem, struct ir_ra *a)
{
  a = ir_ra_gpreg_dep_opt (a, &mem->regs.base);
  return ir_ra_gpreg_dep_opt (a, &mem->regs.index);
}

static struct ir_ra *
ir_init_emit_mem_args (struct ir_mem *mem,
		       struct ir_ra *a, struct ir_enc_mem_args *args)
{
  args->base = mem->regs.base.def ? (a++)->host_idx : REG_NUM;
  args->index = mem->regs.index.def ? (a++)->host_idx : REG_NUM;

  args->seg = mem->seg;
  args->scale = mem->scale;
  args->disp = mem->disp;
  args->size = mem->size;
  args->addr = mem->addr;
  return a;
}

static void
ir_gen_store (struct ir_flattened *flat,
	      struct ir_node *node, struct ir_block *blk)
{
  struct ir_ra ras[3];
  struct ir_ra *a = ir_init_mem_ras (&node->store.dst, ras);
  a = ir_ra_gpreg_dep (a, &node->store.src);
  ir_assign_hosts (flat, blk, ras, a - ras);

  struct ir_enc_mem_args dst;
  a = ir_init_emit_mem_args (&node->store.dst, ras, &dst);
  ir_emit (store, blk, &dst, a->host_idx);
}

static void
ir_gen_load (struct ir_flattened *flat,
	     struct ir_node *node, struct ir_block *blk)
{
  struct ir_ra ras[3];
  struct ir_ra *a = ir_init_mem_ras (&node->store.src, ras);
  a = ir_ra_gpreg_dep_def (a, &node->load.prim, &node->store.dst);
  ir_assign_hosts (flat, blk, ras, a - ras);

  struct ir_enc_mem_args src;
  a = ir_init_emit_mem_args (&node->store.src, ras, &src);
  ir_emit (load, blk, a->host_idx, &src);
}

static void
ir_gen_load_imm (struct ir_flattened *flat,
		 struct ir_node *node, struct ir_block *blk)
{
  struct ir_ra ra;
  ir_ra_gpreg_def (&ra, &node->load_imm.dst);
  ir_assign_hosts (flat, blk, &ra, 1);
  ir_emit (load_imm, blk, ra.host_idx, node->load_imm.src);
}

static void
ir_gen_add (struct ir_flattened *flat,
	    struct ir_node *node, struct ir_block *blk)
{
  struct ir_ra ras[3];
  ir_ra_gpreg_dep_def (ras, node->bin.srcs, &node->bin.dst);
  ir_ra_gpreg_dep (ras + 1, node->bin.srcs + 1);
  ir_ra_desig_def (ras + 2, REG_IDX_RFLAGS, &flat->dummy);
  ir_assign_hosts (flat, blk, ras, eri_length_of (ras));

  ir_emit (add, blk, ras[0].host_idx, ras[1].host_idx);
}

static xed_iclass_enum_t
ir_cmov_iclass (xed_iclass_enum_t iclass)
{
  switch (iclass)
    {
    case XED_ICLASS_JB: return XED_ICLASS_CMOVB;
    case XED_ICLASS_JBE: return XED_ICLASS_CMOVBE;
    case XED_ICLASS_JL: return XED_ICLASS_CMOVL;
    case XED_ICLASS_JLE: return XED_ICLASS_CMOVLE;
    case XED_ICLASS_JNB: return XED_ICLASS_CMOVNB;
    case XED_ICLASS_JNBE: return XED_ICLASS_CMOVNBE;
    case XED_ICLASS_JNL: return XED_ICLASS_CMOVNL;
    case XED_ICLASS_JNLE: return XED_ICLASS_CMOVNLE;
    case XED_ICLASS_JNO: return XED_ICLASS_CMOVNO;
    case XED_ICLASS_JNP: return XED_ICLASS_CMOVNP;
    case XED_ICLASS_JNS: return XED_ICLASS_CMOVNS;
    case XED_ICLASS_JNZ: return XED_ICLASS_CMOVNZ;
    case XED_ICLASS_JO: return XED_ICLASS_CMOVO;
    case XED_ICLASS_JP: return XED_ICLASS_CMOVP;
    case XED_ICLASS_JS: return XED_ICLASS_CMOVS;
    case XED_ICLASS_JZ: return XED_ICLASS_CMOVZ;
    default: eri_assert_unreachable ();
    }
}

static void
ir_gen_cond_branch (struct ir_flattened *flat,
		    struct ir_node *node, struct ir_block *blk)
{
  xed_iclass_enum_t iclass = node->cond_branch.iclass;

  struct ir_ra ras[4];
  struct ir_ra *a = ir_ra_desig_dep_opt (ras, REG_IDX_RFLAGS,
					 &node->cond_branch.flags);
  if (ir_cond_branch_loop (iclass))
    {
      ir_init_ra (a, REG_IDX_RCX,
		  &node->cond_branch.cnt, &node->cond_branch.dec);
      (a++)->exclusive = 1;
    }
  else a = ir_ra_desig_dep_opt (a, REG_IDX, RCX,
				&node->cond_branch.cnt);
  a = ir_ra_gpreg_dep_def (a, &node->cond_branch.taken,
			   &node->cond_branch.dst);
  a = ir_ra_gpreg_dep (a, &node->cond_branch.fall);
  ir_assign_hosts (flat, blk, ras, a - ras);

  xed_iclass_enum_t iclass = node->quad.tag;
  ir_gen_assign_hosts (flat, &assigns, blk);

  if (ir_cond_branch_cnt_only (iclass) || ir_cond_branch_flags_cnt (iclass))
    {
      uint8_t bytes[INST_BYTES];
      uint8_t len = ir_encode_mov (bytes, fall, taken);
      ir_emit (cjmp_relbr, blk, iclass, node->cond_branch.addr, len);
      ir_emit_raw (blk, bytes, len);
    }
  else
    ir_emit (cmov, blk, ir_cmov_iclass (iclass), fall, taken);
}

static void
ir_free_deps (struct ir_flattened *flat, struct ir_node *node)
{
  struct ir_dep *dep;
  ERI_RBT_FOREACH (ir_dep, node, dep)
    {
      if (def->ridx == 0)
	flat->free_host_idxs |= def->locs.host_idxs;

      if (def->ridx == 0 && def->locs.local)
	{
	  ir_put_local (flat, def->locs.local);
	  def->locs.local = 0;
	}
    }
}

static struct block *
ir_output (struct eri_mtpool *pool, struct ir_block *blk)
{
  uint64_t ilen = eri_round_up (blk->insts.off, 16);
  struct block *out = eri_assert_mtmalloc (pool,
			sizeof *out + ilen + blk->trace_regs.off);
  out->insts = out->buf;
  eri_memcpy (out->insts, blk->insts.buf, blk->insts.off);
  out->insts_len = blk->insts.off;
  out->trace_regs = (void *) (out->buf + ilen);
  eri_memcpy (out->trace_regs, blk->trace_regs.buf, blk->trace_regs.off);
  out->ntrace_regs = blk->trace_regs.off / sizeof (struct trace_reg);
  eri_memcpy (out->final_locs, blk->final_locs, sizeof out->final_locs);
  out->sig_info = blk->sig_info;
  out->local_size = blk->local_size;
  return out;
}

static struct block *
ir_generate (struct ir_dag *dag)
{
  struct ir_flattened flat = { dag, { 0, -1 }, { 0, 0 } };
  ERI_LST_INIT_LIST (ir_flat, &flat);
  uint8_t local = REG_IDX_RBP;
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (i != local)
      {
	flat.hosts[i] = &flat.dummy;
	ir_host_idxs_add (&flat.dummy.locs.host_idxs, i);
      }
    else
      {
        flat.hosts[i] = &flat.local;
	ir_host_idxs_add (&flat.local.locs.host_idxs, i);
      }

  struct ir_node *last = dag->last->node;
  ir_mark_supports (dag, last);
  ir_flatten (dag, &flag, last);

  struct ir_node *init = dag->init->node;
  for (i = 0; i < REG_NUM; ++i)
    if (i != REG_IDX_RIP)
      {
	struct ir_def *def = init->init.regs + i;
	eri_assert (def->ridx);
	def->locs.local = ir_get_local (&flat);
	flat->reg_def_locs[i].def = def;
      }

  struct ir_block blk;
  eri_assert_buf_mtpool_init (&blk.insts, dag->pool, 512);
  eri_assert_buf_mtpool_init (&blk.regs, dag->pool, 512);

  if (local != REG_IDX_RDI)
    ir_emit (mov, &blk, local, REG_IDX_RDI);

  struct ir_node *node;
  ERI_LIST_FOREACH (ir_flat, &flat, node)
    {
      switch (node->tag)
	{
#define GEN_TAG(ctag, tag) \
  case ERI_PASTE (IR_, ctag):						\
    ERI_PASTE (ir_gen_, tag) (&flat, node, &blk); break;
	IR_NODE_TAGS (GEN_TAG)
	default: eri_assert_unreachable ();
	}
      ir_free_deps (flat, node);
    }

  blk.local_size = flat.local_size;
  struct block *res = ir_output (dag->pool, &blk);
  eri_assert_buf_fini (&blk.inst);
  eri_assert_buf_fini (&blk.regs);
  return res;
}

static struct block *
translate (struct eri_analyzer *al, uint64_t rip, uint8_t tf)
{
  struct ir_dag dag = { al->group->pool };
  ERI_LST_INIT_LIST (ir_alloc, &dag);

  struct ir_node *init = ir_alloc_node (&dag, IR_INIT, 0);
  init->init.rip = rip;
  dag->init = &init->seq;

  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (i != REG_IDX_RIP)
      dag->reg_defs[i] = ir_define (init, init->init.regs + i);

  i = 0;
  while (1)
    {
      struct ir_node *node = ir_create_inst (al, &dag, rip);
      if (! node) break;

      ir_build_inst_operands (&dag, node);

      xed_decoded_inst_t *dec = &node->inst.dec;
      xed_category_enum_t cate = xed_decoded_inst_get_category (dec);
      xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (dec);

#if 0
      eri_assert (iclass != XED_ICLASS_BOUND);
      eri_assert (iclass != XED_ICLASS_INT);
      eri_assert (iclass != XED_ICLASS_INT1);
      eri_assert (iclass != XED_ICLASS_JMP_FAR);
      eri_assert (iclass != XED_ICLASS_CALL_FAR);
      eri_assert (iclass != XED_ICLASS_RET_FAR);
#endif
      eri_assert (iclass != XED_ICLASS_IRET); /* XXX: ??? */
      eri_assert (iclass != XED_ICLASS_IRETD);
      eri_assert (iclass != XED_ICLASS_IRETQ);

      /* TODO: rep */

      if (cate == XED_CATEGORY_SYSCALL)
	{
	  /* XXX: error out */
	  eri_assert (0);
	}

      /* XXX: XSAVE / XRESTORE */

      if (iclass == XED_ICLASS_POPF || iclass == XED_ICLASS_POPFQ)
	{
	  ir_set_rip_from_inst (dag, node);
	  ir_build_popf (dag, node);
	}
      else if (cate == XED_CATEGORY_UNCOND_BR)
	ir_build_uncond_branch (dag, node);
      else if (cate == XED_CATEGORY_COND_BR)
	ir_build_cond_branch (dag, node);
      else if (cate == XED_CATEGORY_CALL)
	ir_build_call (dag, node);
      else if (cate == XED_CATEGORY_RET)
	ir_build_ret (dag, node);

      if (node->tag == IR_END) break;

      ir_finish_inst (dag, node, rip);
      rip = node->inst.rip;
      if (++i == tf ? : al->group->max_inst_count)
	{
	  ir_set_rip_from_inst (dag, node);
	  ir_end (dag, 0);
	  break;
	}
    }

  struct block *res = ir_output (ir_generate (&dag));

  struct ir_alloc *a, *na;
  ERI_LST_FOREACH_SAFE (ir_alloc, dag, a, na)
    {
      ir_alloc_remove (dag, a);
      eri_assert_mtfree (dag->pool, a);
    }
  return res;
}

eri_noreturn void
eri_analyzer__enter (struct eri_analyzer *al,
		     struct eri_registers *regs)
{
  struct eri_analyzer_group *group = al->group;
  eri_lock (group->trans_lock);
  struct trans_key = { regs->rip, !! (regs->rflags & ERI_RFLAGS_TF) };
  struct trans *trans = trans_rbt_get (group, &trans_key, ERI_RBT_EQ);
  if (! trans)
    {
      trans = eri_assert_mtmalloc (group->pool, sizeof *trans);
      trans->key = trans_key;
      trans->ref_count = 1;
      trans->trans = 0;
      trans->wait = 0;
      trans->done = 0;
      trans_rbt_insert (group, trans);
      eri_unlock (group->trans_lock);

      trans->block = translate (al, trans->key.rip, trans->key.tf);

      if (eri_atomic_load (&trans->wait))
        eri_assert_syscall (futex, &trans->done,
			    ERI_FUTEX_WAKE, ERI_INT_MAX);
    }
  else
    {
      ++trans->ref_count;
      eri_unlock (group->trans_lock);
      if (! eri_atomic_load (&trans->done, 0))
	{
	  eri_atomic_inc (&trans->wait, 1);
	  eri_assert_sys_futex_wait (&trans->done, 0, 0);
	  eri_atomic_loop (&trans->wait, 1);
	}
    }

  struct block *blk = trans->block;
  struct active *act = eri_assert_mtmalloc (group->pool,
				sizeof *act + blk->local_size * 8);
  eri_atomic_store (&al->act, act, 0);
  act->al = al;
  act->trans = trans;
  act->stack = eri_entry__get_stack (al->entry) - 8;
  uint64_t *local_reg = act->local;

#define SAVE_LOCAL_REG(creg, reg) \
  if (ERI_PASTE (REG_IDX_, creg) != REG_IDX_RIP)			\
    *(local_reg++) = regs->reg;
  ERI_FOREACH_REG (SAVE_LOCAL_REG)

  eri_jump (0, blk->insts, act->local, 0, 0);

  eri_assert_unreachable ();
}

static uint8_t
active_single_step (struct active *act)
{
  struct block *blk = act->trans->block;
  return act->local[blk->final_locs[REG_IDX_RFLAGS]] & ERI_RFLAGS_TF;
}

#define GET_REG(creg, reg, local, locs, set, ...) \
  set (reg, (local)[(locs)[ERI_PASTE (REG_IDX_, creg)]], ##__VA_ARGS__);
#define GET_REGS(local, locs, set, ...) \
  do { ERI_FOREACH_REG (GET_REG, local, locs, set, ##__VA_ARGS__) } while (0)

eri_noreturn static void
analysis (uint64_t *local)
{
  struct active *act = eri_struct_of (local, typeof (*act), local);

  struct eri_analyzer *al = act->al;
  struct block *blk = act->trans->block;
  // TODO check e.g. memory

  if (blk->sig_info.sig || active_single_step (act))
    eri_assert_syscall (tgkill, *al->group->pid, *al->tid, ERI_SIGRTMIN + 1);

  struct eri_registers regs;
#define SET_FINAL_REG(reg, v)	do { regs.reg = v; } while (0)
  GET_REGS (act->local, blk->final_locs, SET_FINAL_REG);

  eri_atomic_store (&al->act, 0, 0);
  eri_atomic_dec (&act->trans->ref_count, 1);

  eri_assert_mtfree (al->group->pool, act);

  struct eri_entry *en = al->entry;
  if (eri_within (al->group->map_range, regs.rip))
    {
      struct eri_registers *en_regs = eri_entry__get_regs (en);
      void *th = (void *) regs.rbx;
      regs.rbx = en_regs->rbx;
      *en_regs = regs;
      eri_noreturn void (*entry) (void *) = eri_entry__get_entry (en);
      entry (th);
    }
  else eri_analyzer__enter (al, &regs);
}

static uint8_t
signaled (struct active *act, struct eri_siginfo *info)
{
  struct block *blk = act->trans->block;
  if (blk->sig_info.sig)
    {
      *info = blk->sig_info;
      return 1;
    }

  if (act->local[blk->final_locs[REG_IDX_RFLAGS]] & ERI_RFLAGS_TF)
    {
      info->sig = ERI_SIGTRAP;
      info->code = ERI_TRAP_TRACE;
      return 1;
    }
  return 0;
}

static uint64_t
get_reg_from_ctx_by_idx (struct eri_ucontext *ctx, uint8_t idx)
{
  switch (idx)
   {
#define GET_REG_FROM_CTX(creg, reg) \
   case (ERI_PASTE (REG_IDX_, creg)): return ctx->mctx.reg;
   ERI_FOREACH_REG (GET_REG_FROM_CTX)
   default: eri_assert_unreachable ();
   }
}

uint8_t
eri_analyzer__sig_handler (struct eri_analyzer *al,
			struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (eri_entry__sig_is_access_fault (entry, info) && al->sig_info)
    {
      *al->sig_info = *info;
      al->sig_info = 0;

      eri_entry__sig_access_fault (entry, &ctx->mctx);
      return 0;
    }

  if (! al->act) return 1;

  struct block *blk = al->act->trans->block;
  if ((info->code == ERI_SI_TKILL && info->kill.pid == th->group->pid
       && signaled (al->act, info)))
    {
#define SET_FINAL_CTX_REG(reg, v)	do { ctx->mctx.reg = v; } while (0)
      GET_REGS (al->act->local, blk->final_locs, SET_FINAL_CTX_REG);
      return 1;
    }

  uint64_t rip = ctx->mctx.rip;
  struct eri_range range = {
    (uint64_t) blk->insts, (uint64_t) blk->insts + insts_len
  };
  if (! eri_within (&range, rip)) return 1;

  struct reg_loc locs[REG_NUM];
  uint64_t idx = 0;
#define INIT_REG_LOC(creg, reg) \
  if (ERI_PASTE (REG_IDX_, creg) != REG_IDX_RIP)			\
    {									\
      locs[ERI_PASTE (REG_IDX_, creg)].tag = REG_LOC_LOCAL;		\
      locs[ERI_PASTE (REG_IDX_, creg)].val = idx++;			\
    }
  ERI_FOREACH_REG (INIT_REG_LOC)

  locs[REG_IDX_RIP].tag = REG_LOC_IMM;
  locs[REG_IDX_RIP].val = al->act->trans->key.rip;

  uint64_t rip_off = rip - range.start;
  struct trace_reg *traces = blk->trace_regs;

  uint64_t i;
  for (i = 0; i < blk->ntrace_regs && traces[i].rip_off <= rip_off; ++i)
    locs[traces[i].reg_idx] = traces[i].loc;

  struct eri_registers regs;
#define GET_REG_LOC(creg, reg) \
  do {									\
    struct reg_loc *_loc = &locs[ERI_PASTE (REG_IDX_, creg)].loc;	\
    if (_loc->tag == REG_LOC_REG)					\
      regs.reg = get_reg_from_ctx_by_idx (ctx, _loc->val);		\
    else if (_loc->tag == REG_LOC_LOCAL)				\
      regs.reg = al->act->local[_loc->val];				\
    else								\
      regs.reg = _loc->val;						\
  } while (0);
  ERI_FOREACH_REG (GET_REG_LOC)
#define SET_CTX_REG(creg, reg)	ctx->mctx.reg = regs.reg;
  ERI_FOREACH_REG (SET_CTX_REG)

  return 1;
}
