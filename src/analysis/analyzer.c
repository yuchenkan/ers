/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/cpu.h>
#include <lib/util.h>
#include <lib/lock.h>
#include <lib/atomic.h>
#include <lib/buf.h>
#include <lib/list.h>
#include <lib/rbtree.h>
#include <lib/malloc.h>

#include <common/thread.h>
#include <common/debug.h>

#include <xed-util.h>
#include <xed-interface.h>

#include <analysis/analyzer.h>

// #define DUMP_DIS

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

static void
set_reg_loc (struct reg_loc *loc, enum reg_loc_tag tag, uint64_t val)
{
  loc->tag = tag;
  loc->val = val;
}

struct trace_guest
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
  GPREG_NUM = REG_IDX_RFLAGS
};

static eri_unused const char *
reg_idx_str (uint8_t idx)
{
  switch (idx)
    {
#define CASE_REG_IDX(creg, reg) \
  case ERI_PASTE (REG_IDX_, creg):					\
    return ERI_STR (ERI_PASTE (REG_IDX_, creg));
    ERI_FOREACH_REG (CASE_REG_IDX)
    default: eri_assert_unreachable ();
    }
}

struct trace_access
{
  uint64_t rip_off;
  uint8_t len;
  uint64_t idx;
  uint64_t cond_idx;
};

struct accesses
{
  uint64_t num;
  uint32_t *sizes;
  uint8_t *conds;
  uint64_t cond_count;

  struct trace_access *traces;
};

struct block
{
  uint8_t *insts;
  uint64_t insts_len;

  struct trace_guest *traces;
  uint64_t ntraces;

  struct reg_loc final_locs[REG_NUM];

  struct eri_siginfo sig_info;
  uint8_t new_tf;

  struct accesses reads;
  struct accesses writes;

  uint64_t static_local_num;
  uint64_t local_num;

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
  uint32_t done;

  ERI_RBT_NODE_FIELDS (trans, struct trans)
};

struct active
{
  struct eri_analyzer *al;
  struct trans *trans;
  uint8_t *stack;
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
  struct eri_siginfo act_sig_info;
  struct eri_mcontext act_sig_mctx;
};

struct eri_analyzer_group *
eri_analyzer_group__create (struct eri_analyzer_group__create_args *args)
{
  xed_tables_init ();

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
      eri_lassert (t->ref_count == 0);
      eri_assert_mtfree (group->pool, t->block->reads.traces);
      eri_assert_mtfree (group->pool, t->block->writes.traces);
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
  al->act_sig_info.sig = 0;
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

struct ir_def_sextet
{
  struct ir_def *defs[6];
};

struct ir_local;

struct ir_host_locs
{
  uint32_t host_idxs;
  struct ir_local *local;
};

struct ir_live_range
{
  uint64_t ridx;
  uint64_t next_ridx;
  uint64_t guest_count;
  uint8_t dec_guest_count;
};

static void
ir_init_live_range (struct ir_live_range *range)
{
  range->ridx = 0;
  range->next_ridx = 0;
  range->guest_count = 0;
  range->dec_guest_count = 0;
}

struct ir_def
{
  struct ir_node *node;
  uint64_t imm;

  struct ir_live_range range;
  struct ir_host_locs locs;
};

static void
ir_init_def (struct ir_def *def, struct ir_node *node, uint64_t imm)
{
  def->node = node;
  def->imm = imm;
  ir_init_live_range (&def->range);
  def->locs.host_idxs = 0;
  def->locs.local = 0;
}

struct ir_dep
{
  struct ir_def *def;
  uint8_t use_gpreg;
  uint64_t ridx;

  ERI_RBT_NODE_FIELDS (ir_dep, struct ir_dep)
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
  struct ir_dep read;
  struct ir_dep write;
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
  uint8_t addr_size;
};

struct ir_mem
{
  struct ir_mem_regs regs;
  xed_reg_enum_t seg;
  xed_uint_t scale;
  xed_int64_t disp;

  uint32_t size;
  uint8_t addr_size;
};

#define IR_NODE_TAGS(p, ...) \
  p (INST, inst, ##__VA_ARGS__)						\
  p (INIT, init, ##__VA_ARGS__)						\
  p (END, end, ##__VA_ARGS__)						\
  p (ERR_END, err_end, ##__VA_ARGS__)					\
  p (REC_MEM, rec_mem, ##__VA_ARGS__)					\
  p (STORE, store, ##__VA_ARGS__)					\
  p (LOAD, load, ##__VA_ARGS__)						\
  p (ADD, add, ##__VA_ARGS__)						\
  p (COND_STR_OP, cond_str_op, ##__VA_ARGS__)				\
  p (COND_BRANCH, cond_branch, ##__VA_ARGS__)				\

enum ir_node_tag
{
#define DEF_TAG(ctag, tag)	ERI_PASTE (IR_, ctag),
  IR_NODE_TAGS (DEF_TAG)
};

static eri_unused const char *
ir_node_tag_str (enum ir_node_tag tag)
{
  switch (tag)
    {
#define CASE_TAG(ctag, tag) \
  case ERI_PASTE (IR_, ctag): return ERI_STR (ERI_PASTE (IR_, ctag));
    IR_NODE_TAGS (CASE_TAG)
    default: eri_assert_unreachable ();
    }
}

struct ir_node
{
  enum ir_node_tag tag;

  struct ir_def seq;

  ERI_RBT_TREE_FIELDS (ir_dep, struct ir_dep)
  uint64_t deps;

  struct ir_dep follow;

  uint64_t refs;
  ERI_LST_NODE_FIELDS (ir_flat)

  struct ir_def *next_guests[REG_NUM];

  union
    {
      struct
	{
	  xed_decoded_inst_t dec;

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
	  struct ir_mem mem;
	  uint8_t read;
	  uint64_t idx;
	  struct ir_dep memory;
	  struct ir_dep prev;
	  struct ir_dep map_start, map_end;
	} rec_mem;
      struct
	{
	  struct ir_mem dst;
	  struct ir_dep src;
	  struct ir_dep memory;
	  struct ir_dep check;
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
	  struct ir_dep srcs[2];
	} bin;
      struct
	{
	  xed_iclass_enum_t iclass;
	  uint8_t addr_size;

	  struct ir_def dst;

	  struct ir_def def_rdi;
	  struct ir_def def_rsi;
	  struct ir_def def_rax;
	  struct ir_def def_rcx;
	  struct ir_def def_rflags;

	  struct ir_dep rdi;
	  struct ir_dep rsi;
	  struct ir_dep rax;
	  struct ir_dep rcx;
	  struct ir_dep rflags;

	  struct ir_dep taken;
	  struct ir_dep fall;

	  struct ir_dep prev;
	  struct ir_dep memory;
	  struct ir_dep map_start, map_end;

	  uint64_t read_idx;
	  uint64_t cond_read_idx;
	  uint64_t write_idx;
	  uint64_t cond_write_idx;
	} cond_str_op;
      struct
	{
	  xed_iclass_enum_t iclass;
	  uint8_t addr_size;
	  struct ir_def dst;
	  struct ir_def def_rcx;
	  struct ir_dep rflags;
	  struct ir_dep rcx;
	  struct ir_dep taken;
	  struct ir_dep fall;
	} cond_branch;
    };
};

#define IR_DEP_GPREG_VAL	1
#define IR_DEP_RFLAGS_VAL	2

static uint64_t
ir_dep_val (uint8_t rflags)
{
  return rflags ? IR_DEP_RFLAGS_VAL : IR_DEP_GPREG_VAL;
}

static uint64_t
ir_deps (uint8_t gpreg_num, uint8_t rflags_num)
{
  return ir_dep_val (0) * gpreg_num + ir_dep_val (1) * rflags_num;
}

/*
 * Evaluate expressions with more registers required first.
 * XXX: more accurately, we should evaluate expressions with more temporary
 * registers first.
 * XXX: try to make defining and using rflags closer.
 */
static uint8_t
ir_dep_less_than (struct ir_node *n, struct ir_dep *d1, struct ir_dep *d2)
{
  uint64_t n1 = d1->def->node ? d1->def->node->deps : 0;
  uint64_t n2 = d2->def->node ? d2->def->node->deps : 0;
  return n1 == n2 ? d1->def < d2->def : n1 < n2;
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

  ERI_RBT_NODE_FIELDS (ir_redun, struct ir_redun)
};

ERI_DEFINE_LIST (static, ir_redun_node, struct ir_redun, struct ir_redun_node)

struct ir_alloc
{
  ERI_LST_NODE_FIELDS (ir_alloc)
  eri_aligned16 uint8_t buf[0];
};

struct ir_accesses
{
  struct eri_buf sizes;
  struct eri_buf conds;
  uint32_t cond_count;
};

struct ir_dag
{
  struct eri_mtpool *pool;

  struct ir_def *map_start;
  struct ir_def *map_end;

  struct ir_def *syms[REG_NUM];

  ERI_LST_LIST_FIELDS (ir_alloc)

  ERI_RBT_TREE_FIELDS (ir_redun, struct ir_redun)

  struct ir_def *init;
  struct ir_def *memory;
  struct ir_def *prev;
  struct ir_def *last;

  struct ir_accesses reads;
  struct ir_accesses writes;
};

ERI_DEFINE_LIST (static, ir_alloc, struct ir_dag, struct ir_alloc)
ERI_DEFINE_RBTREE (static, ir_redun, struct ir_dag,
		   struct ir_redun, uint64_t, eri_less_than)

struct ir_local
{
  uint64_t idx;
  ERI_RBT_NODE_FIELDS (ir_local, struct ir_local)
};

struct ir_guest_loc
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

  struct ir_guest_loc guest_locs[REG_NUM];

  uint64_t read_num;
  uint64_t cond_read_num;
  uint64_t write_num;
  uint64_t cond_write_num;

  uint64_t local_num;
  ERI_RBT_TREE_FIELDS (ir_local, struct ir_local)
};

ERI_DEFINE_LIST (static, ir_flat, struct ir_flattened, struct ir_node)
ERI_DEFINE_RBTREE (static, ir_local, struct ir_flattened,
		   struct ir_local, uint64_t, eri_less_than)

struct ir_trace_accesses
{
  struct trace_access *traces;
  uint64_t i;
};

struct ir_block
{
  struct eri_buf insts;
  struct eri_buf traces;

  struct reg_loc final_locs[REG_NUM];
  struct eri_siginfo sig_info;

  struct ir_trace_accesses trace_reads;
  struct ir_trace_accesses trace_writes;

  uint64_t local_num;
};

static uint8_t
ir_reg_idx_from_xed_opt (xed_reg_enum_t reg)
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
ir_reg_idx_from_xed (xed_reg_enum_t reg)
{
  uint8_t reg_idx = ir_reg_idx_from_xed_opt (reg);
  eri_lassert (reg_idx != REG_NUM);
  return reg_idx;
}

static xed_reg_enum_t
ir_xed_reg_from_idx_opt (uint8_t reg_idx, uint8_t size)
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
ir_xed_reg_from_idx (uint8_t reg_idx, uint8_t size)
{
  xed_reg_enum_t reg = ir_xed_reg_from_idx_opt (reg_idx, size);
  eri_lassert (reg != XED_REG_INVALID);
  return reg;
}

static void *
ir_alloc (struct ir_dag *dag, uint64_t size)
{
  struct ir_alloc *a = eri_assert_mtmalloc (dag->pool, size + sizeof *a);
  ir_alloc_lst_append (dag, a);
  return a->buf;
}

static struct ir_def *
ir_define (struct ir_node *node, struct ir_def *def)
{
  ir_init_def (def, node, 0);
  return def;
}

static void
ir_depand (struct ir_node *node, struct ir_dep *dep,
	   struct ir_def *def, uint8_t use_gpreg)
{
  dep->def = def;
  if (! def) return;

  dep->use_gpreg = use_gpreg;
  if (! ir_dep_rbt_get (node, dep, ERI_RBT_EQ))
    ir_dep_rbt_insert (node, dep);
  node->deps = eri_max (node->deps, def->node ? def->node->deps : 0);
}

static struct ir_node *
ir_alloc_node (struct ir_dag *dag, enum ir_node_tag tag, uint64_t deps)
{
  struct ir_node *node = ir_alloc (dag, sizeof *node);
  node->tag = tag;
  ir_define (node, &node->seq);
  ERI_RBT_INIT_TREE (ir_dep, node);
  if (dag->init) ir_depand (node, &node->follow, dag->init, 0);
  node->deps = deps;
  node->refs = 0;
  eri_memset (node->next_guests, 0, sizeof node->next_guests);
  return node;
}

static struct ir_def *
ir_get_sym (struct ir_dag *dag, uint64_t id)
{
  return dag->syms[id];
}

static struct ir_def *
ir_get_xsym (struct ir_dag *dag, xed_reg_enum_t reg)
{
  return ir_get_sym (dag, ir_reg_idx_from_xed (reg));
}

static struct ir_def *
ir_get_xsym_opt (struct ir_dag *dag, xed_reg_enum_t reg)
{
  return reg == XED_REG_INVALID ? 0 : ir_get_xsym (dag, reg);
}

static void
ir_set_sym (struct ir_dag *dag, uint64_t id, struct ir_def *def)
{
  dag->syms[id] = def;
}

static void
ir_set_xsym (struct ir_dag *dag, xed_reg_enum_t reg, struct ir_def *def)
{
  ir_set_sym (dag, ir_reg_idx_from_xed (reg), def);
}

static void
ir_copy_xsym (struct ir_dag *dag, xed_reg_enum_t dst, xed_reg_enum_t src)
{
  ir_set_xsym (dag, dst, ir_get_xsym (dag, src));
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

  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    {
      ir_depand (node, node->end.regs + i, ir_get_sym (dag, i), 0);
      node->next_guests[i] = ir_get_sym (dag, i);
    }

  ir_depand (node, &node->end.memory, dag->memory, 0);
  ir_depand (node, &node->end.prev, dag->prev, 0);
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
  // eri_debug ("%lx\n", info);

  ir_do_end (dag, node, IR_ERR_END);

  if (info) node->end.sig_info = *info;
  else node->end.sig_info.sig = 0;
  node->end.len = len;
  if (bytes) eri_memcpy (node->end.bytes, bytes, len);
}

#define ir_eval(dag, type, t, args) \
  ({									\
    struct ir_dag *_dag = dag;						\
    typeof (args) _args = args;						\
    uint64_t _key = ERI_PASTE (ir_hash_, t) (				\
		eri_hash ((uint64_t) ERI_PASTE (ir_eval_, t)), _args);	\
    struct ir_redun_node *_re;						\
    struct ir_redun *_res = ir_redun_rbt_get (_dag, &_key, ERI_RBT_EQ);	\
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
	  if (_re->tag == ERI_PASTE (ir_eval_, t)			\
	      && ERI_PASTE (ir_redun_, t) ((typeof (_args)) _re->buf,	\
					   _args))			\
	    goto _ret;							\
      }									\
    _re = ir_alloc (_dag,						\
	sizeof *_re + eri_size_of (*_args, 16) + sizeof (type));	\
    _re->tag = ERI_PASTE (ir_eval_, t);					\
    *(typeof (_args)) _re->buf = *_args;				\
    *(type *) (_re->buf + eri_size_of (typeof (_args), 16))		\
			= ERI_PASTE (ir_eval_, t) (_dag, _args); 	\
    ir_redun_node_lst_append (_res, _re);				\
  _ret:									\
    *(type *) (_re->buf + eri_size_of (typeof (_args), 16));		\
  })

#define ir_hash_scalar(k, a)	eri_hashs1 (k, *(a))
#define ir_redun_scalar(a1, a2)	(*(a1) == *(a2))

static uint64_t
ir_hash_def_pair (uint64_t key, struct ir_def_pair *args)
{
  return eri_hashs1 (key, (uint64_t) args->first, (uint64_t) args->second);
}

static uint8_t
ir_redun_def_pair (struct ir_def_pair *a1, struct ir_def_pair *a2)
{
  return a1->first == a2->first && a1->second == a2->second;
}

static uint64_t
ir_init_mem (struct ir_node *node, struct ir_mem *mem,
	     struct ir_mem_args *args)
{
  /* XXX: fold const */
  ir_depand (node, &mem->regs.base, args->base, 1);
  ir_depand (node, &mem->regs.index, args->index, 1);
  mem->seg = args->seg;
  mem->scale = args->scale;
  mem->disp = args->disp;
  mem->size = args->size;
  mem->addr_size = args->addr_size;
  return ir_deps (!! args->base + !! args->index, 0);
}

struct ir_rec_mem_args
{
  struct ir_mem_args mem;
  uint8_t read;
};

#if 0
static uint8_t
ir_const_mem_args (struct ir_mem_args *args)
{
  return (! args->base || ! args->base->node)
	 && (! args->index || ! args->index->node)
	 && args->seg == XED_REG_INVALID;
}

static uint64_t
ir_const_mem_args_addr (struct ir_mem_args *args)
{
  uint64_t base = args->base ? args->base->imm : 0;
  uint64_t index = args->index ? args->index->imm : 0;
  eri_lassert (args->addr_size == 8 || args->addr_size == 4);
  uint64_t mask = args->addr_size == 8 ? (uint64_t) -1 : (uint32_t) -1;
  return (base + index * args->scale + args->disp) & mask;
}
#endif

static uint64_t
ir_hash_mem_args (uint64_t key, struct ir_mem_args *args)
{
  key = eri_hashs1 (key, (uint64_t) args->base, (uint64_t) args->index,
		    args->seg, args->disp, args->size, args->addr_size);
  return args->index ? eri_hashs1 (key, args->scale) : key;
}

static uint8_t
ir_redun_mem_args (struct ir_mem_args *a1, struct ir_mem_args *a2)
{
  if (a1->base != a2->base || a1->index != a2->index || a1->seg != a2->seg
      || a1->disp != a2->disp || a1->size != a2->size
      || a1->addr_size != a2->addr_size) return 0;
  return a1->index ? a1->scale == a2->scale : 1;
}

static uint64_t
ir_hash_rec_mem (uint64_t key, struct ir_rec_mem_args *args)
{
  return eri_hashs1 (ir_hash_mem_args (key, &args->mem), args->read);
}

static uint8_t
ir_redun_rec_mem (struct ir_rec_mem_args *a1, struct ir_rec_mem_args *a2)
{
  return ir_redun_mem_args (&a1->mem, &a2->mem) && a1->read == a2->read;
}

static uint64_t
ir_accesses_add_size (struct ir_accesses *acc, uint32_t size)
{
  eri_assert_buf_append (&acc->sizes, &size, sizeof size);
  return acc->sizes.off / sizeof size - 1;
}

static uint64_t
ir_accesses_add_cond (struct ir_accesses *acc, uint8_t cond)
{
  eri_assert_buf_append (&acc->conds, &cond, sizeof cond);
  return cond ? acc->cond_count++ : 0;
}

static struct ir_def *
ir_eval_rec_mem (struct ir_dag *dag, struct ir_rec_mem_args *args)
{
  struct ir_mem_args *mem = &args->mem;
  struct ir_accesses *acc = args->read ? &dag->reads : &dag->writes;

  struct ir_node *node = ir_alloc_node (dag, IR_REC_MEM,
		args->read ? ir_deps (1, 0) : ir_deps (3, 1));
  node->deps += ir_init_mem (node, &node->rec_mem.mem, mem);
  node->rec_mem.read = args->read;
  node->rec_mem.idx = ir_accesses_add_size (acc, mem->size);
  ir_accesses_add_cond (acc, 0);
  ir_depand (node, &node->rec_mem.memory, dag->memory, 0);
  ir_depand (node, &node->rec_mem.prev, dag->prev, 0);
  if (! args->read)
    {
      ir_depand (node, &node->rec_mem.map_start, dag->map_start, 1);
      ir_depand (node, &node->rec_mem.map_end, dag->map_end, 1);
    }
  return &node->seq;
}

static struct ir_def *
ir_get_rec_mem (struct ir_dag *dag, struct ir_mem_args *mem, uint8_t read)
{
  struct ir_rec_mem_args args = { *mem, read };
  return ir_eval (dag, struct ir_def *, rec_mem, &args);
}

static void
ir_create_store (struct ir_dag *dag,
		 struct ir_mem_args *dst, struct ir_def *src)
{
  struct ir_node *node = ir_alloc_node (dag, IR_STORE, ir_deps (1, 0));
  ir_depand (node, &node->store.dst.regs.write,
	     ir_get_rec_mem (dag, dst, 0), 0);
  node->deps += ir_init_mem (node, &node->store.dst, dst);
  ir_depand (node, &node->store.src, src, 1);
  dag->memory = &node->seq;
}

static struct ir_def *
ir_create_load (struct ir_dag *dag,
		struct ir_mem_args *src, struct ir_def *prim)
{
  struct ir_node *node
		= ir_alloc_node (dag, IR_LOAD, ir_deps (prim ? 2 : 1, 0));
  node->deps += ir_init_mem (node, &node->load.src, src);
  ir_depand (node, &node->load.src.regs.read,
	     ir_get_rec_mem (dag, src, 1), 0);
  ir_depand (node, &node->load.prim, prim, 1);
  dag->memory = &node->seq;
  return ir_define (node, &node->load.dst);
}

static struct ir_def *
ir_create_binary (struct ir_dag *dag, enum ir_node_tag tag,
		  struct ir_def_pair *srcs, uint8_t rflags)
{
  struct ir_node *node = ir_alloc_node (dag, tag, ir_deps (3, rflags));
  ir_depand (node, node->bin.srcs, srcs->first, 1);
  ir_depand (node, node->bin.srcs + 1, srcs->second, 1);
  return ir_define (node, &node->bin.dst);
}

#define ir_hash_load_imm(k, a)		ir_hash_scalar (k, a)
#define ir_redun_load_imm(a1, a2)	ir_redun_scalar (a1, a2)

static struct ir_def *
ir_eval_load_imm (struct ir_dag *dag, uint64_t *args)
{
  struct ir_def *def = ir_alloc (dag, sizeof *def);
  ir_init_def (def, 0, *args);
  return def;
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
  struct ir_def *a = args->first;
  struct ir_def *b = args->second;
  if (! a->node && ! b->node)
    return ir_get_load_imm (dag, a->imm + b->imm);
  else if (! a->node && a->imm == 0) return b;
  else if (! b->node && b->imm == 0) return a;
  return ir_create_binary (dag, IR_ADD, args, 1);
}

static struct ir_def *
ir_get_add (struct ir_dag *dag, struct ir_def *a, struct ir_def *b)
{
  if (! a->node
      && (b->node
	  || eri_abs ((int64_t) a->imm) < eri_abs ((int64_t) b->imm)))
    eri_swap (&a, &b);

  struct ir_def_pair args = { a, b };
  return ir_eval (dag, struct ir_def *, add, &args);
}

struct ir_cond_str_op_args
{
  xed_iclass_enum_t iclass;
  uint8_t addr_size;

  struct ir_def *rdi, *rsi, *rax, *rcx, *rflags, *taken, *fall;
};

#define ir_cond_str_op_rdi(iclass) \
  ({ xed_iclass_enum_t _iclass = xed_norep_map (iclass);		\
     _iclass != XED_ICLASS_LODSB && _iclass != XED_ICLASS_LODSW		\
     && _iclass != XED_ICLASS_LODSD && _iclass != XED_ICLASS_LODSQ; })
#define _ir_cond_str_op_rsi(_iclass) \
  ({ xed_iclass_enum_t __iclass = _iclass;				\
     __iclass != XED_ICLASS_STOSB && __iclass != XED_ICLASS_STOSW	\
     && __iclass != XED_ICLASS_STOSD && __iclass != XED_ICLASS_STOSQ	\
     && __iclass != XED_ICLASS_SCASB && __iclass != XED_ICLASS_SCASW	\
     && __iclass != XED_ICLASS_SCASD && __iclass != XED_ICLASS_SCASQ; })
#define ir_cond_str_op_rsi(_iclass) \
  _ir_cond_str_op_rsi (xed_norep_map (iclass))
#define ir_cond_str_op_rax(iclass) \
  ({ xed_iclass_enum_t _iclass = xed_norep_map (iclass);		\
     _iclass == XED_ICLASS_LODSB || _iclass == XED_ICLASS_LODSW		\
     || ! _ir_cond_str_op_rsi (_iclass); })
#define ir_cond_str_op_def_rax(iclass)	(! ir_cond_str_op_rdi (iclass))
#define ir_cond_str_op_def_rflags(iclass) \
  ({ xed_iclass_enum_t _iclass = xed_norep_map (iclass);		\
     _iclass == XED_ICLASS_CMPSB || _iclass == XED_ICLASS_CMPSW		\
     || _iclass == XED_ICLASS_CMPSD || _iclass == XED_ICLASS_CMPSQ	\
     || _iclass == XED_ICLASS_SCASB || _iclass == XED_ICLASS_SCASW	\
     || _iclass == XED_ICLASS_SCASD || _iclass == XED_ICLASS_SCASQ; })

static uint8_t
ir_str_op_size (xed_iclass_enum_t iclass)
{
  switch (iclass)
    {
    case XED_ICLASS_MOVSB:
    case XED_ICLASS_LODSB:
    case XED_ICLASS_STOSB:
    case XED_ICLASS_CMPSB:
    case XED_ICLASS_SCASB:
      return 1;
    case XED_ICLASS_MOVSW:
    case XED_ICLASS_LODSW:
    case XED_ICLASS_STOSW:
    case XED_ICLASS_CMPSW:
    case XED_ICLASS_SCASW:
      return 2;
    case XED_ICLASS_MOVSD:
    case XED_ICLASS_LODSD:
    case XED_ICLASS_STOSD:
    case XED_ICLASS_CMPSD:
    case XED_ICLASS_SCASD:
      return 4;
    case XED_ICLASS_MOVSQ:
    case XED_ICLASS_LODSQ:
    case XED_ICLASS_STOSQ:
    case XED_ICLASS_CMPSQ:
    case XED_ICLASS_SCASQ:
      return 8;
    default: eri_assert_unreachable ();
    }
}

static void
ir_add_cond_access (struct ir_accesses *acc, uint32_t size,
		    uint64_t *idx, uint64_t *cond_idx)
{
  *idx = ir_accesses_add_size (acc, size);
  *cond_idx = ir_accesses_add_cond (acc, 1);
}

static struct ir_def_sextet
ir_create_cond_str_op (struct ir_dag *dag, struct ir_cond_str_op_args *args)
{
  struct ir_def *rcx = args->rcx;
  struct ir_def_sextet sextet = { {
    0, args->rdi, args->rsi, args->rax, rcx, args->rflags
  } };
  struct ir_def **defs = sextet.defs;

  if (! rcx->node
      && (args->addr_size == 8 ? rcx->imm == 0 : (uint32_t) rcx->imm == 0))
    {
      defs[0] = args->fall;
      return sextet;
    }

  xed_iclass_enum_t iclass = args->iclass;
  struct ir_node *node = ir_alloc_node (dag, IR_COND_STR_OP,
	ir_deps (ir_cond_str_op_rdi (iclass) * 2
			+ ir_cond_str_op_rsi (iclass) * 2
			+ ir_cond_str_op_rax (iclass)
			+ ir_cond_str_op_def_rax (iclass) + 5,
		 1 + ir_cond_str_op_def_rflags (iclass)));
  node->cond_str_op.iclass = iclass;
  node->cond_str_op.addr_size = args->addr_size;

  ir_depand (node, &node->cond_str_op.rdi,
	     ir_cond_str_op_rdi (iclass) ? args->rdi : 0, 1);
  ir_depand (node, &node->cond_str_op.rsi,
	     ir_cond_str_op_rsi (iclass) ? args->rsi : 0, 1);
  ir_depand (node, &node->cond_str_op.rax,
	     ir_cond_str_op_rax (iclass) ? args->rax : 0, 1);
  ir_depand (node, &node->cond_str_op.rcx, rcx, 1);
  ir_depand (node, &node->cond_str_op.rflags, args->rflags, 0);
  ir_depand (node, &node->cond_str_op.taken, args->taken, 1);
  ir_depand (node, &node->cond_str_op.fall, args->fall, 1);

  ir_depand (node, &node->cond_str_op.prev, dag->prev, 0);
  ir_depand (node, &node->cond_str_op.memory, dag->memory, 0);

  uint32_t size = ir_str_op_size (xed_norep_map (iclass));
  if (ir_cond_str_op_rsi (iclass))
    ir_add_cond_access (&dag->reads, size, &node->cond_str_op.read_idx,
			&node->cond_str_op.cond_read_idx);
  if (ir_cond_str_op_rdi (iclass))
    {
      ir_add_cond_access (&dag->writes, size, &node->cond_str_op.write_idx,
			  &node->cond_str_op.cond_write_idx);
      ir_depand (node, &node->cond_str_op.map_start, dag->map_start, 1);
      ir_depand (node, &node->cond_str_op.map_end, dag->map_end, 1);
    }

  dag->memory = &node->seq;

  defs[0] = ir_define (node, &node->cond_str_op.dst);
  if (ir_cond_str_op_rdi (iclass))
    defs[1] = ir_define (node, &node->cond_str_op.def_rdi);
  if (ir_cond_str_op_rsi (iclass))
    defs[2] = ir_define (node, &node->cond_str_op.def_rdi);
  if (ir_cond_str_op_def_rax (iclass))
    defs[3] = ir_define (node, &node->cond_str_op.def_rax);
  defs[4] = ir_define (node, &node->cond_str_op.def_rcx);
  if (ir_cond_str_op_def_rflags (iclass))
    defs[5] = ir_define (node, &node->cond_str_op.def_rflags);
  return sextet;
}

struct ir_cond_branch_args
{
  xed_iclass_enum_t iclass;
  uint8_t addr_size;
  struct ir_def *rflags, *rcx, *taken, *fall;
};

#define ir_cond_branch_loop(iclass) \
  ({ xed_iclass_enum_t _iclass = iclass;				\
     _iclass == XED_ICLASS_LOOP || _iclass == XED_ICLASS_LOOPE		\
     || _iclass == XED_ICLASS_LOOPNE; })
#define ir_cond_branch_rcx_only(iclass) \
  ({ xed_iclass_enum_t _iclass = iclass;				\
     _iclass == XED_ICLASS_JECXZ || _iclass == XED_ICLASS_JRCXZ		\
     || _iclass == XED_ICLASS_LOOP; })
#define ir_cond_brancu_rflags_rcx(iclass) \
  ({ xed_iclass_enum_t _iclass = iclass;				\
     _iclass == XED_ICLASS_LOOPE || _iclass == XED_ICLASS_LOOPNE; })
#define ir_cond_branch_rflags_only(iclass) \
  (! ir_cond_branch_rcx_only (iclass) && ! ir_cond_brancu_rflags_rcx (iclass))

static uint64_t
ir_hash_cond_branch (uint64_t key, struct ir_cond_branch_args *args)
{
  xed_iclass_enum_t iclass = args->iclass;
  key = eri_hashs1 (key, IR_COND_BRANCH, iclass);

  if (ir_cond_branch_loop (iclass))
    key = eri_hashs1 (key, args->addr_size);

  if (ir_cond_branch_rcx_only (iclass))
    key = eri_hashs1 (key, (uint64_t) args->rcx);
  else if (ir_cond_brancu_rflags_rcx (iclass))
    key = eri_hashs1 (key, (uint64_t) args->rflags, (uint64_t) args->rcx);
  else
    key = eri_hashs1 (key, (uint64_t) args->rflags);
  return eri_hashs1 (key, (uint64_t) args->taken, (uint64_t) args->fall);
}

static uint8_t
ir_redun_cond_branch (struct ir_cond_branch_args *a1,
		      struct ir_cond_branch_args *a2)
{
  if (a1->iclass != a2->iclass
      || a1->taken != a2->taken || a1->fall != a2->fall) return 0;
  if (ir_cond_branch_loop (a1->iclass) && a1->addr_size != a2->addr_size)
    return 0;
  if (ir_cond_branch_rcx_only (a1->iclass))
    return a1->rcx == a2->rcx;
  else if (ir_cond_brancu_rflags_rcx (a1->iclass))
    return a1->rflags == a2->rflags && a1->rcx == a2->rcx;
  else return a1->rflags == a2->rflags;
}

static uint8_t
ir_cond_flags_taken (uint64_t rflags, xed_iclass_enum_t iclass)
{
  xed_flag_set_t f = { .flat = rflags };
  switch (iclass)
    {
    case XED_ICLASS_JB: return f.s.cf;
    case XED_ICLASS_JBE: return f.s.cf || f.s.zf;
    case XED_ICLASS_JL: return f.s.sf != f.s.of;
    case XED_ICLASS_JLE: return f.s.zf || f.s.sf != f.s.of;
    case XED_ICLASS_JNB: return ! f.s.cf;
    case XED_ICLASS_JNBE: return ! f.s.cf || ! f.s.zf;
    case XED_ICLASS_JNL: return f.s.sf == f.s.of;
    case XED_ICLASS_JNLE: return f.s.zf && f.s.sf == f.s.of;
    case XED_ICLASS_JNO: return ! f.s.of;
    case XED_ICLASS_JNP: return ! f.s.pf;
    case XED_ICLASS_JNS: return ! f.s.sf;
    case XED_ICLASS_JNZ: return ! f.s.zf;
    case XED_ICLASS_JO: return f.s.of;
    case XED_ICLASS_JP: return f.s.pf;
    case XED_ICLASS_JS: return f.s.sf;
    case XED_ICLASS_JZ: return f.s.zf;
    default: eri_assert_unreachable ();
    }
}

static struct ir_def_pair
ir_eval_cond_branch (struct ir_dag *dag, struct ir_cond_branch_args *args)
{
  xed_iclass_enum_t iclass = args->iclass;
  uint8_t addr_size = args->addr_size;
  struct ir_def *rflags = args->rflags;
  struct ir_def *rcx = args->rcx;
  struct ir_def *taken = args->taken;
  struct ir_def *fall = args->fall;

  struct ir_def_pair pair = { 0 };
  if (ir_cond_branch_rcx_only (iclass))
    {
      if (! rcx->node)
	{
	  if (iclass == XED_ICLASS_JECXZ)
	    pair.first = ! (uint32_t) rcx->imm ? taken : fall;
	  else if (iclass == XED_ICLASS_JRCXZ)
	    pair.first = ! rcx->imm ? taken : fall;
	  else
	    pair.first = rcx->imm ? taken : fall;

	  if (iclass == XED_ICLASS_LOOP)
	    pair.second = ir_get_load_imm (dag,
		addr_size == 4 ? (uint32_t) rcx->imm - 1 : rcx->imm - 1);
	  return pair;
	}
    }
  else if (ir_cond_brancu_rflags_rcx (iclass))
    {
      if (! rcx->node && ! rflags->node)
	{
	  pair.first = rcx->imm && ir_cond_flags_taken (rflags->imm,
		iclass == XED_ICLASS_LOOPE ? XED_ICLASS_JZ : XED_ICLASS_JNZ)
			? taken : fall;
	  pair.second = ir_get_load_imm (dag,
		addr_size == 4 ? (uint32_t) rcx->imm - 1 : rcx->imm - 1);
	}
	return pair;
    }
  else if (! rflags->node)
    {
      pair.first = ir_cond_flags_taken (rflags->imm, iclass) ? taken : fall;
      return pair;
    }

  /* XXX: no short-circuit evaluation */
  struct ir_node *node = ir_alloc_node (dag, IR_COND_BRANCH, ir_deps (3, 0));
  node->cond_branch.iclass = iclass;
  node->cond_branch.addr_size = addr_size;
  ir_define (node, &node->cond_branch.dst);
  pair.first = &node->cond_branch.dst;
  if (ir_cond_branch_loop (iclass))
    {
      ir_define (node, &node->cond_branch.def_rcx);
      pair.second = &node->cond_branch.def_rcx;
      node->deps += ir_dep_val (0);
    }
  ir_depand (node, &node->cond_branch.rcx,
	     ! ir_cond_branch_rflags_only (iclass) ? rcx : 0, 1);
  ir_depand (node, &node->cond_branch.rflags,
	     ! ir_cond_branch_rcx_only (iclass) ? rflags : 0, 0);
  node->deps += ir_deps (! ir_cond_branch_rflags_only (iclass),
			 ! ir_cond_branch_rcx_only (iclass));
  ir_depand (node, &node->cond_branch.taken, taken, 1);
  ir_depand (node, &node->cond_branch.fall, fall, 1);
  return pair;
}

static struct ir_def_pair
ir_get_cond_branch (struct ir_dag *dag, struct ir_cond_branch_args *args)
{
  return ir_eval (dag, struct ir_def_pair, cond_branch, args);
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

static uint64_t
ir_get_rip (struct ir_dag *dag)
{
  eri_assert (! ir_get_sym (dag, REG_IDX_RIP)->node);
  return ir_get_sym (dag, REG_IDX_RIP)->imm;
}

static eri_unused void
ir_dump_dis_dec (eri_file_t log, uint64_t rip, xed_decoded_inst_t *dec)
{
  eri_assert_fprintf (log, "%lx:", rip);

  char dis[64];
  eri_assert (xed_format_context (XED_SYNTAX_ATT, dec,
				  dis, sizeof dis, rip, 0, 0));
  eri_assert_fprintf (log, " %s\n", dis);
}

static uint8_t
ir_decode (struct eri_analyzer *al, struct ir_dag *dag,
	   struct ir_node *node, uint8_t len)
{
  uint64_t rip = ir_get_rip (dag);

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

  // eri_debug ("%s %lx %x %x %x\n", xed_error_enum_t2str (err), rip,
  //	     bytes[0], bytes[1], bytes[2]);

#ifdef DUMP_DIS
  if (err == XED_ERROR_NONE && eri_enabled_debug ()
      && eri_assert_syscall (gettid) == eri_assert_syscall (getpid))
    ir_dump_dis_dec (ERI_STDOUT, rip, dec);
#endif

  if (err != XED_ERROR_NONE)
    ir_err_end (dag, node, 0, len, bytes);
  return 1;
}

static struct ir_node *
ir_create_inst (struct eri_analyzer *al, struct ir_dag *dag)
{
  struct ir_node *node = ir_alloc_node (dag, IR_INST, 0);

  uint64_t rip = ir_get_rip (dag);
  uint64_t page = al->group->page_size;
  uint8_t len = eri_min (eri_round_up (rip + 1, page) - rip, INST_BYTES);
  if (! ir_decode (al, dag, node, len))
    ir_decode (al, dag, node, INST_BYTES);

  if (node->tag == IR_ERR_END)
    {
      dag->last = &node->seq;
      return 0;
    }

  return node;
}

static eri_unused void
ir_dump_inst (eri_file_t log, struct ir_node *node)
{
  uint64_t rip = node->next_guests[REG_IDX_RIP]->imm;
  xed_decoded_inst_t *dec = &node->inst.dec;

  xed_category_enum_t cate = xed_decoded_inst_get_category (dec);
  eri_assert_fprintf (log, "cate: %s, ", xed_category_enum_t2str (cate));
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (dec);
  eri_assert_fprintf (log, "iclass: %s, ", xed_iclass_enum_t2str (iclass));
  xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum (dec);
  eri_assert_fprintf (log, "%s, ", xed_iform_to_iclass_string_att (iform));

  xed_uint_t length = xed_decoded_inst_get_length (dec);
  xed_operand_values_t *ops = xed_decoded_inst_operands (dec);

  const xed_inst_t *inst = xed_decoded_inst_inst (dec);
  int noperands = xed_inst_noperands (inst);
  eri_assert_fprintf (log,
	"length: %u, size: %u, addr_size: %u, noperands: %u\n", length,
	xed_operand_values_get_effective_operand_width (ops) >> 3,
	xed_operand_values_get_effective_address_width (ops) >> 3, noperands);

  uint8_t i;
  for (i = 0; i < noperands; ++i)
    {
      const xed_operand_t *op = xed_inst_operand (inst, i);
      xed_operand_enum_t op_name = xed_operand_name (op);
      eri_assert_fprintf (log, "  opname: %s, ",
			  xed_operand_enum_t2str (op_name));

      if (op_name == XED_OPERAND_SEG0
	  || op_name == XED_OPERAND_SEG1
	  || op_name == XED_OPERAND_INDEX
	  || op_name == XED_OPERAND_BASE0
	  || op_name == XED_OPERAND_BASE1
	  || (op_name >= XED_OPERAND_REG0 && op_name <= XED_OPERAND_REG8))
	{
	  xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
	  eri_assert_fprintf (log, "operand: %s, ", xed_reg_enum_t2str (reg));
	}
      else if (op_name == XED_OPERAND_MEM0 || op_name == XED_OPERAND_AGEN)
	{
	  xed_reg_enum_t base = xed_decoded_inst_get_base_reg (dec, 0);
	  xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg (dec, 0);
	  xed_reg_enum_t index = xed_decoded_inst_get_index_reg (dec, 0);
	  xed_int64_t disp = xed_decoded_inst_get_memory_displacement (dec, 0);
	  uint32_t disp_width
		= xed_decoded_inst_get_memory_displacement_width (dec, 0);
	  xed_uint_t length = xed_decoded_inst_operand_length (dec, i);

	  eri_assert (base != XED_REG_FSBASE && base != XED_REG_GSBASE);
	  eri_assert (seg != XED_REG_FSBASE && seg != XED_REG_GSBASE);
	  eri_assert (index != XED_REG_FSBASE && index != XED_REG_GSBASE);

	  eri_assert_fprintf (log, "base: %s, ", xed_reg_enum_t2str (base));
	  eri_assert_fprintf (log, "seg: %s, ", xed_reg_enum_t2str (seg));
	  eri_assert_fprintf (log, "index: %s, ", xed_reg_enum_t2str (index));
	  eri_assert_fprintf (log, "disp: %lx, %lx, ", disp, ~disp + 1);
	  eri_assert_fprintf (log, "disp_width: %u, ", disp_width);
	  eri_assert_fprintf (log, "length: %u, ", length);
	}
      else if (op_name == XED_OPERAND_MEM1)
	{
	  xed_reg_enum_t base = xed_decoded_inst_get_base_reg (dec, 1);
	  xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg (dec, 1);
	  xed_uint_t length = xed_decoded_inst_operand_length (dec, i);

	  eri_assert (base != XED_REG_FSBASE && base != XED_REG_GSBASE);
	  eri_assert (seg != XED_REG_FSBASE && seg != XED_REG_GSBASE);

	  eri_assert_fprintf (log, "base: %s, ", xed_reg_enum_t2str (base));
	  eri_assert_fprintf (log, "seg: %s, ", xed_reg_enum_t2str (seg));
	  eri_assert_fprintf (log, "length: %u, ", length);
	}
      else if (op_name == XED_OPERAND_RELBR)
	{
	  xed_int32_t disp = xed_decoded_inst_get_branch_displacement (dec);

	  eri_assert_fprintf (log, "disp: %x, %x, ", disp, ~disp + 1);
	  eri_assert_fprintf (log, "addr: %lx, ", rip + length + disp);
	}
      else if (op_name == XED_OPERAND_IMM0)
	{
	  xed_uint64_t imm = xed_decoded_inst_get_unsigned_immediate (dec);
	  xed_uint_t is_signed = xed_decoded_inst_get_immediate_is_signed (dec);
	  xed_uint_t width = xed_decoded_inst_get_immediate_width (dec);

	  eri_assert_fprintf (log, "imm: %lx, %lu, %lx, %lu, ",
			      imm, imm, ~imm + 1, ~imm + 1);
	  eri_assert_fprintf (log, "is_signed: %u, ", is_signed);
	  eri_assert_fprintf (log, "width: %u, ", width);
	}

      xed_operand_action_enum_t rw = xed_decoded_inst_operand_action (dec, i);
      eri_assert_fprintf (log, "action: %s\n",
			  xed_operand_action_enum_t2str (rw));
    }
}


static void
ir_init_inst_operands (struct ir_node *node)
{
  uint8_t i;
  for (i = 0; i < eri_length_of (node->inst.regs); ++i)
    node->inst.regs[i].op = 0;
  node->inst.mems[0].op = 0;
  node->inst.mems[0].regs.read.def = 0;
  node->inst.mems[0].regs.write.def = 0;
  node->inst.mems[1].op = 0;
  node->inst.mems[1].regs.read.def = 0;
  node->inst.mems[1].regs.write.def = 0;
  node->inst.access_mem = 0;
  node->inst.relbr = 0;
}

static uint64_t
ir_build_inst_mem_operand (struct ir_dag *dag, struct ir_node *node,
			   const xed_operand_t *op)
{
  xed_decoded_inst_t *dec = &node->inst.dec;
  xed_operand_enum_t op_name = xed_operand_name (op);
  uint8_t i = op_name == XED_OPERAND_MEM1;

  struct ir_mem_regs *m = &node->inst.mems[i].regs;
  xed_reg_enum_t base = xed_decoded_inst_get_base_reg (dec, i);
  xed_reg_enum_t index = xed_decoded_inst_get_index_reg (dec, i);

  ir_depand (node, &m->base, ir_get_xsym_opt (dag, base), 1);
  ir_depand (node, &m->index, ir_get_xsym_opt (dag, index), 1);

  if (op_name != XED_OPERAND_AGEN) node->inst.access_mem = 1;

  xed_attribute_enum_t push = XED_ATTRIBUTE_STACKPUSH0 + i;
  xed_attribute_enum_t pop = XED_ATTRIBUTE_STACKPOP0 + i;

  if (xed_decoded_inst_get_attribute (dec, push)
      || xed_decoded_inst_get_attribute (dec, pop)) return 0;

  node->inst.mems[i].op = op;
  return !! m->base.def + !! m->index.def;
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

  node->next_guests[REG_IDX_RIP] = ir_get_load_imm (dag,
			ir_get_rip (dag) + xed_decoded_inst_get_length (dec));
  ir_set_sym (dag, REG_IDX_RIP, node->next_guests[REG_IDX_RIP]);

  if (xed_decoded_inst_get_iclass (dec) == XED_ICLASS_NOP) return;

  uint64_t deps = 0;
  struct ir_inst_reg *inst_reg = node->inst.regs;
  uint8_t i;
  for (i = 0; i < xed_inst_noperands (inst); ++i)
    {
      const xed_operand_t *op = xed_inst_operand (inst, i);
      xed_operand_enum_t op_name = xed_operand_name (op);

      eri_lassert (op_name != XED_OPERAND_SEG0);
      eri_lassert (op_name != XED_OPERAND_SEG1);
      eri_lassert (op_name != XED_OPERAND_INDEX);
      eri_lassert (op_name != XED_OPERAND_OUTREG);

      // eri_debug ("%s\n", xed_operand_enum_t2str (op_name));
      if (op_name == XED_OPERAND_BASE0 || op_name == XED_OPERAND_BASE1
	  || (op_name >= XED_OPERAND_REG0 && op_name <= XED_OPERAND_REG8))
	{
	  xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
	  uint8_t idx = ir_reg_idx_from_xed_opt (reg);
	  if (reg != XED_REG_RIP && idx != REG_NUM)
	    {
	      if (ir_inst_op_read (dec, op))
		{
		  ir_depand (node, &inst_reg->src, ir_get_sym (dag, idx),
			     reg != XED_REG_RFLAGS);
		  deps += ir_dep_val (idx == XED_REG_RFLAGS);
		}
	      if (xed_operand_written (op))
		{
		  ir_define (node, &inst_reg->dst);
		  node->next_guests[idx] = &inst_reg->dst;
		  deps += ir_dep_val (idx == XED_REG_RFLAGS);
		}

	      (inst_reg++)->op = op;
	    }
	}
      else if (op_name == XED_OPERAND_MEM0 || op_name == XED_OPERAND_AGEN
	       || op_name == XED_OPERAND_MEM1)
	deps += ir_build_inst_mem_operand (dag, node, op);
      else if (op_name == XED_OPERAND_RELBR)
	node->inst.relbr = 1;
      else
	eri_lassert (op_name == XED_OPERAND_IMM0
		     || op_name == XED_OPERAND_IMM1);
    }

  node->deps = eri_max (node->deps, deps);
}

static uint8_t
ir_reg_idx_from_dec_op (xed_decoded_inst_t *dec, const xed_operand_t *op)
{
  return ir_reg_idx_from_xed (
		xed_decoded_inst_get_reg (dec, xed_operand_name (op)));
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
  eri_lassert (args->seg == XED_REG_INVALID || args->seg == XED_REG_FS
	       || args->seg == XED_REG_GS);
  args->scale = xed_decoded_inst_get_scale (dec, i);
  args->disp = xed_decoded_inst_get_memory_displacement (dec, i);
  args->size = xed_decoded_inst_get_memory_operand_length (dec, i);
  args->addr_size = xed_decoded_inst_get_memop_address_width (dec, i) >> 3;
}

static void
ir_inst_mem_access (struct ir_dag *dag, struct ir_node *node,
		    uint8_t i, uint8_t read)
{
  struct ir_inst_mem *mem = node->inst.mems + i;

  struct ir_mem_args args;
  ir_init_mem_args_from_inst_mem (&args, node, i);

  xed_decoded_inst_t *dec = &node->inst.dec;
  xed_attribute_enum_t push = XED_ATTRIBUTE_STACKPUSH0 + i;
  if (xed_decoded_inst_get_attribute (dec, push)) args.disp -= args.size;

  struct ir_dep *rec = read ? &mem->regs.read : &mem->regs.write;
  ir_depand (node, rec, ir_get_rec_mem (dag, &args, read), 0);
}

static void
ir_inst_mem_check (struct ir_dag *dag,
		   struct ir_node *node, uint8_t i)
{
  xed_decoded_inst_t *dec = &node->inst.dec;

  struct ir_inst_mem *mem = node->inst.mems + i;

  uint8_t push = xed_decoded_inst_get_attribute (dec,
					XED_ATTRIBUTE_STACKPUSH0 + i);
  uint8_t pop = xed_decoded_inst_get_attribute (dec,
					XED_ATTRIBUTE_STACKPOP0 + i);

  const xed_operand_t *op = mem->op;
  if (! push && ! pop && ! op) return;

  eri_lassert (! op || xed_operand_name (op) != XED_OPERAND_AGEN);

  if (pop || (op && xed_operand_read (op)))
    ir_inst_mem_access (dag, node, i, 1);
  if (push || (op && xed_operand_written (op)))
    ir_inst_mem_access (dag, node, i, 0);
}

static void
ir_finish_inst (struct ir_dag *dag, struct ir_node *node)
{
  if (node->inst.access_mem)
    {
      ir_inst_mem_check (dag, node, 0);
      ir_inst_mem_check (dag, node, 1);
      dag->memory = &node->seq;
    }

  ir_depand (node, &node->inst.prev, dag->prev, 0);
  dag->prev = &node->seq;

  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (node->next_guests[i] && i != REG_IDX_RIP)
      ir_set_sym (dag, i, node->next_guests[i]);
}

static struct ir_def *
ir_create_load_from_inst_mem (struct ir_dag *dag, struct ir_node *inst,
			      uint8_t i, struct ir_def *prim)
{
  struct ir_mem_args src;
  ir_init_mem_args_from_inst_mem (&src, inst, i);
  return ir_create_load (dag, &src, prim);
}

static void
ir_set_rip (struct ir_dag *dag, uint64_t imm)
{
  ir_set_sym (dag, REG_IDX_RIP, ir_get_load_imm (dag, imm));
}

static void
ir_set_rip_from_reg (struct ir_dag *dag, xed_reg_enum_t src)
{
  ir_copy_xsym (dag, XED_REG_RIP, src);
}

static void
ir_set_rip_from_mem (struct ir_dag *dag, struct ir_node *inst, uint8_t i)
{
  ir_set_sym (dag, REG_IDX_RIP,
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
  ir_set_sym (dag, REG_IDX_RSP, ir_create_push (dag,
	  ir_get_sym (dag, REG_IDX_RSP), ir_get_xsym (dag, src),
	  xed_get_register_width_bits (src) >> 3));
}

static void
ir_build_pop (struct ir_dag *dag, xed_reg_enum_t dst)
{
  struct ir_def *prim = xed_get_register_width_bits (dst) != 64
					? ir_get_xsym (dag, dst) : 0;
  struct ir_def_pair pair = ir_create_pop (dag,
		ir_get_sym (dag, REG_IDX_RSP), prim);
#if 0
  eri_debug ("%s %u %lx\n",
	     xed_reg_enum_t2str (dst), ir_reg_idx_from_xed (dst), pair.first);
#endif
  ir_set_xsym (dag, dst, pair.first);
  ir_set_sym (dag, REG_IDX_RSP, pair.second);
}

static void
ir_build_popf (struct ir_dag *dag, struct ir_node *inst)
{
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (&inst->inst.dec);
  ir_build_pop (dag,
		iclass == XED_ICLASS_POPF ? XED_REG_FLAGS : XED_REG_RFLAGS);
  ir_end (dag, inst);
}

static void
ir_build_cond_str_op (struct ir_dag *dag, struct ir_node *inst)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (dec);
  xed_uint_t length = xed_decoded_inst_get_length (dec);

  if (iclass == XED_ICLASS_REP_INSB || iclass == XED_ICLASS_REP_INSW
      || iclass == XED_ICLASS_REP_INSD || iclass == XED_ICLASS_REP_OUTSB
      || iclass == XED_ICLASS_REP_OUTSW || iclass == XED_ICLASS_REP_OUTSD)
    {
      struct eri_siginfo info = { .sig = ERI_SIGSEGV, .code = ERI_SI_KERNEL };
      ir_err_end (dag, inst, &info, length, 0);
      return;
    }

  xed_operand_values_t *ops = xed_decoded_inst_operands (dec);

  struct ir_cond_str_op_args args = {
    iclass, xed_operand_values_get_effective_address_width (ops) >> 3,
    ir_get_sym (dag, REG_IDX_RDI), ir_get_sym (dag, REG_IDX_RSI),
    ir_get_sym (dag, REG_IDX_RAX), ir_get_sym (dag, REG_IDX_RCX),
    ir_get_sym (dag, REG_IDX_RFLAGS),
    ir_get_load_imm (dag, ir_get_rip (dag) - length),
    ir_get_sym (dag, REG_IDX_RIP)
  };
  struct ir_def_sextet sextet = ir_create_cond_str_op (dag, &args);
  struct ir_def **defs = sextet.defs;
  ir_set_sym (dag, REG_IDX_RIP, defs[0]);
  ir_set_sym (dag, REG_IDX_RDI, defs[1]);
  ir_set_sym (dag, REG_IDX_RSI, defs[2]);
  ir_set_sym (dag, REG_IDX_RAX, defs[3]);
  ir_set_sym (dag, REG_IDX_RCX, defs[4]);
  ir_set_sym (dag, REG_IDX_RFLAGS, defs[5]);

  ir_end (dag, inst);
}

static void
ir_build_uncond_branch (struct ir_dag *dag, struct ir_node *inst)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  if (inst->inst.relbr)
    /*
     * XXX: leave only because this is simple, this makes INST the only
     * tag updating reg_defs, which makes it easier to trace regs.
     * Review this, reg_defs is renamed to syms.
     */
    ir_set_rip (dag, ir_get_rip (dag)
			+ xed_decoded_inst_get_branch_displacement (dec));
  else
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
  struct ir_def *taken = ir_get_load_imm (dag, ir_get_rip (dag) + disp);
  struct ir_def *fall = ir_get_load_imm (dag, ir_get_rip (dag));

  struct ir_cond_branch_args args = {
    iclass, xed_operand_values_get_effective_address_width (ops) >> 3,
    ir_get_sym (dag, REG_IDX_RFLAGS),
    ir_get_sym (dag, REG_IDX_RCX), taken, fall
  };
  struct ir_def_pair pair = ir_get_cond_branch (dag, &args);
  ir_set_sym (dag, REG_IDX_RIP, pair.first);
  if (pair.second)
    ir_set_sym (dag, REG_IDX_RCX, pair.second);

  ir_end (dag, inst);
}

static void
ir_build_call (struct ir_dag *dag, struct ir_node *inst)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  ir_build_push (dag, XED_REG_RIP);
  if (inst->inst.relbr)
    ir_set_rip (dag, ir_get_rip (dag)
			+ xed_decoded_inst_get_branch_displacement (dec));
  else
    ir_set_uncond_rip (dag, inst,
	xed_decoded_inst_get_iform_enum (dec) == XED_IFORM_CALL_NEAR_GPRv);
  ir_end (dag, inst);
}

static void
ir_build_ret (struct ir_dag *dag, struct ir_node *inst)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  ir_build_pop (dag, XED_REG_RIP);
  ir_set_sym (dag, REG_IDX_RSP, ir_get_add (dag,
	ir_get_sym (dag, REG_IDX_RSP),
	ir_get_load_imm (dag, xed_decoded_inst_get_unsigned_immediate (dec))));
  ir_end (dag, inst);
}

static void
ir_mark_ref (struct ir_dag *dag, struct ir_node *node)
{
  if (node->refs++) return;

  struct ir_dep *dep;
  ERI_RBT_FOREACH (ir_dep, node, dep)
    if (dep->def->node) ir_mark_ref (dag, dep->def->node);
}

static void
ir_flatten (struct ir_flattened *flat, struct ir_node *node)
{
  if (--node->refs) return;

  ++flat->ridx;
  struct ir_dep *dep;
  ERI_RBT_FOREACH (ir_dep, node, dep)
    if (dep->use_gpreg)
      {
	dep->ridx = dep->def->range.ridx;
	dep->def->range.ridx = dep->def->range.next_ridx = flat->ridx;
      }

  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (node->next_guests[i])
      ++node->next_guests[i]->range.guest_count;

  ir_flat_lst_insert_front (flat, node);

  ERI_RBT_FOREACH (ir_dep, node, dep)
    if (dep->def->node) ir_flatten (flat, dep->def->node);
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
  return !! (host_idxs & (1 << host_idx));
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

static uint8_t
ir_host_idxs_has_gpreg (uint32_t host_idxs)
{
  return !! (host_idxs & ((1 << GPREG_NUM) - 1));
}

static struct ir_local *
ir_alloc_local (struct ir_flattened *flat)
{
  struct ir_local *local = ir_alloc (flat->dag, sizeof *local);
  local->idx = flat->local_num++;
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
ir_local_host_idx (struct ir_flattened *flat)
{
  return ir_host_idxs_get_gpreg_idx (flat->local.locs.host_idxs);
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
  uint8_t addr_size;
};

static uint8_t
ir_encode (uint8_t *bytes, xed_encoder_request_t *enc)
{
  uint32_t res;
  eri_lassert (xed_encode (enc, bytes, INST_BYTES, &res) == XED_ERROR_NONE);
  return res;
}

static xed_reg_enum_t
ir_xreg (uint8_t idx)
{
  return ir_xed_reg_from_idx (idx, 8);
}

static void
ir_init_encode (xed_encoder_request_t *enc,
		xed_iclass_enum_t iclass, uint8_t size, uint8_t addr_size)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
  xed_encoder_request_zero_set_mode (enc, &state);
  xed_encoder_request_set_iclass (enc, iclass);
  xed_encoder_request_set_effective_operand_width (enc, size << 3);
  xed_encoder_request_set_effective_address_size (enc, addr_size << 3);
}

static uint8_t
ir_encode_bin (uint8_t *bytes, xed_iclass_enum_t iclass,
	       uint8_t dst, uint8_t src)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG1, ir_xreg (src));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_REG1);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_bin_imm (uint8_t *bytes, xed_iclass_enum_t iclass,
		   uint8_t dst, uint64_t src)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_uimm0 (&enc, src, 4);
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_IMM0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_mov (uint8_t *bytes, uint8_t dst, uint8_t src)
{
  // eri_debug ("\n");
  return ir_encode_bin (bytes, XED_ICLASS_MOV, dst, src);
}

static eri_unused uint8_t
ir_min_width_unsigned (uint64_t x, uint8_t mask)
{
  uint8_t res = xed_shortest_width_unsigned (x, mask & 0x7);
  eri_lassert (res != 8 || mask & 0x8);
  return res;
}

static uint8_t
ir_min_width_signed (int64_t x, uint8_t mask)
{
  uint8_t res = xed_shortest_width_signed (x, mask & 0x7);
  eri_lassert (res != 8 || mask & 0x8);
  return res;
}

static void
ir_encode_set_mem0 (xed_encoder_request_t *enc, struct ir_enc_mem_args *mem)
{
  xed_encoder_request_set_base0 (enc,
			ir_xed_reg_from_idx_opt (mem->base, mem->addr_size));
  xed_encoder_request_set_index (enc,
			ir_xed_reg_from_idx_opt (mem->index, mem->addr_size));
  xed_encoder_request_set_seg0 (enc, mem->seg);
  xed_encoder_request_set_scale (enc, mem->scale);
  xed_encoder_request_set_memory_displacement (enc, mem->disp,
				ir_min_width_signed (mem->disp, 0x4));
  xed_encoder_request_set_memory_operand_length (enc, mem->size);
}

static uint8_t
ir_encode_load (uint8_t *bytes, uint8_t dst, struct ir_enc_mem_args *src)
{
  // eri_debug ("%u %u %u %lu\n", dst, src->base, src->index, src->disp);
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, src->size, src->addr_size);

  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0,
			       ir_xed_reg_from_idx (dst, src->size));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_mem0 (&enc);
  ir_encode_set_mem0 (&enc, src);
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_MEM0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_load_imm (uint8_t *bytes, uint8_t dst, int64_t src)
{
  // eri_debug ("%s %lx\n", reg_idx_str (dst), src);
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, 8, 8);

  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_uimm0 (&enc, src,
				 ir_min_width_signed (src, 0xc));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_IMM0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_store (uint8_t *bytes, struct ir_enc_mem_args *dst, uint8_t src)
{
  // eri_debug ("%u %u %lu %u\n", dst->base, dst->index, dst->disp, src);
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, dst->size, dst->addr_size);

  xed_encoder_request_set_mem0 (&enc);
  ir_encode_set_mem0 (&enc, dst);
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_MEM0);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0,
			       ir_xed_reg_from_idx (src, dst->size));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_REG0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_store_imm (uint8_t *bytes, struct ir_enc_mem_args *dst,
		     uint64_t src)
{
  // eri_debug ("%u %u %lu %lu\n", dst->base, dst->index, dst->disp, src);
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, dst->size, dst->addr_size);

  xed_encoder_request_set_mem0 (&enc);
  ir_encode_set_mem0 (&enc, dst);
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_MEM0);
  xed_encoder_request_set_uimm0 (&enc, src, eri_min (dst->size, 4));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_IMM0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_lea (uint8_t *bytes, uint8_t dst, struct ir_enc_mem_args *src)
{
#if 0
  eri_debug ("%u %u %u %lu %u %u\n", dst,
	     src->base, src->index, src->disp, src->size, src->addr_size);
#endif
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_LEA, 8, src->addr_size);

  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_agen (&enc);
  ir_encode_set_mem0 (&enc, src);
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_AGEN);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_pushf (uint8_t *bytes)
{
  // eri_debug ("\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_PUSHFQ, 8, 8);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_popf (uint8_t *bytes)
{
  // eri_debug ("\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_POPFQ, 8, 8);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_cmov (uint8_t *bytes, xed_iclass_enum_t iclass,
		uint8_t dst, uint8_t src)
{
  // eri_debug ("\n");
  return ir_encode_bin (bytes, iclass, dst, src);
}

static uint8_t
ir_encode_add (uint8_t *bytes, uint8_t dst, uint8_t src)
{
  // eri_debug ("\n");
  return ir_encode_bin (bytes, XED_ICLASS_ADD, dst, src);
}

static uint8_t
ir_encode_add_imm (uint8_t *bytes, uint8_t dst, uint64_t src)
{
  return ir_encode_bin_imm (bytes, XED_ICLASS_ADD, dst, src);
}

static uint8_t
ir_encode_str_op (uint8_t *bytes, xed_iclass_enum_t iclass,
		  uint8_t addr_size)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, ir_str_op_size (iclass), addr_size);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_cmp (uint8_t *bytes, uint8_t a, uint8_t b)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_CMP, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (a));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG1, ir_xreg (b));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_REG1);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_jmp (uint8_t *bytes, uint8_t dst)
{
  // eri_debug ("\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_JMP, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_jmp_mem (uint8_t *bytes, struct ir_enc_mem_args *dst)
{
  // eri_debug ("\n");
  xed_encoder_request_t enc;
  eri_lassert (dst->size == 8);
  ir_init_encode (&enc, XED_ICLASS_JMP, dst->size, dst->addr_size);
  xed_encoder_request_set_mem0 (&enc);
  ir_encode_set_mem0 (&enc, dst);
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_MEM0);
  return ir_encode (bytes, &enc);
}

static uint8_t
ir_encode_cjmp_relbr (uint8_t *bytes, xed_iclass_enum_t iclass,
		      uint8_t addr_size, int64_t rel)
{
  // eri_debug ("\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, 8, addr_size);
  xed_encoder_request_set_relbr (&enc);
  xed_encoder_request_set_branch_displacement (&enc, rel,
	ir_min_width_signed (rel, ir_cond_branch_loop (iclass) ? 0x1 : 0x7));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_RELBR);
  return ir_encode (bytes, &enc);
}

#define IR_FOREACH_LOCKABLE_ICLASS(p, ...) \
  p (ADC, ##__VA_ARGS__)						\
  p (ADD, ##__VA_ARGS__)						\
  p (AND, ##__VA_ARGS__)						\
  p (BTC, ##__VA_ARGS__)						\
  p (BTR, ##__VA_ARGS__)						\
  p (BTS, ##__VA_ARGS__)						\
  p (CMPXCHG, ##__VA_ARGS__)						\
  p (CMPXCHG16B, ##__VA_ARGS__)						\
  p (CMPXCHG8B, ##__VA_ARGS__)						\
  p (DEC, ##__VA_ARGS__)						\
  p (INC, ##__VA_ARGS__)						\
  p (NEG, ##__VA_ARGS__)						\
  p (NOT, ##__VA_ARGS__)						\
  p (OR, ##__VA_ARGS__)							\
  p (SBB, ##__VA_ARGS__)						\
  p (SUB, ##__VA_ARGS__)						\
  p (XADD, ##__VA_ARGS__)						\
  p (XOR, ##__VA_ARGS__)

static xed_iclass_enum_t
ir_remove_lock (xed_iclass_enum_t iclass)
{
  switch (iclass)
    {
#define NOLOCK_MAP(c) \
  case ERI_PASTE2 (XED_ICLASS_, c, _LOCK):				\
    return ERI_PASTE (XED_ICLASS_, c);
    IR_FOREACH_LOCKABLE_ICLASS (NOLOCK_MAP)
    default: return iclass;
    }
}

static uint8_t
ir_encode_inst (uint8_t *bytes, xed_decoded_inst_t *dec)
{
  // eri_debug ("\n");
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (dec);

  xed_encoder_request_init_from_decode (dec);
  xed_encoder_request_t *enc = dec;
  xed_encoder_request_set_iclass (enc, ir_remove_lock (iclass));
  return ir_encode (bytes, enc);
}

static void
ir_emit_raw (struct ir_block *blk, uint8_t *bytes, uint64_t len)
{
#ifdef DUMP_DIS
  if (eri_enabled_debug ()
      && eri_assert_syscall (gettid) == eri_assert_syscall (getpid))
    {
      xed_decoded_inst_t dec;
      uint64_t i;
      for (i = 0; i != len; i += xed_decoded_inst_get_length (&dec))
	{
	  xed_decoded_inst_zero (&dec);
	  xed_decoded_inst_set_mode (&dec, XED_MACHINE_MODE_LONG_64,
				     XED_ADDRESS_WIDTH_64b);
	  xed_error_enum_t err = xed_decode (&dec, bytes + i,
					     eri_min (len - i, INST_BYTES));
	  eri_assert (err != XED_ERROR_BUFFER_TOO_SHORT);
	  if (err != XED_ERROR_NONE)
	    {
	      eri_assert_printf ("%lx:", blk->insts.off + i);
	      uint8_t j;
	      for (j = 0; j < len - i; ++j)
		eri_assert_printf (" %x", bytes[i + j]);
	      eri_assert_printf ("\n");
	      break;
	    }
	  else ir_dump_dis_dec (ERI_STDOUT, blk->insts.off + i, &dec);
	}
    }
#endif

  eri_assert_buf_append (&blk->insts, bytes, len);
  // eri_debug ("rip: %lx\n", blk->insts.off);
}

#define ir_emit(what, blk, ...) \
  ({									\
    uint8_t _bytes[INST_BYTES];						\
    uint8_t _l = ERI_PASTE (ir_encode_, what) (_bytes, ##__VA_ARGS__);	\
    ir_emit_raw (blk, _bytes, _l);					\
    _l;									\
  })

static void
ir_init_guest_loc (struct ir_guest_loc *guest_loc)
{
  struct ir_def *guest = guest_loc->def;
  struct ir_host_locs *locs = &guest->locs;
  struct reg_loc *trace = &guest_loc->loc;

  if (! guest->node)
    set_reg_loc (trace, REG_LOC_IMM, guest->imm);
  else
    {
      uint8_t host_idx = ir_host_idxs_get_reg_idx (locs->host_idxs);
      if (host_idx != REG_NUM)
	set_reg_loc (trace, REG_LOC_REG, host_idx);
      else
	set_reg_loc (trace, REG_LOC_LOCAL, locs->local->idx);
    }
}

static void
ir_update_trace_guest (struct ir_block *blk, uint8_t idx,
		       struct reg_loc loc)
{
  struct trace_guest t = { blk->insts.off, idx, loc };
  eri_assert_buf_append (&blk->traces, &t, sizeof t);
}

static void
ir_try_fix_guest_loc (struct ir_block *blk, uint8_t idx,
		      struct ir_guest_loc *guest_loc)
{
  struct ir_def *guest = guest_loc->def;
  struct ir_host_locs *locs = &guest->locs;
  struct reg_loc *trace = &guest_loc->loc;

#if 0
  eri_debug ("def: %lx, host_idxs: %x, local: %lx, tag: %u, val: %u\n",
	     guest, locs->host_idxs, locs->local, trace->tag, trace->val);
#endif

  if ((trace->tag == REG_LOC_REG
       && ! ir_host_idxs_set (locs->host_idxs, trace->val))
      || (trace->tag == REG_LOC_LOCAL
	  && (! locs->local || locs->local->idx != trace->val))
      || (trace->tag == REG_LOC_IMM
	  && (guest->node || guest->imm != trace->val)))
    {
      ir_init_guest_loc (guest_loc);
      ir_update_trace_guest (blk, idx, *trace);
    }
}

static void
ir_try_update_guest_loc (struct ir_flattened *flat, struct ir_block *blk,
			 struct ir_def *def)
{
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (flat->guest_locs[i].def == def)
      ir_try_fix_guest_loc (blk, i, flat->guest_locs + i);
}

static uint8_t
ir_def_in_use (struct ir_def *def)
{
  return def->range.ridx || def->range.guest_count;
}

static uint8_t
ir_def_continue_in_use (struct ir_def *def)
{
  return def->range.next_ridx
	 || def->range.guest_count - def->range.dec_guest_count;
}

struct ir_ra
{
  uint8_t host_idx;
  struct ir_def *dep;
  struct ir_def *def;
  uint8_t exclusive;
};

static void
ir_init_ra (struct ir_ra *a, uint8_t idx,
	    struct ir_def *dep, struct ir_def *def)
{
  a->host_idx = idx;
  a->dep = dep;
  a->def = def;
  a->exclusive = 0;
}

static eri_unused void
ir_dump_ras (eri_file_t log, struct ir_ra *ras, uint32_t n)
{
  uint32_t i;
  for (i = 0; i < n; ++i)
    {
      eri_assert_fprintf (log, "ir_ra: %u, %lx, %lx, %u\n",
		ras[i].host_idx, ras[i].dep, ras[i].def, ras[i].exclusive);
      if (ras[i].dep)
	eri_assert_fprintf (log, "  dep: %lx, %x, %lx\n", ras[i].dep,
		ras[i].dep->locs.host_idxs, ras[i].dep->locs.local);
      if (ras[i].def)
	eri_assert_fprintf (log, "  def: %lx, %x, %lx\n", ras[i].def,
		ras[i].def->locs.host_idxs, ras[i].def->locs.local);
    }
}

struct ir_assign
{
  uint8_t order;
  struct ir_def *dep;
  struct ir_def *def;
  struct ir_def *check_guest;
  uint8_t exclusive;
  uint8_t destroyed;
};

static void
ir_assign_dep_try_reuse (struct ir_assign *assigns, struct ir_ra *ra)
{
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (assigns[i].dep == ra->dep && ! assigns[i].exclusive
	&& ! ra->exclusive && (! assigns[i].def || ! ra->def))
      {
	ra->host_idx = i;
	if (ra->def) assigns[i].def = ra->def;
	break;
      }
}

static void
ir_assign_set_dep (struct ir_assign *assigns, uint8_t i,
		   struct ir_ra *ra, uint8_t order)
{
  ra->host_idx = i;
  assigns[i].order = order;
  assigns[i].dep = ra->dep;
  if (! assigns[i].def)
    {
      assigns[i].def = ra->def;
      assigns[i].exclusive = ra->exclusive;
    }
}

static uint8_t
ir_assign_dep_assignable (struct ir_assign *assign, struct ir_ra *ra)
{
  return ! assign->dep
	 && (! assign->def
	     || (! assign->exclusive && ! ra->exclusive && ! ra->def));
}

static void
ir_assign_dep_try_current (struct ir_assign *assigns, struct ir_ra *ra,
			   uint8_t order)
{
  uint8_t i;
  for (i = 0; i < GPREG_NUM; ++i)
    if (! assigns[i].destroyed && ir_assign_dep_assignable (assigns + i, ra)
	&& ir_host_idxs_set (ra->dep->locs.host_idxs, i))
      {
	ir_assign_set_dep (assigns, i, ra, order);
	break;
      }
}

static uint8_t
ir_assign_more_than_one_host_gpregs (
			struct ir_def *def, struct ir_assign *assigns)
{
  uint8_t i, n = 0;
  for (i = 0; i < GPREG_NUM; ++i)
    if ((assigns[i].dep == def
	 || (ir_host_idxs_set (def->locs.host_idxs, i)
	     && (! assigns[i].destroyed && ! assigns[i].dep)))
	&& n++)
      return 1;
  return 0;
}

static uint64_t
ir_assign_get_ridx (struct ir_def *def, uint8_t next)
{
  uint64_t ridx = next ? def->range.next_ridx : def->range.ridx;
  return def->node ? ridx : (ridx + 1) / 2;
}

static void
ir_assign_dep_pick (struct ir_flattened *flat, struct ir_assign *assigns,
		    struct ir_ra *ra, uint8_t order)
{
  uint8_t min = REG_NUM;
  uint64_t min_ridx = -1;

  uint8_t i;
  for (i = 0; i < GPREG_NUM; ++i)
    if (ir_assign_dep_assignable (assigns + i, ra))
      {
	struct ir_def *old = flat->hosts[i];
	if (assigns[i].destroyed || ! ir_def_in_use (old)
	    || ir_assign_more_than_one_host_gpregs (old, assigns))
	  {
	    min = i;
	    break;
	  }

	if (assigns[i].def)
	  {
	    min = i;
	    min_ridx = 0;
	  }
	else if (ir_assign_get_ridx (old, 0) < min_ridx)
	  {
	    min = i;
	    min_ridx = ir_assign_get_ridx (old, 0);
	  }
      }

  // eri_debug ("pick %s\n", reg_idx_str (min));
  eri_lassert (min != REG_NUM);
  ir_assign_set_dep (assigns, min, ra, order);
}

static void
ir_assign_def_pick (struct ir_flattened *flat, struct ir_assign *assigns,
		    struct ir_ra *ra, uint8_t order)
{
  uint8_t min = REG_NUM;
  uint64_t min_ridx = -1;

  uint8_t i;
  for (i = 0; i < GPREG_NUM; ++i)
    if (! assigns[i].def && (! assigns[i].dep || ! ra->exclusive))
      {
	if (! assigns[i].dep && assigns[i].destroyed)
	  {
	    min = i;
	    break;
	  }

	struct ir_def *old = assigns[i].dep ? : flat->hosts[i];
	if (! ir_def_continue_in_use (old)
	    || ir_assign_more_than_one_host_gpregs (old, assigns))
	  {
	    min = i;
	    break;
	  }

        if (ir_assign_get_ridx (old, 1) < min_ridx)
	  {
	    min = i;
	    min_ridx = ir_assign_get_ridx (old, 1);
	  }
      }

  // eri_debug ("pick %s\n", reg_idx_str (min));
  eri_lassert (min != REG_NUM);
  ra->host_idx = min;
  assigns[i].order = order;
  assigns[i].def = ra->def;
}

static uint8_t
ir_host_locs_has_gpreg_or_local (struct ir_host_locs *locs)
{
  return ir_host_idxs_has_gpreg (locs->host_idxs) || locs->local;
}

static void
ir_assign_check_rflags (struct ir_flattened *flat,
		struct ir_assign *assigns, struct ir_ra *ras, uint32_t n)
{
  struct ir_def *old = flat->hosts[REG_IDX_RFLAGS];

  if (assigns[REG_IDX_RFLAGS].dep && assigns[REG_IDX_RFLAGS].dep != old)
    {
      assigns[REG_IDX_RSP].destroyed = 1;
      return;
    }

  if (! ir_def_in_use (old)
      || ir_host_locs_has_gpreg_or_local (&old->locs))
    return;

  if (assigns[REG_IDX_RFLAGS].def && ir_def_continue_in_use (old))
    {
      assigns[REG_IDX_RSP].destroyed = 1;
      return;
    }

  uint32_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (assigns[i].dep == old)
      {
	assigns[REG_IDX_RSP].destroyed = 1;
	return;
      }

  for (i = 0; i < n; ++i)
    if (ras[i].host_idx == REG_NUM && ras[i].dep && ras[i].dep == old)
      {
	assigns[REG_IDX_RSP].destroyed = 1;
	return;
      }
}

static void
ir_init_host (struct ir_flattened *flat, uint8_t idx, struct ir_def *def)
{
  // eri_debug ("%lx %u\n", def, idx);

  flat->hosts[idx] = def;
  ir_host_idxs_add (&def->locs.host_idxs, idx);
}

static void
ir_set_host (struct ir_flattened *flat, uint8_t idx, struct ir_def *def)
{
  // eri_debug ("%s = %lx\n", reg_idx_str (idx), def);
  ir_host_idxs_del (&flat->hosts[idx]->locs.host_idxs, idx);
  ir_init_host (flat, idx, def);
}

static uint64_t
ir_assign_get_local (struct ir_flattened *flat, struct ir_def *def)
{
  eri_assert (! def->locs.local);
  def->locs.local = ir_get_local (flat);
  return def->locs.local->idx;
}

static void
ir_assign_init_local_enc_mem_args_size (struct ir_flattened *flat,
		uint64_t idx, struct ir_enc_mem_args *args, uint8_t size)
{
  args->base = ir_local_host_idx (flat);
  args->index = REG_NUM;
  args->seg = XED_REG_INVALID;
  args->scale = 1;
  args->disp = idx * size;
  args->size = size;
  args->addr_size = 8;
}

static void
ir_assign_init_local_enc_mem_args (struct ir_flattened *flat, uint64_t idx,
				   struct ir_enc_mem_args *args)
{
  ir_assign_init_local_enc_mem_args_size (flat, idx, args, 8);
}

static void
ir_assign_move (struct ir_flattened *flat, struct ir_block *blk,
		struct reg_loc dst, struct reg_loc src)
{
  // eri_debug ("\n");
  struct ir_enc_mem_args mem;
  if (dst.tag == REG_LOC_REG)
    {
      if (dst.val == REG_IDX_RFLAGS)
	{
	  eri_assert (src.tag == REG_LOC_LOCAL);
	  ir_assign_init_local_enc_mem_args (flat, src.val, &mem);
	  ir_emit (lea, blk, REG_IDX_RSP, &mem);
	  ir_emit (popf, blk);
	}
      else if (src.tag == REG_LOC_REG)
	ir_emit (mov, blk, dst.val, src.val);
      else if (src.tag == REG_LOC_LOCAL)
	{
	  ir_assign_init_local_enc_mem_args (flat, src.val, &mem);
	  ir_emit (load, blk, dst.val, &mem);
	}
      else
	ir_emit (load_imm, blk, dst.val, src.val);
    }
  else if (src.tag == REG_LOC_REG)
    {
      if (src.val == REG_IDX_RFLAGS)
	{
	  ir_assign_init_local_enc_mem_args (flat, dst.val + 1, &mem);
	  ir_emit (lea, blk, REG_IDX_RSP, &mem);
	  ir_emit (pushf, blk);
	}
      else
	{
	  ir_assign_init_local_enc_mem_args (flat, dst.val, &mem);
	  ir_emit (store, blk, &mem, src.val);
	}
    }
  else
    {
      ir_assign_init_local_enc_mem_args (flat, dst.val, &mem);
      ir_emit (store_imm, blk, &mem, src.val);
    }
}

static uint8_t
ir_assign_may_spill (struct ir_def *def, uint8_t idx)
{
  if (! def->node) return 0;

  struct ir_host_locs locs = def->locs;
  ir_host_idxs_del (&locs.host_idxs, idx);
  return ! ir_host_locs_has_gpreg_or_local (&locs);
}

/*
 * Hosts update in the following order:
 * 1. update location
 * 2. emit code to update
 * 3. update reg def
 * This is consistent with the process of the instruction to generate.
 */
static void
ir_assign_spill (struct ir_flattened *flat, struct ir_block *blk,
		 struct ir_def *def, struct ir_assign *assigns)
{
  if (! ir_host_idxs_has_gpreg (def->locs.host_idxs))
    {
      struct ir_def *check_guest = flat->hosts[REG_IDX_RSP];

      struct reg_loc dst = {
	REG_LOC_LOCAL, ir_assign_get_local (flat, def)
      };
      struct reg_loc src = { REG_LOC_REG, REG_IDX_RFLAGS };
      ir_set_host (flat, REG_IDX_RSP, &flat->dummy);
      ir_assign_move (flat, blk, dst, src);
      ir_try_update_guest_loc (flat, blk, check_guest);
      return;
    }

  uint8_t i;
  for (i = 0; i < GPREG_NUM; ++i)
    if (! ir_def_in_use (flat->hosts[i])
	&& def == assigns[i].dep && ! assigns[i].destroyed)
      break;

  if (i == GPREG_NUM)
    for (i = 0; i < GPREG_NUM; ++i)
      if (! ir_def_in_use (flat->hosts[i])
	  && ! assigns[i].dep && ! assigns[i].def && ! assigns[i].destroyed)
	break;

  struct reg_loc src = {
    REG_LOC_REG, ir_host_idxs_get_gpreg_idx (def->locs.host_idxs)
  };

  if (i != GPREG_NUM)
    {
      struct reg_loc dst = { REG_LOC_REG, i };
      ir_set_host (flat, i, def);
      ir_assign_move (flat, blk, dst, src);
      return;
    }

  struct reg_loc dst = { REG_LOC_LOCAL, ir_assign_get_local (flat, def) };
  // eri_debug ("%lu\n", dst.val);
  ir_assign_move (flat, blk, dst, src);
}

static void
ir_assign_prepare_rflags (struct ir_flattened *flat,
			  struct ir_block *blk, struct ir_assign *assigns)
{
  if (ir_def_in_use (flat->hosts[REG_IDX_RSP])
      && ir_assign_may_spill (flat->hosts[REG_IDX_RSP], REG_IDX_RSP))
    ir_assign_spill (flat, blk, flat->hosts[REG_IDX_RSP], assigns);
}

static void
ir_assign_save_to_local (struct ir_flattened *flat, struct ir_block *blk,
			 struct ir_def *def, uint8_t tmp_idx)
{
  struct reg_loc dst = { REG_LOC_LOCAL, ir_assign_get_local (flat, def) };
  struct reg_loc src;
  uint8_t gpreg = ir_host_idxs_get_gpreg_idx (def->locs.host_idxs);
  if (gpreg != REG_NUM)
    {
      src.tag = REG_LOC_REG;
      src.val = gpreg;
    }
  else
    {
      eri_lassert (! def->node);
      set_reg_loc (&src, REG_LOC_IMM, def->imm);
      if (ir_min_width_signed (src.val, 0xc) == 8)
	{
	  struct reg_loc tmp = { REG_LOC_REG, tmp_idx };
	  ir_assign_move (flat, blk, tmp, src);
	  src = tmp;
	}
    }
  ir_assign_move (flat, blk, dst, src);
}

static void
ir_assign_load_dep (struct ir_flattened *flat, struct ir_block *blk,
		    uint8_t idx, struct ir_def *def)
{
  struct reg_loc dst = { REG_LOC_REG, idx };

  if (idx == REG_IDX_RFLAGS)
    {
      ir_set_host (flat, idx, def);
      ir_set_host (flat, REG_IDX_RSP, &flat->dummy);
      if (! def->locs.local)
	ir_assign_save_to_local (flat, blk, def, REG_IDX_RSP);

      struct reg_loc src = { REG_LOC_LOCAL, def->locs.local->idx };
      ir_assign_move (flat, blk, dst, src);
      return;
    }

  uint8_t gpreg = ir_host_idxs_get_gpreg_idx (def->locs.host_idxs);
  ir_set_host (flat, idx, def);
  struct reg_loc src;
  if (! def->node)
    set_reg_loc (&src, REG_LOC_IMM, def->imm);
  else if (gpreg != REG_NUM)
    set_reg_loc (&src, REG_LOC_REG, gpreg);
  else
    set_reg_loc (&src, REG_LOC_LOCAL, def->locs.local->idx);
  ir_assign_move (flat, blk, dst, src);
}

static void
ir_assign_assign (struct ir_flattened *flat, struct ir_block *blk,
		  struct ir_assign *assigns, uint8_t i)
{
  struct ir_def *old = flat->hosts[i];

  if (i == REG_IDX_RFLAGS)
    {
      uint8_t i;
      for (i = 0; i < GPREG_NUM && assigns[i].dep != old; ++i)
	continue;
      if (i != GPREG_NUM &&
	  ! ir_host_locs_has_gpreg_or_local (&old->locs))
	{
	  ir_assign_prepare_rflags (flat, blk, assigns);
	  ir_assign_spill (flat, blk, old, assigns);
	}
    }

  if (assigns[i].dep && assigns[i].dep != old)
    {
      struct ir_def *check_guest = 0;

      if (i == REG_IDX_RFLAGS)
	ir_assign_prepare_rflags (flat, blk, assigns);
      if (ir_def_in_use (old) && ir_assign_may_spill (old, i))
	{
	  check_guest = old;
	  ir_assign_spill (flat, blk, old, assigns);
	}

      ir_assign_load_dep (flat, blk, i, assigns[i].dep);

      if (check_guest)
	ir_try_update_guest_loc (flat, blk, check_guest);
    }

  if (! assigns[i].def) return;

  if (assigns[i].dep) old = assigns[i].dep;

  if (ir_def_continue_in_use (old) && ir_assign_may_spill (old, i))
    {
      assigns[i].check_guest = old;
      if (i == REG_IDX_RFLAGS)
	ir_assign_prepare_rflags (flat, blk, assigns);
      ir_assign_spill (flat, blk, old, assigns);
    };
  ir_set_host (flat, i, assigns[i].def);
}

static void
ir_assign_update_usage (struct ir_flattened *flat, struct ir_node *node)
{
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (node->next_guests[i])
      flat->guest_locs[i].def->range.dec_guest_count = 1;

  struct ir_dep *dep;
  ERI_RBT_FOREACH (ir_dep, node, dep)
    if (dep->use_gpreg)
      dep->def->range.next_ridx = dep->ridx;
}

static void
ir_assign_may_free_local (struct ir_flattened *flat, struct ir_def *def)
{
  if (ir_def_in_use (def) || ! def->locs.local) return;
  ir_put_local (flat, def->locs.local);
  def->locs.local = (void *) -1; /* sanity check */
}

static void
ir_assign_update_free_deps (struct ir_flattened *flat,
			    struct ir_block *blk, struct ir_node *node)
{
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (node->next_guests[i])
      {
	--flat->guest_locs[i].def->range.guest_count;
	flat->guest_locs[i].def->range.dec_guest_count = 0;
	ir_assign_may_free_local (flat, flat->guest_locs[i].def);
	flat->guest_locs[i].def = node->next_guests[i];
	ir_try_fix_guest_loc (blk, i, flat->guest_locs + i);
      }

  struct ir_dep *dep;
  ERI_RBT_FOREACH (ir_dep, node, dep)
    if (dep->use_gpreg)
      {
	dep->def->range.ridx = dep->ridx;
	ir_assign_may_free_local (flat, dep->def);
      }
}

static struct ir_ra *
ir_append_ra (struct eri_buf *ras, uint8_t idx,
	      struct ir_def *dep, struct ir_def *def)
{
  if (! dep && ! def) return 0;

  struct ir_ra a;
  ir_init_ra (&a, idx, dep, def);
  eri_assert_buf_append (ras, &a, sizeof a);
  return (void *) ((uint8_t *) ras->buf + ras->off - sizeof a);
}

static void
ir_append_mem_ras (struct eri_buf *ras, struct ir_mem *mem)
{
  ir_append_ra (ras, REG_NUM, mem->regs.base.def, 0);
  ir_append_ra (ras, REG_NUM, mem->regs.index.def, 0);
}

static struct ir_ra *
ir_init_emit_mem_args (struct ir_enc_mem_args *args,
		       struct ir_mem *mem, struct ir_ra *a)
{
  args->base = mem->regs.base.def ? (a++)->host_idx : REG_NUM;
  args->index = mem->regs.index.def ? (a++)->host_idx : REG_NUM;

  args->seg = mem->seg;
  args->scale = mem->scale;
  args->disp = mem->disp;
  args->size = mem->size;
  args->addr_size = mem->addr_size;
  return a;
}

static void
ir_add_trace_access (struct ir_trace_accesses *traces,
	uint64_t rip_off, uint8_t len, uint64_t idx, uint64_t cond_idx)
{
  struct trace_access *trace = traces->traces + traces->i++;
  trace->rip_off = rip_off;
  trace->len = len;
  trace->idx = idx;
  trace->cond_idx = cond_idx;
}

static void
ir_trace_access (struct ir_block *blk, struct ir_node *node, uint8_t len)
{
  ir_add_trace_access (
		node->rec_mem.read ? &blk->trace_reads : &blk->trace_writes,
		blk->insts.off, len, node->rec_mem.idx, -1);
}

static void
ir_try_trace_access (struct ir_block *blk, struct ir_def *def, uint8_t len)
{
  if (def) ir_trace_access (blk, def->node, len);
}

static void
ir_assign_gen_inst_ras (struct ir_node *node, struct eri_buf *ras)
{
  xed_decoded_inst_t *dec = &node->inst.dec;

  struct ir_inst_reg *inst_reg;
  for (inst_reg = node->inst.regs; inst_reg->op; ++inst_reg)
    {
      const xed_operand_t *op = inst_reg->op;
      ir_append_ra (ras, ir_inst_designated_reg (dec, op)
			? ir_reg_idx_from_dec_op (dec, op) : REG_NUM,
		    ir_inst_op_read (dec, op) ? inst_reg->src.def : 0,
		    xed_operand_written (op) ? &inst_reg->dst : 0);
    }

  struct ir_def *mems[] = {
    node->inst.mems[0].op ? node->inst.mems[0].regs.base.def : 0,
    node->inst.mems[0].op ? node->inst.mems[0].regs.index.def : 0,
    node->inst.mems[1].op ? node->inst.mems[1].regs.base.def : 0
  };

  uint8_t i;
  for (i = 0; i < eri_length_of (mems); ++i)
    if (mems[i]) ir_append_ra (ras, REG_NUM, mems[i], 0);
}

static void
ir_assign_emit_inst (struct ir_block *blk, struct ir_node *node,
		     struct ir_ra *a)
{
  xed_decoded_inst_t *dec = &node->inst.dec;
  xed_operand_values_t *ops = xed_decoded_inst_operands (dec);

  struct ir_inst_reg *inst_reg;
  for (inst_reg = node->inst.regs; inst_reg->op; ++inst_reg)
    {
      xed_operand_enum_t op_name = xed_operand_name (inst_reg->op);
      xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
      uint8_t size = xed_get_register_width_bits64 (reg) >> 3;
      xed_operand_values_set_operand_reg (ops, op_name,
				ir_xed_reg_from_idx ((a++)->host_idx, size));
    }

  struct ir_def *mems[] = {
    node->inst.mems[0].op ? node->inst.mems[0].regs.base.def : 0,
    node->inst.mems[0].op ? node->inst.mems[0].regs.index.def : 0,
    node->inst.mems[1].op ? node->inst.mems[1].regs.base.def : 0
  };

  xed_operand_enum_t mem_op_names[] = {
    XED_OPERAND_BASE0, XED_OPERAND_INDEX, XED_OPERAND_BASE1
  };

  uint8_t i;
  for (i = 0; i < eri_length_of (mem_op_names); ++i)
    if (mems[i])
      xed_operand_values_set_operand_reg (ops, mem_op_names[i],
				ir_xed_reg_from_idx ((a++)->host_idx, 8));

  uint8_t len = ir_emit (inst, blk, &node->inst.dec);

  ir_try_trace_access (blk, node->inst.mems[0].regs.read.def, len);
  ir_try_trace_access (blk, node->inst.mems[0].regs.write.def, len);
  ir_try_trace_access (blk, node->inst.mems[1].regs.read.def, len);
  ir_try_trace_access (blk, node->inst.mems[1].regs.write.def, len);
}

static void
ir_assign_gen_end_ras (struct ir_flattened *flat,
		       struct ir_node *node, struct eri_buf *ras)
{
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (i != ir_local_host_idx (flat) && i != REG_IDX_RIP)
      ir_append_ra (ras, i, 0, &flat->dummy);
}

eri_noreturn static void analysis (uint64_t *local);

static void
ir_assign_emit_end (struct ir_flattened *flat, struct ir_block *blk,
		    struct ir_node *node)
{
  ir_emit (mov, blk, REG_IDX_RDX, ir_local_host_idx (flat));
  struct ir_enc_mem_args rsp = {
    REG_IDX_RDX, REG_NUM,
    .disp = __builtin_offsetof (struct active, stack)
		- __builtin_offsetof (struct active, local),
    .size = 8, .addr_size = 8
  };
  ir_emit (load, blk, REG_IDX_RDI, &rsp);
  ir_emit (load_imm, blk, REG_IDX_RSI, (uint64_t) analysis);
  ir_emit (load_imm, blk, REG_IDX_RCX, (uint64_t) eri_jump);
  ir_emit (jmp, blk, REG_IDX_RCX);

  struct ir_dep *regs = node->end.regs;
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (! regs[i].def->node)
      set_reg_loc (blk->final_locs + i, REG_LOC_IMM, regs[i].def->imm);
    else
      set_reg_loc (blk->final_locs + i, REG_LOC_LOCAL,
		   regs[i].def->locs.local->idx);
}

static void
ir_assign_gen_rec_mem_ras (struct ir_flattened *flat,
			   struct ir_node *node, struct eri_buf *ras)
{
  if (node->rec_mem.mem.seg != XED_REG_INVALID) return; // TODO fs gs

  ir_append_mem_ras (ras, &node->rec_mem.mem);
  if (node->rec_mem.read)
    ir_append_ra (ras, REG_NUM, 0, &flat->dummy);
  else
    {
      ir_append_ra (ras, REG_NUM, 0, &flat->dummy)->exclusive = 1;
      ir_append_ra (ras, REG_NUM, node->rec_mem.map_start.def, 0);
      ir_append_ra (ras, REG_NUM, node->rec_mem.map_end.def, 0);
      ir_append_ra (ras, REG_IDX_RFLAGS, 0, &flat->dummy);
    }
}

enum
{
  LOCAL_INVALID_WRITE,
  LOCAL_PREDEFINED_NUM
};

#define IR_ASSIGN_ENCODE_REC_CHECK_WRITE_INST_NUM	5

static uint32_t
ir_assign_encode_rec_check_write (struct ir_flattened *flat,
	uint8_t *bytes, uint8_t addr, uint8_t map_start, uint8_t map_end)
{
  uint8_t invalid[INST_BYTES];
  struct ir_enc_mem_args invalid_write;
  ir_assign_init_local_enc_mem_args (flat, LOCAL_INVALID_WRITE,
				     &invalid_write);
  uint8_t invalid_len = ir_encode_jmp_mem (invalid, &invalid_write);

  uint8_t end[INST_BYTES * 2];
  uint8_t end_len = ir_encode_cmp (end, addr, map_end);
  end_len += ir_encode_cjmp_relbr (end + end_len, XED_ICLASS_JNB,
				   8, invalid_len);

  uint8_t len = ir_encode_cmp (bytes, addr, map_start);
  len += ir_encode_cjmp_relbr (bytes + len, XED_ICLASS_JB,
			       8, end_len + invalid_len);
  eri_memcpy (bytes + len, end, end_len);
  eri_memcpy (bytes + len + end_len, invalid, invalid_len);
  return len + end_len + invalid_len;
}

static void
ir_assign_emit_rec_mem (struct ir_flattened *flat, struct ir_block *blk,
			struct ir_node *node, struct ir_ra *a)
{
  if (node->rec_mem.mem.seg != XED_REG_INVALID) return; // TODO fs gs

  struct ir_enc_mem_args mem;
  a = ir_init_emit_mem_args (&mem, &node->rec_mem.mem, a);
  ir_emit (lea, blk, a->host_idx, &mem);
  struct ir_enc_mem_args rec;
  uint64_t idx = LOCAL_PREDEFINED_NUM;
  if (! node->rec_mem.read) idx += flat->read_num + flat->cond_read_num;
  ir_assign_init_local_enc_mem_args (flat, idx + node->rec_mem.idx, &rec);
  ir_emit (store, blk, &rec, a->host_idx);
  if (! node->rec_mem.read)
    {
      uint8_t check[INST_BYTES * IR_ASSIGN_ENCODE_REC_CHECK_WRITE_INST_NUM];
      uint32_t len = ir_assign_encode_rec_check_write (flat, check,
			a->host_idx, (a + 1)->host_idx, (a + 2)->host_idx);
      ir_emit_raw (blk, check, len);
    }
}

static uint8_t
ir_assign_def_fits_imml (struct ir_def *def)
{
  return ! def->node && ir_min_width_signed (def->imm, 0xc) == 4;
}

static void
ir_assign_gen_store_ras (struct ir_node *node, struct eri_buf *ras)
{
  ir_append_mem_ras (ras, &node->store.dst);
  struct ir_def *src = node->store.src.def;
  if (! ir_assign_def_fits_imml (src))
    ir_append_ra (ras, REG_NUM, src, 0);
}

static void
ir_assign_emit_store (struct ir_block *blk,
		      struct ir_node *node, struct ir_ra *a)
{
  struct ir_enc_mem_args dst;
  a = ir_init_emit_mem_args (&dst, &node->store.dst, a);
  struct ir_def *src = node->store.src.def;
  uint8_t len = ! ir_assign_def_fits_imml (src)
			? ir_emit (store, blk, &dst, a->host_idx)
			: ir_emit (store_imm, blk, &dst, src->imm);
  ir_trace_access (blk, node->store.dst.regs.write.def->node, len);
}

static void
ir_assign_gen_load_ras (struct ir_node *node, struct eri_buf *ras)
{
  ir_append_ra (ras, REG_NUM, node->load.prim.def, &node->load.dst);
  ir_append_mem_ras (ras, &node->load.src);
}

static void
ir_assign_emit_load (struct ir_block *blk,
		     struct ir_node *node, struct ir_ra *a)
{
  struct ir_enc_mem_args src;
  ir_init_emit_mem_args (&src, &node->load.src, a + 1);
  uint8_t len = ir_emit (load, blk, a->host_idx, &src);
  ir_trace_access (blk, node->load.src.regs.read.def->node, len);
}

static void
ir_assign_gen_add_ras (struct ir_flattened *flat,
		       struct ir_node *node, struct eri_buf *ras)
{
  ir_append_ra (ras, REG_NUM, node->bin.srcs[0].def, &node->bin.dst);
  if (! ir_assign_def_fits_imml (node->bin.srcs[1].def))
    ir_append_ra (ras, REG_NUM, node->bin.srcs[1].def, 0);
  ir_append_ra (ras, REG_IDX_RFLAGS, 0, &flat->dummy);
}

static void
ir_assign_emit_add (struct ir_block *blk,
		    struct ir_node *node, struct ir_ra *a)
{
  struct ir_def *sec = node->bin.srcs[1].def;
  if (! ir_assign_def_fits_imml (sec))
    ir_emit (add, blk, a[0].host_idx, a[1].host_idx);
  else
    ir_emit (add_imm, blk, a[0].host_idx, sec->imm);
}

static void
ir_assign_gen_cond_str_op_ras (struct ir_flattened *flat,
			       struct ir_node *node, struct eri_buf *ras)
{
  xed_iclass_enum_t iclass = node->cond_str_op.iclass;
  if (ir_cond_str_op_rdi (iclass))
    ir_append_ra (ras, REG_IDX_RDI, node->cond_str_op.rdi.def,
		  &node->cond_str_op.def_rdi)->exclusive = 1;
  if (ir_cond_str_op_rsi (iclass))
    ir_append_ra (ras, REG_IDX_RSI, node->cond_str_op.rsi.def,
		  &node->cond_str_op.def_rsi)->exclusive = 1;
  if (ir_cond_str_op_def_rax (iclass))
    ir_append_ra (ras, REG_IDX_RAX, node->cond_str_op.rax.def,
		  &node->cond_str_op.def_rax)->exclusive = 1;
  else ir_append_ra (ras, REG_IDX_RAX, node->cond_str_op.rax.def, 0);
  ir_append_ra (ras, REG_IDX_RCX, node->cond_str_op.rcx.def,
		&node->cond_str_op.def_rcx)->exclusive = 1;;
  struct ir_def *def_rflags = ir_cond_str_op_def_rflags (iclass)
			? &node->cond_str_op.def_rflags
			: (ir_cond_str_op_rdi (iclass) ? &flat->dummy : 0);
  ir_append_ra (ras, REG_IDX_RFLAGS,
		node->cond_str_op.rflags.def, def_rflags);
  ir_append_ra (ras, REG_NUM, node->cond_str_op.taken.def,
		&node->cond_str_op.dst);
  if (node->cond_str_op.fall.def->node)
    ir_append_ra (ras, REG_NUM, node->cond_str_op.fall.def, 0);

  if (ir_cond_str_op_rdi (iclass))
    {
      ir_append_ra (ras, REG_NUM, node->cond_str_op.map_start.def, 0);
      ir_append_ra (ras, REG_NUM, node->cond_str_op.map_end.def, 0);
    }
}

static uint8_t
ir_assign_encode_cjmp_set_fall (uint8_t *bytes,
				struct ir_def *def, struct ir_ra *a)
{
  return def->node
	? ir_encode_mov (bytes, (a - 2)->host_idx, (a - 1)->host_idx)
	: ir_encode_load_imm (bytes, (a - 1)->host_idx, def->imm);
}

static xed_iclass_enum_t
ir_cjmp_iclass_from_cond_str_op (xed_iclass_enum_t iclass)
{
  switch (iclass)
    {
    case XED_ICLASS_REP_MOVSB:
    case XED_ICLASS_REP_MOVSW:
    case XED_ICLASS_REP_MOVSD:
    case XED_ICLASS_REP_MOVSQ:
    case XED_ICLASS_REP_LODSB:
    case XED_ICLASS_REP_LODSW:
    case XED_ICLASS_REP_LODSD:
    case XED_ICLASS_REP_LODSQ:
    case XED_ICLASS_REP_STOSB:
    case XED_ICLASS_REP_STOSW:
    case XED_ICLASS_REP_STOSD:
    case XED_ICLASS_REP_STOSQ:
      return XED_ICLASS_LOOP;
    case XED_ICLASS_REPE_CMPSB:
    case XED_ICLASS_REPE_CMPSW:
    case XED_ICLASS_REPE_CMPSD:
    case XED_ICLASS_REPE_CMPSQ:
    case XED_ICLASS_REPE_SCASB:
    case XED_ICLASS_REPE_SCASW:
    case XED_ICLASS_REPE_SCASD:
    case XED_ICLASS_REPE_SCASQ:
      return XED_ICLASS_LOOPE;
    case XED_ICLASS_REPNE_CMPSB:
    case XED_ICLASS_REPNE_CMPSW:
    case XED_ICLASS_REPNE_CMPSD:
    case XED_ICLASS_REPNE_CMPSQ:
    case XED_ICLASS_REPNE_SCASB:
    case XED_ICLASS_REPNE_SCASW:
    case XED_ICLASS_REPNE_SCASD:
    case XED_ICLASS_REPNE_SCASQ:
      return XED_ICLASS_LOOPNE;
    default: eri_assert_unreachable ();
    }
}

#define IR_ASSIGN_ENCODE_REC_STR_OP_ACCESS_INST_NUM	3

static eri_unused uint32_t
ir_assign_encode_rec_str_op_access (struct ir_flattened *flat, uint8_t *bytes,
				    struct ir_node *node, uint8_t read)
{
  uint64_t base = LOCAL_PREDEFINED_NUM;
  if (! read) base += flat->read_num + flat->cond_read_num;
  uint64_t num = read ? flat->read_num : flat->write_num;
  uint64_t idx = read ? node->cond_str_op.read_idx
		      : node->cond_str_op.write_idx;
  uint64_t cond_idx = read ? node->cond_str_op.cond_read_idx
			   : node->cond_str_op.cond_write_idx;
  uint8_t reg_idx = read ? REG_IDX_RSI : REG_IDX_RDI;

  uint8_t len = 0;
  if (node->cond_str_op.addr_size == 4)
    {
      struct ir_enc_mem_args mem = { reg_idx, REG_NUM, .addr_size = 4 };
      len = ir_encode_lea (bytes, reg_idx, &mem);
    }

  struct ir_enc_mem_args rec;
  ir_assign_init_local_enc_mem_args (flat, base + idx, &rec);
  len += ir_encode_store (bytes + len, &rec, reg_idx);
  ir_assign_init_local_enc_mem_args_size (flat,
				8 * (base + num) + cond_idx, &rec, 1);
  return len + ir_encode_store_imm (bytes + len, &rec, 1);
}

static void
ir_assign_emit_cond_str_op (struct ir_flattened *flat, struct ir_block *blk,
			    struct ir_node *node, struct ir_ra *a)
{
  xed_iclass_enum_t iclass = node->cond_str_op.iclass;
  uint8_t addr_size = node->cond_str_op.addr_size;

  uint32_t inst_num = IR_ASSIGN_ENCODE_REC_STR_OP_ACCESS_INST_NUM * 2
			+ IR_ASSIGN_ENCODE_REC_CHECK_WRITE_INST_NUM + 2;
  uint8_t op[INST_BYTES * inst_num];
  uint32_t len = 0;
  if (ir_cond_str_op_rsi (iclass))
    len = ir_assign_encode_rec_str_op_access (flat, op, node, 1);
  if (ir_cond_str_op_rdi (iclass))
    {
      len += ir_assign_encode_rec_str_op_access (flat, op + len, node, 0);
      uint8_t map_end = (--a)->host_idx;
      uint8_t map_start = (--a)->host_idx;
      len += ir_assign_encode_rec_check_write (flat, op + len, 
				REG_IDX_RDI, map_start, map_end);
    }

  uint32_t str_op_len = ir_encode_str_op (op + len,
					  xed_norep_map (iclass), addr_size);
  uint32_t str_op_off = len += str_op_len;

  uint8_t fall[INST_BYTES];
  uint8_t fall_len = ir_assign_encode_cjmp_set_fall (fall,
					node->cond_str_op.fall.def, a);
  len += ir_encode_cjmp_relbr (op + len,
	ir_cjmp_iclass_from_cond_str_op (iclass), addr_size, fall_len);

  ir_emit (cjmp_relbr, blk, addr_size == 8
		? XED_ICLASS_JRCXZ : XED_ICLASS_JECXZ, addr_size, len);

  uint64_t str_op_rip_off = blk->insts.off + str_op_off;
  if (ir_cond_str_op_rsi (iclass))
    ir_add_trace_access (&blk->trace_reads, str_op_rip_off, str_op_len,
	node->cond_str_op.read_idx, node->cond_str_op.cond_read_idx);
  if (ir_cond_str_op_rdi (iclass))
    ir_add_trace_access (&blk->trace_writes, str_op_rip_off, str_op_len,
	node->cond_str_op.write_idx, node->cond_str_op.cond_write_idx);

  ir_emit_raw (blk, op, len);
  ir_emit_raw (blk, fall, fall_len);
}

static void
ir_assign_gen_cond_branch_ras (struct ir_node *node, struct eri_buf *ras)
{
  xed_iclass_enum_t iclass = node->cond_branch.iclass;
  ir_append_ra (ras, REG_IDX_RFLAGS, node->cond_branch.rflags.def, 0);
  if (ir_cond_branch_loop (iclass))
    ir_append_ra (ras, REG_IDX_RCX, node->cond_branch.rcx.def,
		  &node->cond_branch.def_rcx)->exclusive = 1;
  else ir_append_ra (ras, REG_IDX_RCX, node->cond_branch.rcx.def, 0);

  if (! ir_cond_branch_rflags_only (iclass))
    {
      ir_append_ra (ras, REG_NUM, node->cond_branch.taken.def,
		    &node->cond_branch.dst);
      if (node->cond_branch.fall.def->node)
	ir_append_ra (ras, REG_NUM, node->cond_branch.fall.def, 0);
    }
  else
    {
      ir_append_ra (ras, REG_NUM, node->cond_branch.fall.def,
		    &node->cond_branch.dst);
      ir_append_ra (ras, REG_NUM, node->cond_branch.taken.def, 0);
    }
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
ir_assign_emit_cond_branch (struct ir_block *blk,
			    struct ir_node *node, struct ir_ra *a)
{
  xed_iclass_enum_t iclass = node->cond_branch.iclass;

  if (! ir_cond_branch_rflags_only (iclass))
    {
      uint8_t bytes[INST_BYTES];
      uint8_t len = ir_assign_encode_cjmp_set_fall (bytes,
					node->cond_branch.fall.def, a);
      ir_emit (cjmp_relbr, blk, iclass, node->cond_branch.addr_size, len);
      ir_emit_raw (blk, bytes, len);
    }
  else ir_emit (cmov, blk, ir_cmov_iclass (iclass),
		(a - 2)->host_idx, (a - 1)->host_idx);
}

static void
ir_assign_gen_ras (struct ir_flattened *flat, struct ir_node *node,
		   struct eri_buf *ras)
{
  switch (node->tag)
    {
    case IR_INST: ir_assign_gen_inst_ras (node, ras); break;
    case IR_END:
    case IR_ERR_END:
      ir_assign_gen_end_ras (flat, node, ras); break;
    case IR_REC_MEM: ir_assign_gen_rec_mem_ras (flat, node, ras); break;
    case IR_STORE: ir_assign_gen_store_ras (node, ras); break;
    case IR_LOAD: ir_assign_gen_load_ras (node, ras); break;
    case IR_ADD: ir_assign_gen_add_ras (flat, node, ras); break;
    case IR_COND_STR_OP:
      ir_assign_gen_cond_str_op_ras (flat, node, ras); break;
    case IR_COND_BRANCH: ir_assign_gen_cond_branch_ras (node, ras); break;
    default: eri_assert_unreachable ();
    }
}

static void
ir_assign_emit (struct ir_flattened *flat, struct ir_block *blk,
		struct ir_node *node, struct ir_ra *ras, uint32_t n)
{
  switch (node->tag)
    {
    case IR_INST: ir_assign_emit_inst (blk, node, ras); break;
    case IR_END:
    case IR_ERR_END:
      ir_assign_emit_end (flat, blk, node);
      if (node->tag == IR_ERR_END)
	blk->sig_info = node->end.sig_info;
      break;
    case IR_REC_MEM: ir_assign_emit_rec_mem (flat, blk, node, ras); break;
    case IR_STORE: ir_assign_emit_store (blk, node, ras); break;
    case IR_LOAD: ir_assign_emit_load (blk, node, ras); break;
    case IR_ADD: ir_assign_emit_add (blk, node, ras); break;
    case IR_COND_STR_OP:
      ir_assign_emit_cond_str_op (flat, blk, node, ras + n); break;
    case IR_COND_BRANCH:
      ir_assign_emit_cond_branch (blk, node, ras + n); break;
    default: eri_assert_unreachable ();
    }
}

static void
ir_assign_hosts (struct ir_flattened *flat, struct ir_block *blk,
		 struct ir_node *node)
{
#ifdef DUMP_DIS
  if (eri_assert_syscall (gettid) == eri_assert_syscall (getpid))
    eri_debug ("%s\n", ir_node_tag_str (node->tag));
#endif

  ir_assign_update_usage (flat, node);

  struct eri_buf ras_buf;
  eri_assert_buf_mtpool_init (&ras_buf, flat->dag->pool,
			      sizeof (struct ir_ra) * 32);
  ir_assign_gen_ras (flat, node, &ras_buf);

  struct ir_ra *ras = ras_buf.buf;
  uint32_t n = ras_buf.off / sizeof *ras;

  // ir_dump_ras (ERI_STDOUT, ras, n);

  struct ir_assign assigns[REG_NUM] = { 0 };

  uint32_t i, j;
  for (i = 0; i < n; ++i)
    if (ras[i].host_idx != REG_NUM)
      {
	struct ir_assign *a = assigns + ras[i].host_idx;
	if (ras[i].dep) a->dep = ras[i].dep;
	a->def = ras[i].def;
	a->exclusive = ras[i].exclusive;
       }

  ir_assign_check_rflags (flat, assigns, ras, n);

  uint8_t order = 0;
  for (i = 0; i < n; ++i)
    if (ras[i].dep && ras[i].host_idx == REG_NUM)
      {
	ir_assign_dep_try_reuse (assigns, ras + i);
	if (ras[i].host_idx == REG_NUM)
	  ir_assign_dep_try_current (assigns, ras + i, ++order);
      }

  for (i = 0; i < n; ++i)
    if (ras[i].dep && ras[i].host_idx == REG_NUM)
      {
	ir_assign_dep_try_reuse (assigns, ras + i);
	if (ras[i].host_idx == REG_NUM)
	  ir_assign_dep_pick (flat, assigns, ras + i, ++order);
      }

  for (i = 0; i < n; ++i)
    if (ras[i].host_idx == REG_NUM)
      ir_assign_def_pick (flat, assigns, ras + i, ++order);

  ir_assign_assign (flat, blk, assigns, REG_IDX_RFLAGS);

  for (i = 0; i <= order; ++i)
    for (j = 0; j < GPREG_NUM; ++j)
      if (assigns[j].order == i && (assigns[j].dep || assigns[j].def))
	ir_assign_assign (flat, blk, assigns, j);

  ir_assign_emit (flat, blk, node, ras, n);
  eri_assert_buf_fini (&ras_buf);

  ir_assign_update_free_deps (flat, blk, node);

  for (i = 0; i < REG_NUM; ++i)
    if (assigns[i].check_guest)
      ir_try_update_guest_loc (flat, blk, assigns[i].check_guest);
}

static void
ir_gen_init (struct ir_flattened *flat, struct ir_node *node)
{
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    {
      if (i != REG_IDX_RIP)
	node->next_guests[i]->locs.local = ir_get_local (flat);
      flat->guest_locs[i].def = node->next_guests[i];
      ir_init_guest_loc (flat->guest_locs + i);
    }
}

static uint64_t
ir_accesses_static_num (struct ir_accesses *acc, uint64_t *n, uint64_t *cn)
{
  uint64_t ln = acc->sizes.off / sizeof (uint32_t);
  uint64_t lcn = eri_div_ceil (acc->cond_count, 8);
  if (n) *n = ln;
  if (cn) *cn = lcn;
  return ln + lcn;
}

static struct block *
ir_output (struct ir_dag *dag, struct ir_block *blk, uint8_t new_tf)
{
  uint64_t ilen = eri_round_up (blk->insts.off, 16);
  uint64_t tlen = eri_round_up (blk->traces.off, 16);

  uint64_t size = sizeof (struct block) + ilen + tlen;
  struct ir_accesses *r = &dag->reads;
  struct ir_accesses *w = &dag->writes;
  size += r->sizes.off + r->conds.off + w->sizes.off + w->conds.off;

  struct block *res = eri_assert_mtmalloc (dag->pool, size);

  // eri_debug ("res->buf: %lx\n", res->buf);
  res->insts = res->buf;
  eri_memcpy (res->insts, blk->insts.buf, blk->insts.off);
  res->insts_len = blk->insts.off;

  res->traces = (void *) (res->buf + ilen);
  eri_memcpy (res->traces, blk->traces.buf, blk->traces.off);
  res->ntraces = blk->traces.off / sizeof (struct trace_guest);

  eri_memcpy (res->final_locs, blk->final_locs, sizeof res->final_locs);

  res->sig_info = blk->sig_info;
  res->new_tf = new_tf;

  res->static_local_num = LOCAL_PREDEFINED_NUM
		+ ir_accesses_static_num (r, &res->reads.num, 0)
		+ ir_accesses_static_num (w, &res->writes.num, 0);

  uint8_t *acc = res->buf + ilen + tlen;

  res->reads.sizes = (void *) acc;
  eri_memcpy (res->reads.sizes, r->sizes.buf, r->sizes.off);

  res->writes.sizes = (void *) (acc += r->sizes.off);
  eri_memcpy (res->writes.sizes, w->sizes.buf, w->sizes.off);

  res->reads.conds = acc += w->sizes.off;
  eri_memcpy (res->reads.conds, r->conds.buf, r->conds.off);

  res->writes.conds = acc + r->conds.off;
  eri_memcpy (res->writes.conds, w->conds.buf, w->conds.off);

  res->reads.cond_count = r->cond_count;
  res->writes.cond_count = w->cond_count;

  res->reads.traces = blk->trace_reads.traces;
  res->writes.traces = blk->trace_writes.traces;

  res->local_num = blk->local_num;
  return res;
}

static void
ir_init_trace_accesses (struct ir_trace_accesses *traces,
			struct eri_mtpool *pool, uint64_t num)
{
  traces->traces = eri_assert_mtmalloc (pool,
					sizeof traces->traces[0] * num);
  traces->i = 0;
}

static struct block *
ir_generate (struct ir_dag *dag, uint8_t new_tf)
{
  // eri_debug ("\n");

  struct ir_flattened flat = { dag, { 0, 0, { -1, -1 } } };
  ERI_LST_INIT_LIST (ir_flat, &flat);

  uint64_t static_num = LOCAL_PREDEFINED_NUM;
  static_num += ir_accesses_static_num (&dag->reads, &flat.read_num,
					&flat.cond_read_num);
  static_num += ir_accesses_static_num (&dag->writes, &flat.write_num,
					&flat.cond_write_num);
  flat.local_num = static_num;

  struct ir_node *last = dag->last->node;
  ir_mark_ref (dag, last);
  ir_flatten (&flat, last);

  uint8_t local = REG_IDX_RBP;
  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    ir_init_host (&flat, i, i == local ? &flat.local : &flat.dummy);

  struct ir_block blk;
  eri_assert_buf_mtpool_init (&blk.insts, dag->pool, 512);
  eri_assert_buf_mtpool_init (&blk.traces, dag->pool, 512);
  blk.sig_info.sig = 0;
  ir_init_trace_accesses (&blk.trace_reads, dag->pool, flat.read_num);
  ir_init_trace_accesses (&blk.trace_writes, dag->pool, flat.write_num);

  if (local != REG_IDX_RDI)
    ir_emit (mov, &blk, local, REG_IDX_RDI);

  struct ir_node *node;
  ERI_LST_FOREACH (ir_flat, &flat, node)
    if (node->tag == IR_INIT)
      ir_gen_init (&flat, node);
    else if (node->tag == IR_ERR_END && ! node->end.sig_info.sig)
      ir_emit_raw (&blk, node->end.bytes, node->end.len);
    else
      ir_assign_hosts (&flat, &blk, node);

  eri_lassert (blk.trace_reads.i == flat.read_num);
  eri_lassert (blk.trace_writes.i == flat.write_num);

  blk.local_num = flat.local_num;
  struct block *res = ir_output (dag, &blk, new_tf);

  eri_assert_buf_fini (&blk.insts);
  eri_assert_buf_fini (&blk.traces);
  return res;
}

static void
ir_init_accesses (struct ir_accesses *acc,
		  struct eri_mtpool *pool, uint32_t n)
{
  eri_assert_buf_mtpool_init (&acc->sizes, pool, sizeof (uint32_t) * n);
  eri_assert_buf_mtpool_init (&acc->conds, pool, n);
}

static void
ir_fini_accesses (struct ir_accesses *acc)
{
  eri_assert_buf_fini (&acc->sizes);
  eri_assert_buf_fini (&acc->conds);
}

static struct block *
translate (struct eri_analyzer *al, uint64_t rip, uint8_t tf)
{
#ifdef DUMP_DIS
  if (eri_assert_syscall (gettid) == eri_assert_syscall (getpid))
    eri_debug ("rip = %lx\n", rip);
#endif

  struct ir_dag dag = { al->group->pool };
  ERI_LST_INIT_LIST (ir_alloc, &dag);

  dag.map_start = ir_get_load_imm (&dag, al->group->map_range->start);
  dag.map_end = ir_get_load_imm (&dag, al->group->map_range->end);

  uint32_t max_inst_count = tf ? 1 : al->group->max_inst_count;
  ir_init_accesses (&dag.reads, dag.pool, max_inst_count);
  ir_init_accesses (&dag.writes, dag.pool, max_inst_count);

  struct ir_node *init = ir_alloc_node (&dag, IR_INIT, 0);
  dag.init = &init->seq;

  uint8_t i;
  for (i = 0; i < REG_NUM; ++i)
    {
      struct ir_def *def = i != REG_IDX_RIP
	? ir_define (init, init->init.regs + i) : ir_get_load_imm (&dag, rip);
      init->next_guests[i] = def;
      ir_set_sym (&dag, i, def);
    }

  uint8_t new_tf = 0;

  i = 0;
  while (1)
    {
      struct ir_node *node = ir_create_inst (al, &dag);
      if (! node) break;

      // eri_debug ("\n");
      ir_build_inst_operands (&dag, node);

      // if (eri_enabled_debug ()) ir_dump_inst (ERI_STDOUT, node);

      xed_decoded_inst_t *dec = &node->inst.dec;
      xed_category_enum_t cate = xed_decoded_inst_get_category (dec);
      xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (dec);

#if 0
      eri_lassert (iclass != XED_ICLASS_BOUND);
      eri_lassert (iclass != XED_ICLASS_INT);
      eri_lassert (iclass != XED_ICLASS_INT1);
      eri_lassert (iclass != XED_ICLASS_JMP_FAR);
      eri_lassert (iclass != XED_ICLASS_CALL_FAR);
      eri_lassert (iclass != XED_ICLASS_RET_FAR);
#endif
      eri_lassert (iclass != XED_ICLASS_IRET); /* XXX: ??? */
      eri_lassert (iclass != XED_ICLASS_IRETD);
      eri_lassert (iclass != XED_ICLASS_IRETQ);

      /* TODO: warn lock */

      if (cate == XED_CATEGORY_SYSCALL)
	{
	  /* TODO: error out */
	  eri_lassert (0);
	}

      if (iclass == XED_ICLASS_POPF || iclass == XED_ICLASS_POPFQ)
	{
	  ir_build_popf (&dag, node);
	  new_tf = 1;
	}
      else if (xed_norep_map (iclass) != XED_ICLASS_INVALID)
	ir_build_cond_str_op (&dag, node);
      else if (cate == XED_CATEGORY_UNCOND_BR)
	ir_build_uncond_branch (&dag, node);
      else if (cate == XED_CATEGORY_COND_BR)
	ir_build_cond_branch (&dag, node);
      else if (cate == XED_CATEGORY_CALL)
	ir_build_call (&dag, node);
      else if (cate == XED_CATEGORY_RET)
	ir_build_ret (&dag, node);

      if (node->tag == IR_END) break;

      eri_assert (node->tag == IR_INST);
      ir_finish_inst (&dag, node);
      if (++i == max_inst_count)
	{
	  ir_end (&dag, 0);
	  break;
	}
    }
#ifdef DUMP_DIS
  if (eri_assert_syscall (gettid) == eri_assert_syscall (getpid))
    eri_debug ("\n");
#endif

  struct block *res = ir_generate (&dag, new_tf);

  struct ir_alloc *a, *na;
  ERI_LST_FOREACH_SAFE (ir_alloc, &dag, a, na)
    {
      ir_alloc_lst_remove (&dag, a);
      eri_assert_mtfree (dag.pool, a);
    }

  ir_fini_accesses (&dag.reads);
  ir_fini_accesses (&dag.writes);
  return res;
}

static void
init_act_local (struct active *act,
		struct block *blk, struct eri_registers *regs)
{
  act->local[LOCAL_INVALID_WRITE] = 0; // TODO detailed check

  uint64_t *cond_reads = act->local + LOCAL_PREDEFINED_NUM + blk->reads.num;
  eri_memset (cond_reads, 0, blk->reads.cond_count);
  uint64_t *cond_writes = cond_reads
		+ eri_div_ceil (blk->reads.cond_count, 8) + blk->writes.num;
  eri_memset (cond_writes, 0, blk->writes.cond_count);

  uint64_t *l = act->local + blk->static_local_num;

#define SAVE_LOCAL_REG(creg, reg) \
  if (ERI_PASTE (REG_IDX_, creg) != REG_IDX_RIP)			\
    *l++ = ERI_PASTE (REG_IDX_, creg) == REG_IDX_RFLAGS			\
		? regs->reg & ~ERI_RFLAGS_TF : regs->reg;
  ERI_FOREACH_REG (SAVE_LOCAL_REG)
}

static eri_noreturn void
analysis_enter (struct eri_analyzer *al,
	        struct eri_registers *regs)
{
  // eri_debug ("rip = %lx rcx = %lx\n", regs->rip, regs->rcx);
  eri_assert (! eri_within (al->group->map_range, regs->rip));

  struct eri_analyzer_group *group = al->group;
  eri_assert_lock (&group->trans_lock);
  struct trans_key key = { regs->rip, !! (regs->rflags & ERI_RFLAGS_TF) };
  struct trans *trans = trans_rbt_get (group, &key, ERI_RBT_EQ);
  if (! trans)
    {
      trans = eri_assert_mtmalloc (group->pool, sizeof *trans);
      trans->key = key;
      trans->ref_count = 1;
      trans->wait = 0;
      trans->done = 0;
      trans_rbt_insert (group, trans);
      eri_assert_unlock (&group->trans_lock);

      trans->block = translate (al, key.rip, key.tf);
      eri_atomic_store (&trans->done, 1, 0);

      if (eri_atomic_load (&trans->wait, 1))
        eri_assert_syscall (futex, &trans->done,
			    ERI_FUTEX_WAKE, ERI_INT_MAX);
    }
  else
    {
      ++trans->ref_count;
      eri_assert_unlock (&group->trans_lock);
      if (! eri_atomic_load (&trans->done, 0))
	{
	  eri_atomic_inc (&trans->wait, 1);
	  eri_assert_sys_futex_wait (&trans->done, 0, 0);
	  eri_atomic_dec (&trans->wait, 1);
	}
    }

  struct block *blk = trans->block;
  struct active *act = eri_assert_mtmalloc (group->pool,
				sizeof *act + blk->local_num * 8);
  act->al = al;
  act->trans = trans;
  act->stack = eri_entry__get_stack (al->entry) - 8;
  // eri_debug ("%lx\n", act->stack);
  init_act_local (act, blk, regs);

  eri_atomic_store (&al->act, act, 0);

  // eri_debug ("leave\n");
  eri_jump (0, blk->insts, act->local, 0, 0);
}

static void
raise (struct eri_analyzer *al,
       struct eri_siginfo *info, struct eri_registers *regs)
{
  al->act_sig_info = *info;
  eri_mcontext_from_registers (&al->act_sig_mctx, regs);
  eri_assert_syscall (tgkill, *al->group->pid, *al->tid, ERI_SIGRTMIN + 1);
}

static void
raise_single_step (struct eri_analyzer *al, struct eri_registers *regs)
{
  struct eri_siginfo info = { .sig = ERI_SIGTRAP, .code = ERI_TRAP_TRACE };
  raise (al, &info, regs);
}

eri_noreturn void
eri_analyzer__enter (struct eri_analyzer *al, struct eri_registers *regs)
{
  if (regs->rflags & ERI_RFLAGS_TF) raise_single_step (al, regs);
  analysis_enter (al, regs);
}

static void
get_regs_from_final_locs (struct eri_registers *regs,
			  struct reg_loc *final_locs, uint64_t *local)
{
#define GET_FINAL_REG(creg, reg) \
  do {									\
    struct reg_loc *_l = final_locs + ERI_PASTE (REG_IDX_, creg);	\
    regs->reg = _l->tag == REG_LOC_IMM ? _l->val : local[_l->val];	\
  } while (0);

  ERI_FOREACH_REG (GET_FINAL_REG)
}

static void
release_active (struct eri_analyzer *al)
{
  struct active *act = al->act;
  eri_atomic_store (&al->act, 0, 0);
  eri_atomic_dec (&act->trans->ref_count, 1);

  eri_assert_mtfree (al->group->pool, act);
}

eri_noreturn static void
analysis (uint64_t *local)
{
  struct active *act = eri_struct_of (local, typeof (*act), local);

  struct eri_analyzer *al = act->al;
  struct block *blk = act->trans->block;
  // TODO check e.g. memory

  struct eri_registers regs;
  get_regs_from_final_locs (&regs, blk->final_locs, local);

  uint8_t tf = act->trans->key.tf;
  if (! blk->new_tf && tf) regs.rflags |= ERI_RFLAGS_TF;

  // eri_barrier ();

  struct eri_siginfo info = blk->sig_info;
  release_active (al);

  if (info.sig) raise (al, &info, &regs);
  else if (tf) raise_single_step (al, &regs);

  struct eri_entry *en = al->entry;
  if (eri_within (al->group->map_range, regs.rip))
    {
      struct eri_registers *en_regs = eri_entry__get_regs (en);
      regs.rbx = en_regs->rbx;
      regs.rip = en_regs->rip;
      *en_regs = regs;
      eri_noreturn void (*entry) (void *) = eri_entry__get_entry (en);
      entry (en);
    }
  else analysis_enter (al, &regs);
}

static uint64_t
get_reg_from_mctx_by_idx (struct eri_mcontext *mctx, uint8_t idx)
{
  switch (idx)
   {
#define GET_REG_FROM_CTX(creg, reg) \
   case (ERI_PASTE (REG_IDX_, creg)): return mctx->reg;
   ERI_FOREACH_REG (GET_REG_FROM_CTX)
   default: eri_assert_unreachable ();
   }
}

void
eri_analyzer__sig_handler (struct eri_analyzer__sig_handler_args *args)
{
  struct eri_analyzer *al = args->analyzer;
  struct eri_siginfo *info = args->info;
  struct eri_mcontext *mctx = &args->ctx->mctx;

  if (eri_entry__sig_is_access_fault (al->entry, info))
    {
      if (al->sig_info)
	{
	  *al->sig_info = *info;
	  al->sig_info = 0;

	  eri_entry__sig_access_fault (al->entry, mctx);
	  return;
	}

      eri_lassert (! al->act && ! al->act_sig_info.sig);
    }

  if (info->code == ERI_SI_TKILL && info->kill.pid == *al->group->pid
      && al->act_sig_info.sig)
    {
      struct eri_mcontext saved = *mctx;
      *info = al->act_sig_info;
#define GET_MCTX(creg, reg) mctx->reg = al->act_sig_mctx.reg;
      ERI_FOREACH_REG (GET_MCTX)
      al->act_sig_info.sig = 0;

      if (args->handler (info, args->ctx, args->args)) return;

      *mctx = saved;
      return;
    }

  if (! al->act)
    {
      args->handler (info, args->ctx, args->args);
      return;
    }

  struct trans *trans = al->act->trans;
  struct block *blk = trans->block;

  uint64_t rip = mctx->rip;
  struct eri_range range = {
    (uint64_t) blk->insts, (uint64_t) blk->insts + blk->insts_len
  };
  if (! eri_within (&range, rip))
    {
      args->handler (info, args->ctx, args->args);
      return;
    }
  eri_debug ("%lx\n", rip - (uint64_t) blk->insts);

  struct reg_loc locs[REG_NUM];

  uint64_t i;
  for (i = 0; i < REG_NUM; ++i)
    if (i != REG_IDX_RIP)
      set_reg_loc (locs + i, REG_LOC_LOCAL, blk->static_local_num + i);
    else set_reg_loc (locs + i, REG_LOC_IMM, trans->key.rip);

  uint64_t rip_off = rip - range.start;
  struct trace_guest *traces = blk->traces;

  for (i = 0; i < blk->ntraces && traces[i].rip_off <= rip_off; ++i)
    locs[traces[i].reg_idx] = traces[i].loc;

  struct eri_registers regs;
#define GET_REG(creg, reg) \
  do {									\
    struct reg_loc *_loc = locs + ERI_PASTE (REG_IDX_, creg);		\
    if (_loc->tag == REG_LOC_REG)					\
      regs.reg = get_reg_from_mctx_by_idx (mctx, _loc->val);		\
    else if (_loc->tag == REG_LOC_LOCAL)				\
      regs.reg = al->act->local[_loc->val];				\
    else								\
      regs.reg = _loc->val;						\
  } while (0);
  ERI_FOREACH_REG (GET_REG)

  struct eri_mcontext saved = *mctx;
  eri_mcontext_from_registers (mctx, &regs);

  if (args->handler (info, args->ctx, args->args)) release_active (al);
  else *mctx = saved;
}

/* For xed.  */

void *
memset (void *s, int32_t c, uint64_t n)
{
  eri_memset (s, (char) c, n);
  return s;
}

void *
memcpy (void *d, const void *s, uint64_t n)
{
  eri_memcpy (d, s, n);
  return d;
}

int32_t
memcmp (const void *s1, const void *s2, uint64_t n)
{
  return eri_memcmp (s1, s2, n);
}

uint64_t
strlen (const char *s)
{
  return eri_strlen (s);
}

char *
strncat (char *d, const char *s, uint64_t n)
{
  eri_strncat (d, s, n);
  return d;
}

int32_t
strcmp (const char *s1, const char *s2)
{
  return eri_strcmp (s1, s2);
}

void abort (void) { eri_lassert (0); }
int32_t fprintf (void *a1, void *a2, ...) { return 0; }
void *stderr;
