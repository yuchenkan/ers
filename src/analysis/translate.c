/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/cpu.h>
#include <lib/util.h>
#include <lib/syscall-common.h>
#include <lib/atomic.h>
#include <lib/buf.h>
#include <lib/list.h>
#include <lib/rbtree.h>
#include <lib/malloc.h>

#include <common/debug.h>
#include <common/common.h>

#include <analysis/translate.h>

#include <xed-util.h>
#include <xed-interface.h>

void eri_trans_init_translate (void) { xed_tables_init (); }

enum
{
  TRANS_LOC_REG,
  TRANS_LOC_LOCAL,
  TRANS_LOC_IMM
};

enum
{
  /* XXX: depands on the order of ERI_FOREACH_REG */
#define TRANS_REG(creg, reg)	ERI_PASTE (TRANS_, creg),
  ERI_FOREACH_REG (TRANS_REG)
  TRANS_REG_NUM,
  TRANS_GPREG_NUM = TRANS_RFLAGS
};

static const char *
trans_reg_str (uint8_t idx)
{
  switch (idx)
    {
#define CASE_TRANS_REG(creg, reg) \
  case ERI_PASTE (TRANS_, creg):					\
    return ERI_STR (ERI_PASTE (TRANS_, creg));
    ERI_FOREACH_REG (CASE_TRANS_REG)
    default: eri_assert_unreachable ();
    }
}

struct trans_loc
{
  uint8_t tag;
  uint64_t val;
};

static void
trans_set_loc (struct trans_loc *loc, uint8_t tag, uint64_t val)
{
  loc->tag = tag;
  loc->val = val;
}

struct trace_guest
{
  uint64_t rip_off;
  uint8_t reg_idx;
  struct trans_loc loc;
};

struct access
{
  uint8_t type;
  uint32_t size;
  uint8_t cond;
  uint8_t var;
  uint64_t addr;

  uint64_t rip_off;
  uint8_t inst_len;
};

struct accesses
{
  uint64_t num;

  struct access *accesses;
  uint64_t vars_count;
  uint64_t conds_count;
};

struct eri_trans
{
  void *data;

  uint64_t rip;
  uint8_t tf;

  uint8_t *insts;
  uint64_t insts_len;

  struct trace_guest *traces;
  uint64_t traces_num;

  struct trans_loc final_locs[TRANS_REG_NUM];

  struct eri_siginfo sig_info;
  uint8_t new_tf;

  struct accesses accesses;

  uint64_t local_num;

  eri_aligned16 uint8_t buf[0];
};

struct eri_trans_active
{
  void *data;

  struct eri_trans *trans;
  uint8_t *stack;
  uint64_t local[0];
};

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

static const char *
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

  struct ir_def *next_guests[TRANS_REG_NUM];

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
	  struct ir_def regs[TRANS_REG_NUM];
	} init;
      struct
	{
	  struct ir_dep regs[TRANS_REG_NUM];
	  struct ir_dep memory;
	  struct ir_dep prev;

	  struct eri_siginfo sig_info;
	  uint8_t len;
	  uint8_t bytes[INST_BYTES];
	} end;
      struct
	{
	  uint64_t idx;
	  struct ir_mem mem;
	  struct ir_dep memory;
	  struct ir_dep prev;
	  struct ir_dep map_start, map_end;
	  struct ir_dep rec_mem;
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

	  uint64_t read_idx;
	  uint64_t read_cond_idx;
	  uint64_t write_idx;
	  uint64_t write_cond_idx;

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
  struct eri_buf accesses;
  uint64_t vars_count;
  uint64_t conds_count;
};

struct ir_dag
{
  struct eri_mtpool *pool;
  eri_file_t log;

  ERI_LST_LIST_FIELDS (ir_alloc)
  ERI_RBT_TREE_FIELDS (ir_redun, struct ir_redun)

  uint64_t len;

  struct ir_def *map_start;
  struct ir_def *map_end;

  struct ir_def *syms[TRANS_REG_NUM];

  struct ir_def *init;
  struct ir_def *memory;
  struct ir_def *prev;
  struct ir_def *last;
  struct ir_def *rec_mem;

  struct ir_accesses accesses;
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
  struct trans_loc loc;
};

struct ir_flat
{
  struct ir_dag *dag;
  struct ir_def local;
  struct ir_def dummy;

  uint64_t ridx;
  ERI_LST_LIST_FIELDS (ir_flat)

  struct ir_def *hosts[TRANS_REG_NUM];

  struct ir_guest_loc guest_locs[TRANS_REG_NUM];

  void *analysis;

  struct eri_buf insts;
  struct eri_buf traces;

  struct trans_loc final_locs[TRANS_REG_NUM];
  struct eri_siginfo sig_info;

  uint64_t access_idx;
  uint64_t access_cond_idx;
  struct access *access;

  uint64_t local_num;
  ERI_RBT_TREE_FIELDS (ir_local, struct ir_local)
};

ERI_DEFINE_LIST (static, ir_flat, struct ir_flat, struct ir_node)
ERI_DEFINE_RBTREE (static, ir_local, struct ir_flat,
		   struct ir_local, uint64_t, eri_less_than)

static uint8_t
ir_reg_idx_from_xed_opt (xed_reg_enum_t reg)
{
  switch (xed_get_largest_enclosing_register (reg))
    {
#define CONV_XED_REG(creg, reg) \
  case ERI_PASTE (XED_REG_, creg): return ERI_PASTE (TRANS_, creg);
    ERI_FOREACH_REG (CONV_XED_REG)
    default: return TRANS_REG_NUM;
    }
}

static uint8_t
ir_reg_idx_from_xed (eri_file_t log, xed_reg_enum_t reg)
{
  uint8_t reg_idx = ir_reg_idx_from_xed_opt (reg);
  eri_lassert (log, reg_idx != TRANS_REG_NUM);
  return reg_idx;
}

static xed_reg_enum_t
ir_xed_reg_from_idx_opt (uint8_t reg_idx, uint8_t size, uint8_t high)
{
  if (high)
    {
      eri_assert (size == 1);
      if (reg_idx >= TRANS_REG_NUM) return XED_REG_INVALID;
      else if (reg_idx == TRANS_RAX) return XED_REG_AH;
      else if (reg_idx == TRANS_RCX) return XED_REG_CH;
      else if (reg_idx == TRANS_RDX) return XED_REG_DH;
      else if (reg_idx == TRANS_RBX) return XED_REG_BH;
      else eri_xassert (0, eri_info);
    }

  switch (reg_idx)
    {
#define CONV_REG_IDX(creg, reg) \
  case ERI_PASTE (TRANS_, creg):					\
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
    case TRANS_RFLAGS:
      if (size == 2) return XED_REG_FLAGS;
      else if (size == 4) return XED_REG_EFLAGS;
      else if (size == 8) return XED_REG_RFLAGS;
      else return XED_REG_INVALID;
    case TRANS_RIP:
      if (size == 2) return XED_REG_IP;
      else if (size == 4) return XED_REG_EIP;
      else if (size == 8) return XED_REG_RIP;
      else return XED_REG_INVALID;
    default: return XED_REG_INVALID;
    }
}

static xed_reg_enum_t
ir_xed_reg_from_idx (eri_file_t log, uint8_t reg_idx,
		     uint8_t size, uint8_t high)
{
  xed_reg_enum_t reg = ir_xed_reg_from_idx_opt (reg_idx, size, high);
  eri_lassert (log, reg != XED_REG_INVALID);
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
  return ir_get_sym (dag, ir_reg_idx_from_xed (dag->log, reg));
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
  ir_set_sym (dag, ir_reg_idx_from_xed (dag->log, reg), def);
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
  for (i = 0; i < TRANS_REG_NUM; ++i)
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
  eri_log8 (dag->log, "%lx\n", info);

  ir_do_end (dag, node, IR_ERR_END);

  if (info) node->end.sig_info = *info;
  else node->end.sig_info.sig = 0;
  if (bytes)
    {
      node->end.len = len;
      eri_memcpy (node->end.bytes, bytes, len);
    }
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

static void
ir_add_const_access (struct ir_accesses *acc,
		     uint8_t read, uint64_t addr, uint32_t size)
{
  struct access a = {
    read ? ERI_ACCESS_READ : ERI_ACCESS_WRITE, size, 0, 0, addr
  };
  eri_assert_buf_append (&acc->accesses, &a, 1);
}

static void
ir_add_access (struct ir_accesses *acc,
	       uint8_t read, uint32_t size, uint8_t cond)
{
  struct access a = {
    read ? ERI_ACCESS_READ : ERI_ACCESS_WRITE, size, cond, 1
  };
  eri_assert_buf_append (&acc->accesses, &a, 1);
  if (cond) ++acc->conds_count;
  ++acc->vars_count;
}

static struct ir_def *
ir_eval_rec_mem (struct ir_dag *dag, struct ir_rec_mem_args *args)
{
  struct ir_mem_args *mem = &args->mem;

  struct ir_node *node = ir_alloc_node (dag, IR_REC_MEM,
		args->read ? ir_deps (1, 0) : ir_deps (3, 1));
  node->deps += ir_init_mem (node, &node->rec_mem.mem, mem);
  node->rec_mem.idx = dag->accesses.vars_count;
  ir_add_access (&dag->accesses, args->read, mem->size, 0);
  ir_depand (node, &node->rec_mem.memory, dag->memory, 0);
  ir_depand (node, &node->rec_mem.prev, dag->prev, 0);
  ir_depand (node, &node->rec_mem.rec_mem, dag->rec_mem, 0);
   dag->rec_mem = &node->seq;
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
  if (mem->seg != XED_REG_INVALID) return 0; // TODO fs gs

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
    {
      node->cond_str_op.read_idx = dag->accesses.vars_count;
      node->cond_str_op.read_cond_idx = dag->accesses.conds_count;
      ir_add_access (&dag->accesses, 1, size, 1);
    }
  if (ir_cond_str_op_rdi (iclass))
    {
      node->cond_str_op.write_idx = dag->accesses.vars_count;
      node->cond_str_op.write_cond_idx = dag->accesses.conds_count;
      ir_add_access (&dag->accesses, 0, size, 1);
      ir_depand (node, &node->cond_str_op.map_start, dag->map_start, 1);
      ir_depand (node, &node->cond_str_op.map_end, dag->map_end, 1);
    }

  dag->memory = &node->seq;

  defs[0] = ir_define (node, &node->cond_str_op.dst);
  if (ir_cond_str_op_rdi (iclass))
    defs[1] = ir_define (node, &node->cond_str_op.def_rdi);
  if (ir_cond_str_op_rsi (iclass))
    defs[2] = ir_define (node, &node->cond_str_op.def_rsi);
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
  eri_assert (! ir_get_sym (dag, TRANS_RIP)->node);
  return ir_get_sym (dag, TRANS_RIP)->imm;
}

static void
ir_dump_dis_dec (eri_file_t log, uint64_t rip, xed_decoded_inst_t *dec)
{
  eri_rlog (log, "%lx:", rip);

  char dis[64];
  eri_assert (xed_format_context (XED_SYNTAX_ATT, dec,
				  dis, sizeof dis, rip, 0, 0));
  eri_rlog (log, " %s\n", dis);
}

static xed_error_enum_t
ir_do_decode (xed_decoded_inst_t *dec, uint8_t *bytes, uint8_t len)
{
  xed_decoded_inst_zero (dec);
  xed_decoded_inst_set_mode (dec, XED_MACHINE_MODE_LONG_64,
			     XED_ADDRESS_WIDTH_64b);
  return xed_decode (dec, bytes, len);
}

static uint8_t
si_map_err (const struct eri_siginfo *info)
{
  return info->sig == ERI_SIGSEGV
	  && (info->code == ERI_SEGV_MAPERR || info->code == ERI_SEGV_ACCERR);
}

static uint8_t
ir_decode (struct eri_translate_args *args, struct ir_dag *dag,
	   struct ir_node *node, uint8_t len)
{
  uint64_t rip = ir_get_rip (dag);

  uint8_t inst_len;

  uint8_t bytes[INST_BYTES];
  struct eri_siginfo info;
  if (! args->copy (bytes, (void *) rip, len, &info, args->copy_args))
    {
      if (! si_map_err (&info)) eri_assert_unreachable ();
      inst_len = info.fault.addr + 1 - rip;
      ir_err_end (dag, node, &info, 0, 0);
      goto done;
    }

  xed_decoded_inst_t *dec = &node->inst.dec;
  xed_error_enum_t err = ir_do_decode (dec, bytes, len);
  if (err == XED_ERROR_BUFFER_TOO_SHORT) return 0;

  if (err == XED_ERROR_NONE && eri_global_enable_debug >= 2)
    ir_dump_dis_dec (dag->log, rip, dec);

  if (err != XED_ERROR_NONE)
    {
      for (inst_len = 1; inst_len < len; ++inst_len)
	if (ir_do_decode (dec, bytes, inst_len) != XED_ERROR_BUFFER_TOO_SHORT)
	  break;

      eri_lassert (dag->log, inst_len != len);
      ir_err_end (dag, node, 0, len, bytes);
    }
  else inst_len = xed_decoded_inst_get_length (dec);

done:
  dag->len += inst_len;
  ir_add_const_access (&dag->accesses, 1, rip, inst_len);
  return 1;
}

static struct ir_node *
ir_create_inst (struct eri_translate_args *args, struct ir_dag *dag)
{
  struct ir_node *node = ir_alloc_node (dag, IR_INST, 0);

  uint64_t rip = ir_get_rip (dag);
  uint64_t page = args->page_size;
  uint8_t len = eri_min (eri_round_up (rip + 1, page) - rip, INST_BYTES);
  if (! ir_decode (args, dag, node, len))
    ir_decode (args, dag, node, INST_BYTES);

  if (node->tag == IR_ERR_END)
    {
      dag->last = &node->seq;
      return 0;
    }

  return node;
}

static void
ir_dump_inst (eri_file_t log, struct ir_node *node)
{
  uint64_t rip = node->next_guests[TRANS_RIP]->imm;
  xed_decoded_inst_t *dec = &node->inst.dec;

  xed_category_enum_t cate = xed_decoded_inst_get_category (dec);
  eri_rlog4 (log, "cate: %s, ", xed_category_enum_t2str (cate));
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (dec);
  eri_rlog4 (log, "iclass: %s, ", xed_iclass_enum_t2str (iclass));
  xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum (dec);
  eri_rlog4 (log, "%s, ", xed_iform_to_iclass_string_att (iform));

  xed_uint_t length = xed_decoded_inst_get_length (dec);
  xed_operand_values_t *ops = xed_decoded_inst_operands (dec);

  const xed_inst_t *inst = xed_decoded_inst_inst (dec);
  int noperands = xed_inst_noperands (inst);
  eri_rlog4 (log, "length: %u, size: %u, addr_size: %u, noperands: %u\n",
	length, xed_operand_values_get_effective_operand_width (ops) >> 3,
	xed_operand_values_get_effective_address_width (ops) >> 3, noperands);

  uint8_t i;
  for (i = 0; i < noperands; ++i)
    {
      const xed_operand_t *op = xed_inst_operand (inst, i);
      xed_operand_enum_t op_name = xed_operand_name (op);
      eri_rlog4 (log, "  opname: %s, ", xed_operand_enum_t2str (op_name));

      if (op_name == XED_OPERAND_SEG0
	  || op_name == XED_OPERAND_SEG1
	  || op_name == XED_OPERAND_INDEX
	  || op_name == XED_OPERAND_BASE0
	  || op_name == XED_OPERAND_BASE1
	  || (op_name >= XED_OPERAND_REG0 && op_name <= XED_OPERAND_REG8))
	{
	  xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
	  eri_rlog4 (log, "operand: %s, ", xed_reg_enum_t2str (reg));
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

	  eri_rlog4 (log, "base: %s, ", xed_reg_enum_t2str (base));
	  eri_rlog4 (log, "seg: %s, ", xed_reg_enum_t2str (seg));
	  eri_rlog4 (log, "index: %s, ", xed_reg_enum_t2str (index));
	  eri_rlog4 (log, "disp: %lx, %lx, ", disp, ~disp + 1);
	  eri_rlog4 (log, "disp_width: %u, ", disp_width);
	  eri_rlog4 (log, "length: %u, ", length);
	}
      else if (op_name == XED_OPERAND_MEM1)
	{
	  xed_reg_enum_t base = xed_decoded_inst_get_base_reg (dec, 1);
	  xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg (dec, 1);
	  xed_uint_t length = xed_decoded_inst_operand_length (dec, i);

	  eri_assert (base != XED_REG_FSBASE && base != XED_REG_GSBASE);
	  eri_assert (seg != XED_REG_FSBASE && seg != XED_REG_GSBASE);

	  eri_rlog4 (log, "base: %s, ", xed_reg_enum_t2str (base));
	  eri_rlog4 (log, "seg: %s, ", xed_reg_enum_t2str (seg));
	  eri_rlog4 (log, "length: %u, ", length);
	}
      else if (op_name == XED_OPERAND_RELBR)
	{
	  xed_int32_t disp = xed_decoded_inst_get_branch_displacement (dec);

	  eri_rlog4 (log, "disp: %x, %x, ", disp, ~disp + 1);
	  eri_rlog4 (log, "addr: %lx, ", rip + length + disp);
	}
      else if (op_name == XED_OPERAND_IMM0)
	{
	  xed_uint64_t imm = xed_decoded_inst_get_unsigned_immediate (dec);
	  xed_uint_t is_signed = xed_decoded_inst_get_immediate_is_signed (dec);
	  xed_uint_t width = xed_decoded_inst_get_immediate_width (dec);

	  eri_rlog4 (log, "imm: %lx, %lu, %lx, %lu, ",
		     imm, imm, ~imm + 1, ~imm + 1);
	  eri_rlog4 (log, "is_signed: %u, ", is_signed);
	  eri_rlog4 (log, "width: %u, ", width);
	}

      xed_operand_action_enum_t rw = xed_decoded_inst_operand_action (dec, i);
      eri_rlog4 (log, "action: %s\n", xed_operand_action_enum_t2str (rw));
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
  return xed_operand_read (op) || xed_operand_conditional_write (op)
		|| xed_get_register_width_bits (reg) < 32;
}

static void
ir_build_inst_operands (struct ir_dag *dag, struct ir_node *node)
{
  xed_decoded_inst_t *dec = &node->inst.dec;
  const xed_inst_t *inst = xed_decoded_inst_inst (dec);

  ir_init_inst_operands (node);

  node->next_guests[TRANS_RIP] = ir_get_load_imm (dag,
			ir_get_rip (dag) + xed_decoded_inst_get_length (dec));
  ir_set_sym (dag, TRANS_RIP, node->next_guests[TRANS_RIP]);

  if (xed_decoded_inst_get_iclass (dec) == XED_ICLASS_NOP) return;

  uint64_t deps = 0;
  struct ir_inst_reg *inst_reg = node->inst.regs;
  uint8_t i;
  for (i = 0; i < xed_inst_noperands (inst); ++i)
    {
      const xed_operand_t *op = xed_inst_operand (inst, i);
      xed_operand_enum_t op_name = xed_operand_name (op);

      eri_lassert (dag->log, op_name != XED_OPERAND_SEG0);
      eri_lassert (dag->log, op_name != XED_OPERAND_SEG1);
      eri_lassert (dag->log, op_name != XED_OPERAND_INDEX);
      eri_lassert (dag->log, op_name != XED_OPERAND_OUTREG);

      eri_log8 (dag->log, "%s\n", xed_operand_enum_t2str (op_name));

      if (op_name == XED_OPERAND_BASE0 || op_name == XED_OPERAND_BASE1
	  || (op_name >= XED_OPERAND_REG0 && op_name <= XED_OPERAND_REG8))
	{
	  xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
	  uint8_t idx = ir_reg_idx_from_xed_opt (reg);
	  if (reg != XED_REG_RIP && idx != TRANS_REG_NUM)
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
	eri_lassert (dag->log, op_name == XED_OPERAND_IMM0
			       || op_name == XED_OPERAND_IMM1);
    }

  node->deps = eri_max (node->deps, deps);
}

static uint8_t
ir_reg_idx_from_dec_op (eri_file_t log,
			xed_decoded_inst_t *dec, const xed_operand_t *op)
{
  return ir_reg_idx_from_xed (log,
		xed_decoded_inst_get_reg (dec, xed_operand_name (op)));
}

static void
ir_init_mem_args_from_inst_mem (eri_file_t log, struct ir_mem_args *args,
				struct ir_node *inst, uint8_t i)
{
  xed_decoded_inst_t *dec = &inst->inst.dec;
  struct ir_mem_regs *mem = &inst->inst.mems[i].regs;
  args->base = mem->base.def;
  args->index = mem->index.def;
  args->seg = xed_decoded_inst_get_seg_reg (dec, i);
  eri_lassert (log, args->seg == XED_REG_INVALID || args->seg == XED_REG_FS
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
  ir_init_mem_args_from_inst_mem (dag->log, &args, node, i);

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

  eri_lassert (dag->log, ! op || xed_operand_name (op) != XED_OPERAND_AGEN);

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
  for (i = 0; i < TRANS_REG_NUM; ++i)
    if (node->next_guests[i] && i != TRANS_RIP)
      ir_set_sym (dag, i, node->next_guests[i]);
}

static struct ir_def *
ir_create_load_from_inst_mem (struct ir_dag *dag, struct ir_node *inst,
			      uint8_t i, struct ir_def *prim)
{
  struct ir_mem_args src;
  ir_init_mem_args_from_inst_mem (dag->log, &src, inst, i);
  return ir_create_load (dag, &src, prim);
}

static void
ir_set_rip (struct ir_dag *dag, uint64_t imm)
{
  ir_set_sym (dag, TRANS_RIP, ir_get_load_imm (dag, imm));
}

static void
ir_set_rip_from_reg (struct ir_dag *dag, xed_reg_enum_t src)
{
  ir_copy_xsym (dag, XED_REG_RIP, src);
}

static void
ir_set_rip_from_mem (struct ir_dag *dag, struct ir_node *inst, uint8_t i)
{
  ir_set_sym (dag, TRANS_RIP,
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
  ir_set_sym (dag, TRANS_RSP, ir_create_push (dag,
	  ir_get_sym (dag, TRANS_RSP), ir_get_xsym (dag, src),
	  xed_get_register_width_bits (src) >> 3));
}

static void
ir_build_pop (struct ir_dag *dag, xed_reg_enum_t dst)
{
  struct ir_def *prim = xed_get_register_width_bits (dst) != 64
					? ir_get_xsym (dag, dst) : 0;
  struct ir_def_pair pair = ir_create_pop (dag,
		ir_get_sym (dag, TRANS_RSP), prim);

  eri_log8 (dag->log, "%s %u %lx\n", xed_reg_enum_t2str (dst),
	    ir_reg_idx_from_xed (dag->log, dst), pair.first);

  ir_set_xsym (dag, dst, pair.first);
  ir_set_sym (dag, TRANS_RSP, pair.second);
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
      ir_err_end (dag, inst, &info, 0, 0);
      return;
    }

  xed_operand_values_t *ops = xed_decoded_inst_operands (dec);

  struct ir_cond_str_op_args args = {
    iclass, xed_operand_values_get_effective_address_width (ops) >> 3,
    ir_get_sym (dag, TRANS_RDI), ir_get_sym (dag, TRANS_RSI),
    ir_get_sym (dag, TRANS_RAX), ir_get_sym (dag, TRANS_RCX),
    ir_get_sym (dag, TRANS_RFLAGS),
    ir_get_load_imm (dag, ir_get_rip (dag) - length),
    ir_get_sym (dag, TRANS_RIP)
  };
  struct ir_def_sextet sextet = ir_create_cond_str_op (dag, &args);
  struct ir_def **defs = sextet.defs;
  ir_set_sym (dag, TRANS_RIP, defs[0]);
  ir_set_sym (dag, TRANS_RDI, defs[1]);
  ir_set_sym (dag, TRANS_RSI, defs[2]);
  ir_set_sym (dag, TRANS_RAX, defs[3]);
  ir_set_sym (dag, TRANS_RCX, defs[4]);
  ir_set_sym (dag, TRANS_RFLAGS, defs[5]);

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
    ir_get_sym (dag, TRANS_RFLAGS),
    ir_get_sym (dag, TRANS_RCX), taken, fall
  };
  struct ir_def_pair pair = ir_get_cond_branch (dag, &args);
  ir_set_sym (dag, TRANS_RIP, pair.first);
  if (pair.second)
    ir_set_sym (dag, TRANS_RCX, pair.second);

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
  ir_set_sym (dag, TRANS_RSP, ir_get_add (dag, ir_get_sym (dag, TRANS_RSP),
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
ir_flatten (struct ir_flat *flat, struct ir_node *node)
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
  for (i = 0; i < TRANS_REG_NUM; ++i)
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
  uint32_t g = host_idxs & ((1 << TRANS_REG_NUM) - 1);
  return (__builtin_ffs (g) ? : TRANS_REG_NUM + 1) - 1;
}

static uint8_t
ir_host_idxs_get_gpreg_idx (uint32_t host_idxs)
{
  uint32_t g = host_idxs & ((1 << TRANS_GPREG_NUM) - 1);
  return (__builtin_ffs (g) ? : TRANS_REG_NUM + 1) - 1;
}

static uint8_t
ir_host_idxs_has_gpreg (uint32_t host_idxs)
{
  return !! (host_idxs & ((1 << TRANS_GPREG_NUM) - 1));
}

static struct ir_local *
ir_alloc_local (struct ir_flat *flat)
{
  struct ir_local *local = ir_alloc (flat->dag, sizeof *local);
  local->idx = flat->local_num++;
  return local;
}

static struct ir_local *
ir_get_local (struct ir_flat *flat)
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
ir_put_local (struct ir_flat *flat, struct ir_local *local)
{
  ir_local_rbt_insert (flat, local);
}

static uint8_t
ir_local_host_idx (struct ir_flat *flat)
{
  return ir_host_idxs_get_gpreg_idx (flat->local.locs.host_idxs);
}

static uint8_t
ir_inst_designated_reg (xed_decoded_inst_t *dec, const xed_operand_t *op)
{
  xed_operand_enum_t op_name = xed_operand_name (op);
  xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
  if (reg >= XED_REG_GPR8h_FIRST && reg <= XED_REG_GPR8h_LAST) return 1;

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

#define ir_encode(log, bytes, enc) \
  ({ uint32_t _res;							\
     eri_lassert (log, xed_encode (enc, bytes,				\
				INST_BYTES, &_res) == XED_ERROR_NONE);	\
     _res; })

static xed_reg_enum_t
ir_xreg (eri_file_t log, uint8_t idx)
{
  return ir_xed_reg_from_idx (log, idx, 8, 0);
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
ir_encode_bin (eri_file_t log, uint8_t *bytes, xed_iclass_enum_t iclass,
	       uint8_t dst, uint8_t src)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (log, dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG1, ir_xreg (log, src));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_REG1);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_bin_imm (eri_file_t log, uint8_t *bytes, xed_iclass_enum_t iclass,
		   uint8_t dst, uint64_t src)
{
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (log, dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_uimm0 (&enc, src, 4);
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_IMM0);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_mov (eri_file_t log, uint8_t *bytes, uint8_t dst, uint8_t src)
{
  eri_log8 (log, "\n");
  return ir_encode_bin (log, bytes, XED_ICLASS_MOV, dst, src);
}

static eri_unused uint8_t
ir_min_width_unsigned (eri_file_t log, uint64_t x, uint8_t mask)
{
  uint8_t res = xed_shortest_width_unsigned (x, mask & 0x7);
  eri_lassert (log, res != 8 || mask & 0x8);
  return res;
}

static uint8_t
ir_min_width_signed (eri_file_t log, int64_t x, uint8_t mask)
{
  uint8_t res = xed_shortest_width_signed (x, mask & 0x7);
  eri_lassert (log, res != 8 || mask & 0x8);
  return res;
}

static void
ir_encode_set_mem0 (eri_file_t log,
		    xed_encoder_request_t *enc, struct ir_enc_mem_args *mem)
{
  xed_encoder_request_set_base0 (enc,
		ir_xed_reg_from_idx_opt (mem->base, mem->addr_size, 0));
  xed_encoder_request_set_index (enc,
		ir_xed_reg_from_idx_opt (mem->index, mem->addr_size, 0));
  xed_encoder_request_set_seg0 (enc, mem->seg);
  xed_encoder_request_set_scale (enc, mem->scale);
  xed_encoder_request_set_memory_displacement (enc, mem->disp,
				ir_min_width_signed (log, mem->disp, 0x4));
  xed_encoder_request_set_memory_operand_length (enc, mem->size);
}

static uint8_t
ir_encode_load (eri_file_t log, uint8_t *bytes,
		uint8_t dst, struct ir_enc_mem_args *src)
{
  eri_log8 (log, "%u %u %u %lu\n", dst, src->base, src->index, src->disp);
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, src->size, src->addr_size);

  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0,
			       ir_xed_reg_from_idx (log, dst, src->size, 0));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_mem0 (&enc);
  ir_encode_set_mem0 (log, &enc, src);
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_MEM0);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_load_imm (eri_file_t log,
		    uint8_t *bytes, uint8_t dst, int64_t src)
{
  eri_log8 (log, "%s %lx\n", trans_reg_str (dst), src);
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, 8, 8);

  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (log, dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_uimm0 (&enc, src,
				 ir_min_width_signed (log, src, 0xc));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_IMM0);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_store (eri_file_t log, uint8_t *bytes,
		 struct ir_enc_mem_args *dst, uint8_t src)
{
  eri_log8 (log, "%u %u %lu %u\n", dst->base, dst->index, dst->disp, src);
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, dst->size, dst->addr_size);

  xed_encoder_request_set_mem0 (&enc);
  ir_encode_set_mem0 (log, &enc, dst);
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_MEM0);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0,
			       ir_xed_reg_from_idx (log, src, dst->size, 0));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_REG0);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_store_imm (eri_file_t log, uint8_t *bytes,
		     struct ir_enc_mem_args *dst, uint64_t src)
{
  eri_log8 (log, "%u %u %lu %lu\n", dst->base, dst->index, dst->disp, src);
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_MOV, dst->size, dst->addr_size);

  xed_encoder_request_set_mem0 (&enc);
  ir_encode_set_mem0 (log, &enc, dst);
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_MEM0);
  xed_encoder_request_set_uimm0 (&enc, src, eri_min (dst->size, 4));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_IMM0);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_lea (eri_file_t log, uint8_t *bytes,
	       uint8_t dst, struct ir_enc_mem_args *src)
{
  eri_log8 (log, "%u %u %u %lu %u %u\n", dst,
	    src->base, src->index, src->disp, src->size, src->addr_size);
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_LEA, 8, src->addr_size);

  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (log, dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_agen (&enc);
  ir_encode_set_mem0 (log, &enc, src);
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_AGEN);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_pushf (eri_file_t log, uint8_t *bytes)
{
  eri_log8 (log, "\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_PUSHFQ, 8, 8);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_popf (eri_file_t log, uint8_t *bytes)
{
  eri_log8 (log, "\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_POPFQ, 8, 8);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_cmov (eri_file_t log, uint8_t *bytes,
		xed_iclass_enum_t iclass, uint8_t dst, uint8_t src)
{
  eri_log8 (log, "\n");
  return ir_encode_bin (log, bytes, iclass, dst, src);
}

static uint8_t
ir_encode_add (eri_file_t log, uint8_t *bytes, uint8_t dst, uint8_t src)
{
  eri_log8 (log, "\n");
  return ir_encode_bin (log, bytes, XED_ICLASS_ADD, dst, src);
}

static uint8_t
ir_encode_add_imm (eri_file_t log, uint8_t *bytes, uint8_t dst, uint64_t src)
{
  eri_log8 (log, "\n");
  return ir_encode_bin_imm (log, bytes, XED_ICLASS_ADD, dst, src);
}

static uint8_t
ir_encode_str_op (eri_file_t log, uint8_t *bytes,
		  xed_iclass_enum_t iclass, uint8_t addr_size)
{
  eri_log8 (log, "\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, ir_str_op_size (iclass), addr_size);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_cmp (eri_file_t log, uint8_t *bytes, uint8_t a, uint8_t b)
{
  eri_log8 (log, "\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_CMP, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (log, a));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG1, ir_xreg (log, b));
  xed_encoder_request_set_operand_order (&enc, 1, XED_OPERAND_REG1);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_jmp (eri_file_t log, uint8_t *bytes, uint8_t dst)
{
  eri_log8 (log, "\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, XED_ICLASS_JMP, 8, 8);
  xed_encoder_request_set_reg (&enc, XED_OPERAND_REG0, ir_xreg (log, dst));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_REG0);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_jmp_mem (eri_file_t log, uint8_t *bytes,
		   struct ir_enc_mem_args *dst)
{
  eri_log8 (log, "\n");
  xed_encoder_request_t enc;
  eri_lassert (log, dst->size == 8);
  ir_init_encode (&enc, XED_ICLASS_JMP, dst->size, dst->addr_size);
  xed_encoder_request_set_mem0 (&enc);
  ir_encode_set_mem0 (log, &enc, dst);
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_MEM0);
  return ir_encode (log, bytes, &enc);
}

static uint8_t
ir_encode_cjmp_relbr (eri_file_t log, uint8_t *bytes,
		xed_iclass_enum_t iclass, uint8_t addr_size, int64_t rel)
{
  eri_log8 (log, "\n");
  xed_encoder_request_t enc;
  ir_init_encode (&enc, iclass, 8, addr_size);
  xed_encoder_request_set_relbr (&enc);
  xed_encoder_request_set_branch_displacement (&enc, rel,
	ir_min_width_signed (log, rel,
			     ir_cond_branch_loop (iclass) ? 0x1 : 0x7));
  xed_encoder_request_set_operand_order (&enc, 0, XED_OPERAND_RELBR);
  return ir_encode (log, bytes, &enc);
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
ir_encode_inst (eri_file_t log, uint8_t *bytes, xed_decoded_inst_t *dec)
{
  eri_log8 (log, "\n");
  xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (dec);

  xed_encoder_request_init_from_decode (dec);
  xed_encoder_request_t *enc = dec;
  xed_encoder_request_set_iclass (enc, ir_remove_lock (iclass));
  return ir_encode (log, bytes, enc);
}

static void
ir_emit_raw (struct ir_flat *flat, uint8_t *bytes, uint64_t len)
{
  eri_file_t log = flat->dag->log;
  if (eri_global_enable_debug >= 2)
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
	      eri_rlog (log, "%lx:", flat->insts.o + i);
	      uint8_t j;
	      for (j = 0; j < len - i; ++j)
		eri_rlog (log, " %x", bytes[i + j]);
	      eri_rlog (log, "\n");
	      break;
	    }
	  else ir_dump_dis_dec (log, flat->insts.o + i, &dec);
	}
    }

  eri_assert_buf_append (&flat->insts, bytes, len);
  eri_log8 (log, "rip: %lx\n", flat->insts.o);
}

#define ir_emit(what, flat, ...) \
  ({									\
    struct ir_flat *_flat = flat;					\
    uint8_t _bytes[INST_BYTES];						\
    uint8_t _l = ERI_PASTE (ir_encode_, what) (				\
			_flat->dag->log, _bytes, ##__VA_ARGS__);	\
    ir_emit_raw (_flat, _bytes, _l);					\
    _l;									\
  })

static void
ir_trace_inc_access (struct ir_flat *flat, uint64_t rip_off, uint8_t len)
{
  flat->access->rip_off = rip_off;
  flat->access->inst_len = len;
  if (flat->access->var) ++flat->access_idx;
  if (flat->access->cond) ++flat->access_cond_idx;
  ++flat->access;
}

static void
ir_add_trace_guest (struct ir_flat *flat, uint8_t idx,
		    struct trans_loc loc)
{
  if (idx == TRANS_RIP)
    {
      eri_log4 (flat->dag->log, "%lx\n", flat->insts.o);
      ir_trace_inc_access (flat, flat->insts.o, 0);
    }
  struct trace_guest t = { flat->insts.o, idx, loc };
  eri_assert_buf_append (&flat->traces, &t, 1);
}

static void
ir_set_guest_loc (struct ir_flat *flat, uint8_t idx)
{
  struct ir_guest_loc *guest_loc = flat->guest_locs + idx;

  struct ir_def *guest = guest_loc->def;
  struct ir_host_locs *locs = &guest->locs;
  struct trans_loc *trace = &guest_loc->loc;

  if (! guest->node)
    trans_set_loc (trace, TRANS_LOC_IMM, guest->imm);
  else
    {
      uint8_t host_idx = ir_host_idxs_get_reg_idx (locs->host_idxs);
      if (host_idx != TRANS_REG_NUM)
	trans_set_loc (trace, TRANS_LOC_REG, host_idx);
      else
	trans_set_loc (trace, TRANS_LOC_LOCAL, locs->local->idx);
    }

  ir_add_trace_guest (flat, idx, *trace);
}

static void
ir_try_fix_guest_loc (struct ir_flat *flat, uint8_t idx)
{
  struct ir_guest_loc *guest_loc = flat->guest_locs + idx;

  struct ir_def *guest = guest_loc->def;
  struct ir_host_locs *locs = &guest->locs;
  struct trans_loc *trace = &guest_loc->loc;

  eri_log8 (flat->dag->log,
	    "def: %lx, idxs: %x, local: %lx, tag: %u, val: %u\n",
	    guest, locs->host_idxs, locs->local, trace->tag, trace->val);

  if ((trace->tag == TRANS_LOC_REG
       && ! ir_host_idxs_set (locs->host_idxs, trace->val))
      || (trace->tag == TRANS_LOC_LOCAL
	  && (! locs->local || locs->local->idx != trace->val))
      || (trace->tag == TRANS_LOC_IMM
	  && (guest->node || guest->imm != trace->val)))
    ir_set_guest_loc (flat, idx);
}

static void
ir_try_update_guest_loc (struct ir_flat *flat, struct ir_def *def)
{
  uint8_t i;
  for (i = 0; i < TRANS_REG_NUM; ++i)
    if (flat->guest_locs[i].def == def) ir_try_fix_guest_loc (flat, i);
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

static void
ir_dump_ras (eri_file_t log, struct ir_ra *ras, uint32_t n)
{
  uint32_t i;
  for (i = 0; i < n; ++i)
    {
      eri_rlog (log, "ir_ra: %u, %lx, %lx, %u\n",
		ras[i].host_idx, ras[i].dep, ras[i].def, ras[i].exclusive);
      if (ras[i].dep)
	eri_rlog (log, "  dep: %lx, %x, %lx\n", ras[i].dep,
		  ras[i].dep->locs.host_idxs, ras[i].dep->locs.local);
      if (ras[i].def)
	eri_rlog (log, "  def: %lx, %x, %lx\n", ras[i].def,
		  ras[i].def->locs.host_idxs, ras[i].def->locs.local);
    }
}

struct ir_assign
{
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
  for (i = 0; i < TRANS_GPREG_NUM; ++i)
    if (assigns[i].dep == ra->dep && ! assigns[i].exclusive
	&& ! ra->exclusive && (! assigns[i].def || ! ra->def))
      {
	ra->host_idx = i;
	if (ra->def) assigns[i].def = ra->def;
	break;
      }
}

static void
ir_assign_set_dep (struct ir_assign *assigns, uint8_t i, struct ir_ra *ra)
{
  ra->host_idx = i;
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
ir_assign_dep_try_current (struct ir_assign *assigns, struct ir_ra *ra)
{
  uint8_t i;
  for (i = 0; i < TRANS_GPREG_NUM; ++i)
    if (! assigns[i].destroyed && ir_assign_dep_assignable (assigns + i, ra)
	&& ir_host_idxs_set (ra->dep->locs.host_idxs, i))
      {
	ir_assign_set_dep (assigns, i, ra);
	break;
      }
}

static uint8_t
ir_assign_more_than_one_host_gpregs (
			struct ir_def *def, struct ir_assign *assigns)
{
  uint8_t i, n = 0;
  for (i = 0; i < TRANS_GPREG_NUM; ++i)
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
  return def->node || ridx == -1 ? ridx : (ridx + 1) / 2;
}

static void
ir_assign_dep_pick (struct ir_flat *flat, struct ir_assign *assigns,
		    struct ir_ra *ra)
{
  uint8_t min = TRANS_REG_NUM;
  uint64_t min_ridx = -1;

  uint8_t i;
  for (i = 0; i < TRANS_GPREG_NUM; ++i)
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

  eri_log8 (flat->dag->log, "pick %s\n", trans_reg_str (min));
  eri_lassert (flat->dag->log, min != TRANS_REG_NUM);
  ir_assign_set_dep (assigns, min, ra);
}

static void
ir_assign_def_pick (struct ir_flat *flat, struct ir_assign *assigns,
		    struct ir_ra *ra)
{
  uint8_t min = TRANS_REG_NUM;
  uint64_t min_ridx = -1;

  uint8_t i;
  for (i = 0; i < TRANS_GPREG_NUM; ++i)
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

  eri_log8 (flat->dag->log, "pick %s\n", trans_reg_str (min));
  eri_lassert (flat->dag->log, min != TRANS_REG_NUM);
  ra->host_idx = min;
  assigns[min].def = ra->def;
}

static uint8_t
ir_host_locs_has_gpreg_or_local (struct ir_host_locs *locs)
{
  return ir_host_idxs_has_gpreg (locs->host_idxs) || locs->local;
}

static void
ir_assign_check_rflags (struct ir_flat *flat,
		struct ir_assign *assigns, struct ir_ra *ras, uint32_t n)
{
  struct ir_def *old = flat->hosts[TRANS_RFLAGS];

  if (assigns[TRANS_RFLAGS].dep && assigns[TRANS_RFLAGS].dep != old)
    {
      assigns[TRANS_RSP].destroyed = 1;
      return;
    }

  if (! ir_def_in_use (old)
      || ir_host_locs_has_gpreg_or_local (&old->locs))
    return;

  if (assigns[TRANS_RFLAGS].def && ir_def_continue_in_use (old))
    {
      assigns[TRANS_RSP].destroyed = 1;
      return;
    }

  uint32_t i;
  for (i = 0; i < TRANS_REG_NUM; ++i)
    if (assigns[i].dep == old)
      {
	assigns[TRANS_RSP].destroyed = 1;
	return;
      }

  for (i = 0; i < n; ++i)
    if (ras[i].host_idx == TRANS_REG_NUM && ras[i].dep && ras[i].dep == old)
      {
	assigns[TRANS_RSP].destroyed = 1;
	return;
      }
}

static void
ir_init_host (struct ir_flat *flat, uint8_t idx, struct ir_def *def)
{
  eri_log8 (flat->dag->log, "%lx %u\n", def, idx);

  flat->hosts[idx] = def;
  ir_host_idxs_add (&def->locs.host_idxs, idx);
}

static void
ir_set_host (struct ir_flat *flat, uint8_t idx, struct ir_def *def)
{
  eri_log8 (flat->dag->log, "%s = %lx\n", trans_reg_str (idx), def);
  ir_host_idxs_del (&flat->hosts[idx]->locs.host_idxs, idx);
  ir_init_host (flat, idx, def);
}

static uint64_t
ir_assign_get_local (struct ir_flat *flat, struct ir_def *def)
{
  eri_assert (! def->locs.local);
  def->locs.local = ir_get_local (flat);
  return def->locs.local->idx;
}

static void
ir_assign_init_local_enc_mem_args_size (struct ir_flat *flat,
		uint64_t idx, struct ir_enc_mem_args *args, uint8_t size)
{
  args->base = ir_local_host_idx (flat);
  eri_lassert (flat->dag->log, args->base != TRANS_REG_NUM);
  args->index = TRANS_REG_NUM;
  args->seg = XED_REG_INVALID;
  args->scale = 1;
  args->disp = idx * size;
  args->size = size;
  args->addr_size = 8;
}

static void
ir_assign_init_local_enc_mem_args (struct ir_flat *flat, uint64_t idx,
				   struct ir_enc_mem_args *args)
{
  ir_assign_init_local_enc_mem_args_size (flat, idx, args, 8);
}

static void
ir_assign_move (struct ir_flat *flat,
		struct trans_loc dst, struct trans_loc src)
{
  eri_log8 (flat->dag->log, "\n");
  struct ir_enc_mem_args mem;
  if (dst.tag == TRANS_LOC_REG)
    {
      if (dst.val == TRANS_RFLAGS)
	{
	  eri_assert (src.tag == TRANS_LOC_LOCAL);
	  ir_assign_init_local_enc_mem_args (flat, src.val, &mem);
	  ir_emit (lea, flat, TRANS_RSP, &mem);
	  ir_emit (popf, flat);
	}
      else if (src.tag == TRANS_LOC_REG)
	ir_emit (mov, flat, dst.val, src.val);
      else if (src.tag == TRANS_LOC_LOCAL)
	{
	  ir_assign_init_local_enc_mem_args (flat, src.val, &mem);
	  ir_emit (load, flat, dst.val, &mem);
	}
      else
	ir_emit (load_imm, flat, dst.val, src.val);
    }
  else if (src.tag == TRANS_LOC_REG)
    {
      if (src.val == TRANS_RFLAGS)
	{
	  ir_assign_init_local_enc_mem_args (flat, dst.val + 1, &mem);
	  ir_emit (lea, flat, TRANS_RSP, &mem);
	  ir_emit (pushf, flat);
	}
      else
	{
	  ir_assign_init_local_enc_mem_args (flat, dst.val, &mem);
	  ir_emit (store, flat, &mem, src.val);
	}
    }
  else
    {
      ir_assign_init_local_enc_mem_args (flat, dst.val, &mem);
      ir_emit (store_imm, flat, &mem, src.val);
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
ir_assign_spill (struct ir_flat *flat,
		 struct ir_def *def, struct ir_assign *assigns)
{
  if (! ir_host_idxs_has_gpreg (def->locs.host_idxs))
    {
      struct ir_def *check_guest = flat->hosts[TRANS_RSP];

      struct trans_loc dst = {
	TRANS_LOC_LOCAL, ir_assign_get_local (flat, def)
      };
      struct trans_loc src = { TRANS_LOC_REG, TRANS_RFLAGS };
      ir_set_host (flat, TRANS_RSP, &flat->dummy);
      ir_assign_move (flat, dst, src);
      eri_log8 (flat->dag->log, "try update\n");
      ir_try_update_guest_loc (flat, check_guest);
      return;
    }

  uint8_t i;
  for (i = 0; i < TRANS_GPREG_NUM; ++i)
    if (! ir_def_in_use (flat->hosts[i])
	&& def == assigns[i].dep && ! assigns[i].destroyed)
      break;

  if (i == TRANS_GPREG_NUM)
    for (i = 0; i < TRANS_GPREG_NUM; ++i)
      if (! ir_def_in_use (flat->hosts[i])
	  && ! assigns[i].dep && ! assigns[i].def && ! assigns[i].destroyed)
	break;

  struct trans_loc src = {
    TRANS_LOC_REG, ir_host_idxs_get_gpreg_idx (def->locs.host_idxs)
  };

  if (i != TRANS_GPREG_NUM)
    {
      struct trans_loc dst = { TRANS_LOC_REG, i };
      ir_set_host (flat, i, def);
      ir_assign_move (flat, dst, src);
      return;
    }

  struct trans_loc dst = {
    TRANS_LOC_LOCAL, ir_assign_get_local (flat, def)
  };
  eri_log8 (flat->dag->log, "%lu\n", dst.val);
  ir_assign_move (flat, dst, src);
}

static void
ir_assign_prepare_rflags (struct ir_flat *flat,
			  struct ir_assign *assigns)
{
  if (ir_def_in_use (flat->hosts[TRANS_RSP])
      && ir_assign_may_spill (flat->hosts[TRANS_RSP], TRANS_RSP))
    ir_assign_spill (flat, flat->hosts[TRANS_RSP], assigns);
}

static void
ir_assign_save_to_local (struct ir_flat *flat,
			 struct ir_def *def, uint8_t tmp_idx)
{
  struct trans_loc dst = {
    TRANS_LOC_LOCAL, ir_assign_get_local (flat, def)
  };
  struct trans_loc src;
  uint8_t gpreg = ir_host_idxs_get_gpreg_idx (def->locs.host_idxs);
  if (gpreg != TRANS_REG_NUM)
    {
      src.tag = TRANS_LOC_REG;
      src.val = gpreg;
    }
  else
    {
      eri_lassert (flat->dag->log, ! def->node);
      trans_set_loc (&src, TRANS_LOC_IMM, def->imm);
      if (ir_min_width_signed (flat->dag->log, src.val, 0xc) == 8)
	{
	  struct trans_loc tmp = { TRANS_LOC_REG, tmp_idx };
	  ir_assign_move (flat, tmp, src);
	  src = tmp;
	}
    }
  ir_assign_move (flat, dst, src);
}

static void
ir_assign_load_dep (struct ir_flat *flat,
		    uint8_t idx, struct ir_def *def)
{
  struct trans_loc dst = { TRANS_LOC_REG, idx };

  if (idx == TRANS_RFLAGS)
    {
      ir_set_host (flat, idx, def);
      ir_set_host (flat, TRANS_RSP, &flat->dummy);
      if (! def->locs.local)
	ir_assign_save_to_local (flat, def, TRANS_RSP);

      struct trans_loc src = { TRANS_LOC_LOCAL, def->locs.local->idx };
      ir_assign_move (flat, dst, src);
      return;
    }

  uint8_t gpreg = ir_host_idxs_get_gpreg_idx (def->locs.host_idxs);
  ir_set_host (flat, idx, def);
  struct trans_loc src;
  if (! def->node)
    trans_set_loc (&src, TRANS_LOC_IMM, def->imm);
  else if (gpreg != TRANS_REG_NUM)
    trans_set_loc (&src, TRANS_LOC_REG, gpreg);
  else
    trans_set_loc (&src, TRANS_LOC_LOCAL, def->locs.local->idx);
  ir_assign_move (flat, dst, src);
}

static void
ir_assign_dep_on_rflags (struct ir_flat *flat, struct ir_assign *assigns)
{
  struct ir_def *rflags = flat->hosts[TRANS_RFLAGS];

  uint8_t i;
  for (i = 0; i < TRANS_GPREG_NUM && assigns[i].dep != rflags; ++i)
    continue;
  if (i != TRANS_GPREG_NUM &&
      ! ir_host_locs_has_gpreg_or_local (&rflags->locs))
    {
      ir_assign_prepare_rflags (flat, assigns);
      ir_assign_spill (flat, rflags, assigns);
    }
}

static void
ir_assign_dep (struct ir_flat *flat, struct ir_assign *assigns, uint8_t i)
{
  eri_log8 (flat->dag->log, "\n");
  struct ir_def *old = flat->hosts[i];

  if (assigns[i].dep && assigns[i].dep != old)
    {
      struct ir_def *check_guest = 0;

      if (i == TRANS_RFLAGS)
	ir_assign_prepare_rflags (flat, assigns);
      if (ir_def_in_use (old) && ir_assign_may_spill (old, i))
	{
	  check_guest = old;
	  ir_assign_spill (flat, old, assigns);
	}

      ir_assign_load_dep (flat, i, assigns[i].dep);

      if (check_guest)
	ir_try_update_guest_loc (flat, check_guest);
    }
}

static void
ir_assign_def (struct ir_flat *flat, struct ir_assign *assigns, uint8_t i)
{
  eri_log8 (flat->dag->log, "\n");
  if (! assigns[i].def) return;

  struct ir_def *old = flat->hosts[i];

  if (ir_def_continue_in_use (old) && ir_assign_may_spill (old, i))
    {
      assigns[i].check_guest = old;
      if (i == TRANS_RFLAGS)
	ir_assign_prepare_rflags (flat, assigns);
      ir_assign_spill (flat, old, assigns);
    };
  ir_set_host (flat, i, assigns[i].def);
}

static void
ir_assign_update_usage (struct ir_flat *flat, struct ir_node *node)
{
  uint8_t i;
  for (i = 0; i < TRANS_REG_NUM; ++i)
    if (node->next_guests[i])
      flat->guest_locs[i].def->range.dec_guest_count = 1;

  struct ir_dep *dep;
  ERI_RBT_FOREACH (ir_dep, node, dep)
    if (dep->use_gpreg)
      dep->def->range.next_ridx = dep->ridx;
}

static void
ir_assign_may_free_local (struct ir_flat *flat, struct ir_def *def)
{
  if (ir_def_in_use (def) || ! def->locs.local) return;
  ir_put_local (flat, def->locs.local);
  def->locs.local = (void *) -1; /* sanity check */
}

static void
ir_assign_update_free_deps (struct ir_flat *flat, struct ir_node *node)
{
  uint8_t i;
  for (i = 0; i < TRANS_REG_NUM; ++i)
    if (node->next_guests[i])
      {
	--flat->guest_locs[i].def->range.guest_count;
	flat->guest_locs[i].def->range.dec_guest_count = 0;
	ir_assign_may_free_local (flat, flat->guest_locs[i].def);
	struct ir_def *next = node->next_guests[i];
	if (node->tag == IR_END || node->tag == IR_ERR_END)
	  {
	    if (! next->node)
	      trans_set_loc (flat->final_locs + i, TRANS_LOC_IMM, next->imm);
	    else
	      trans_set_loc (flat->final_locs + i, TRANS_LOC_LOCAL,
			     next->locs.local->idx);
	  }
	else
	  {
	    flat->guest_locs[i].def = next;
	    eri_log8 (flat->dag->log, "try fix\n");
	    ir_try_fix_guest_loc (flat, i);
	  }
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
  eri_assert_buf_append (ras, &a, 1);
  return (struct ir_ra *) ras->buf + ras->o - 1;
}

static void
ir_append_mem_ras (struct eri_buf *ras, struct ir_mem *mem)
{
  ir_append_ra (ras, TRANS_REG_NUM, mem->regs.base.def, 0);
  ir_append_ra (ras, TRANS_REG_NUM, mem->regs.index.def, 0);
}

static struct ir_ra *
ir_init_emit_mem_args (struct ir_enc_mem_args *args,
		       struct ir_mem *mem, struct ir_ra *a)
{
  args->base = mem->regs.base.def ? (a++)->host_idx : TRANS_REG_NUM;
  args->index = mem->regs.index.def ? (a++)->host_idx : TRANS_REG_NUM;

  args->seg = mem->seg;
  args->scale = mem->scale;
  args->disp = mem->disp;
  args->size = mem->size;
  args->addr_size = mem->addr_size;
  return a;
}

static void
ir_trace_access (struct ir_flat *flat, uint8_t len)
{
  ir_trace_inc_access (flat, flat->insts.o, len);
}

static void
ir_try_trace_access (struct ir_flat *flat, struct ir_def *def, uint8_t len)
{
  if (def) ir_trace_access (flat, len);
}

static void
ir_assign_gen_inst_ras (eri_file_t log,
			struct ir_node *node, struct eri_buf *ras)
{
  xed_decoded_inst_t *dec = &node->inst.dec;

  struct ir_inst_reg *inst_reg;
  for (inst_reg = node->inst.regs; inst_reg->op; ++inst_reg)
    {
      const xed_operand_t *op = inst_reg->op;
      ir_append_ra (ras, ir_inst_designated_reg (dec, op)
			? ir_reg_idx_from_dec_op (log, dec, op)
			: TRANS_REG_NUM,
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
    if (mems[i]) ir_append_ra (ras, TRANS_REG_NUM, mems[i], 0);
}

static void
ir_assign_emit_inst (struct ir_flat *flat,
		     struct ir_node *node, struct ir_ra *a)
{
  eri_file_t log = flat->dag->log;
  xed_decoded_inst_t *dec = &node->inst.dec;
  xed_operand_values_t *ops = xed_decoded_inst_operands (dec);

  struct ir_inst_reg *inst_reg;
  for (inst_reg = node->inst.regs; inst_reg->op; ++inst_reg)
    {
      xed_operand_enum_t op_name = xed_operand_name (inst_reg->op);
      xed_reg_enum_t reg = xed_decoded_inst_get_reg (dec, op_name);
      uint8_t size = xed_get_register_width_bits64 (reg) >> 3;
      uint8_t high = reg >= XED_REG_GPR8h_FIRST && reg <= XED_REG_GPR8h_LAST;
      xed_operand_values_set_operand_reg (ops, op_name,
		ir_xed_reg_from_idx (log, (a++)->host_idx, size, high));
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
					  ir_xreg (log, (a++)->host_idx));

  uint8_t len = ir_emit (inst, flat, &node->inst.dec);

  ir_try_trace_access (flat, node->inst.mems[0].regs.read.def, len);
  ir_try_trace_access (flat, node->inst.mems[0].regs.write.def, len);
  ir_try_trace_access (flat, node->inst.mems[1].regs.read.def, len);
  ir_try_trace_access (flat, node->inst.mems[1].regs.write.def, len);
}

static void
ir_assign_gen_end_ras (struct ir_flat *flat,
		       struct ir_node *node, struct eri_buf *ras)
{
  uint8_t i;
  for (i = 0; i < TRANS_REG_NUM; ++i)
    if (i != ir_local_host_idx (flat) && i != TRANS_RIP)
      ir_append_ra (ras, i, 0, &flat->dummy);
}

static void
ir_assign_emit_end (struct ir_flat *flat, struct ir_node *node)
{
  ir_emit (mov, flat, TRANS_RDX, ir_local_host_idx (flat));
  uint64_t off = __builtin_offsetof (struct eri_trans_active, local);
  struct ir_enc_mem_args rsp = {
    TRANS_RDX, TRANS_REG_NUM,
    .disp = __builtin_offsetof (struct eri_trans_active, stack) - off,
    .size = 8, .addr_size = 8
  };
  ir_emit (load, flat, TRANS_RDI, &rsp);
  struct ir_enc_mem_args act = {
    TRANS_RDX, TRANS_REG_NUM, .disp = -off, .size = 8, .addr_size = 8
  };
  ir_emit (lea, flat, TRANS_RDX, &act);
  ir_emit (load_imm, flat, TRANS_RSI, (uint64_t) flat->analysis);
  ir_emit (load_imm, flat, TRANS_RCX, (uint64_t) eri_jump);
  ir_emit (jmp, flat, TRANS_RCX);
}

static void
ir_assign_gen_rec_mem_ras (struct ir_flat *flat,
			   struct ir_node *node, struct eri_buf *ras)
{
  ir_append_mem_ras (ras, &node->rec_mem.mem);
  if (flat->access->type == ERI_ACCESS_READ)
    ir_append_ra (ras, TRANS_REG_NUM, 0, &flat->dummy);
  else
    {
      ir_append_ra (ras, TRANS_REG_NUM, 0, &flat->dummy)->exclusive = 1;
      ir_append_ra (ras, TRANS_REG_NUM, node->rec_mem.map_start.def, 0);
      ir_append_ra (ras, TRANS_REG_NUM, node->rec_mem.map_end.def, 0);
      ir_append_ra (ras, TRANS_RFLAGS, 0, &flat->dummy);
    }
}

enum
{
  LOCAL_INVALID_WRITE,
  LOCAL_PREDEFINED_NUM
};

#define IR_ASSIGN_ENCODE_REC_CHECK_WRITE_INST_NUM	5

static uint32_t
ir_assign_encode_rec_check_write (struct ir_flat *flat,
	uint8_t *bytes, uint8_t addr, uint8_t map_start, uint8_t map_end)
{
  uint8_t invalid[INST_BYTES];
  struct ir_enc_mem_args invalid_write;
  ir_assign_init_local_enc_mem_args (flat, LOCAL_INVALID_WRITE,
				     &invalid_write);
  eri_file_t log = flat->dag->log;
  uint8_t invalid_len = ir_encode_jmp_mem (log, invalid, &invalid_write);

  uint8_t end[INST_BYTES * 2];
  uint8_t end_len = ir_encode_cmp (log, end, addr, map_end);
  end_len += ir_encode_cjmp_relbr (log, end + end_len, XED_ICLASS_JNB,
				   8, invalid_len);

  uint8_t len = ir_encode_cmp (log, bytes, addr, map_start);
  len += ir_encode_cjmp_relbr (log, bytes + len, XED_ICLASS_JB,
			       8, end_len + invalid_len);
  eri_memcpy (bytes + len, end, end_len);
  eri_memcpy (bytes + len + end_len, invalid, invalid_len);
  return len + end_len + invalid_len;
}

struct active_local_layout_args
{
  uint64_t access_vars_count;
  uint64_t access_conds_count;

  void *local;

  void *accesses;
  void *access_conds;

  void *dynamics;
};

static void
active_local_layout (struct active_local_layout_args *args)
{
  args->dynamics = eri_memory_layout (args->local,
	(LOCAL_PREDEFINED_NUM * 8, 0),
	(args->access_vars_count * 8, &args->accesses),
	(eri_round_up (args->access_conds_count, 8), &args->access_conds));
}

static void
ir_active_local_layout (struct active_local_layout_args *args,
			struct ir_dag *dag)
{
  args->access_vars_count = dag->accesses.vars_count;
  args->access_conds_count = dag->accesses.conds_count;
  args->local = 0;

  active_local_layout (args);
}

static void
ir_assign_emit_rec_mem (struct ir_flat *flat,
			struct ir_node *node, struct ir_ra *a)
{
  struct ir_enc_mem_args mem;
  a = ir_init_emit_mem_args (&mem, &node->rec_mem.mem, a);
  ir_emit (lea, flat, a->host_idx, &mem);
  struct ir_enc_mem_args rec;

  struct active_local_layout_args layout;
  ir_active_local_layout (&layout, flat->dag);
  uint64_t idx = ((uint64_t) layout.accesses >> 3) + node->rec_mem.idx;

  ir_assign_init_local_enc_mem_args (flat, idx, &rec);
  ir_emit (store, flat, &rec, a->host_idx);
  if (flat->access->type == ERI_ACCESS_WRITE)
    {
      uint8_t check[INST_BYTES * IR_ASSIGN_ENCODE_REC_CHECK_WRITE_INST_NUM];
      uint32_t len = ir_assign_encode_rec_check_write (flat, check,
			a->host_idx, (a + 1)->host_idx, (a + 2)->host_idx);
      ir_emit_raw (flat, check, len);
    }
}

static uint8_t
ir_assign_def_fits_imml (eri_file_t log, struct ir_def *def)
{
  return ! def->node && ir_min_width_signed (log, def->imm, 0xc) == 4;
}

static void
ir_assign_gen_store_ras (eri_file_t log,
			 struct ir_node *node, struct eri_buf *ras)
{
  ir_append_mem_ras (ras, &node->store.dst);
  struct ir_def *src = node->store.src.def;
  if (! ir_assign_def_fits_imml (log, src))
    ir_append_ra (ras, TRANS_REG_NUM, src, 0);
}

// TODO fs gs
static void ir_try_trace_access (struct ir_flat *flat,
				 struct ir_def *def, uint8_t len);

static void
ir_assign_emit_store (struct ir_flat *flat,
		      struct ir_node *node, struct ir_ra *a)
{
  struct ir_enc_mem_args dst;
  a = ir_init_emit_mem_args (&dst, &node->store.dst, a);
  struct ir_def *src = node->store.src.def;
  uint8_t len = ! ir_assign_def_fits_imml (flat->dag->log, src)
			? ir_emit (store, flat, &dst, a->host_idx)
			: ir_emit (store_imm, flat, &dst, src->imm);
  ir_try_trace_access (flat, node->store.dst.regs.write.def, len);
}

static void
ir_assign_gen_load_ras (struct ir_node *node, struct eri_buf *ras)
{
  ir_append_ra (ras, TRANS_REG_NUM,
		node->load.prim.def, &node->load.dst);
  ir_append_mem_ras (ras, &node->load.src);
}

static void
ir_assign_emit_load (struct ir_flat *flat,
		     struct ir_node *node, struct ir_ra *a)
{
  struct ir_enc_mem_args src;
  ir_init_emit_mem_args (&src, &node->load.src, a + 1);
  uint8_t len = ir_emit (load, flat, a->host_idx, &src);
  ir_try_trace_access (flat, node->load.src.regs.read.def, len);
}

static void
ir_assign_gen_add_ras (struct ir_flat *flat,
		       struct ir_node *node, struct eri_buf *ras)
{
  ir_append_ra (ras, TRANS_REG_NUM,
		node->bin.srcs[0].def, &node->bin.dst);
  if (! ir_assign_def_fits_imml (flat->dag->log, node->bin.srcs[1].def))
    ir_append_ra (ras, TRANS_REG_NUM, node->bin.srcs[1].def, 0);
  ir_append_ra (ras, TRANS_RFLAGS, 0, &flat->dummy);
}

static void
ir_assign_emit_add (struct ir_flat *flat,
		    struct ir_node *node, struct ir_ra *a)
{
  struct ir_def *sec = node->bin.srcs[1].def;
  if (! ir_assign_def_fits_imml (flat->dag->log, sec))
    ir_emit (add, flat, a[0].host_idx, a[1].host_idx);
  else
    ir_emit (add_imm, flat, a[0].host_idx, sec->imm);
}

static void
ir_assign_gen_cond_str_op_ras (struct ir_flat *flat,
			       struct ir_node *node, struct eri_buf *ras)
{
  xed_iclass_enum_t iclass = node->cond_str_op.iclass;
  if (ir_cond_str_op_rdi (iclass))
    ir_append_ra (ras, TRANS_RDI, node->cond_str_op.rdi.def,
		  &node->cond_str_op.def_rdi)->exclusive = 1;
  if (ir_cond_str_op_rsi (iclass))
    ir_append_ra (ras, TRANS_RSI, node->cond_str_op.rsi.def,
		  &node->cond_str_op.def_rsi)->exclusive = 1;
  if (ir_cond_str_op_def_rax (iclass))
    ir_append_ra (ras, TRANS_RAX, node->cond_str_op.rax.def,
		  &node->cond_str_op.def_rax)->exclusive = 1;
  else ir_append_ra (ras, TRANS_RAX, node->cond_str_op.rax.def, 0);
  ir_append_ra (ras, TRANS_RCX, node->cond_str_op.rcx.def,
		&node->cond_str_op.def_rcx)->exclusive = 1;;
  struct ir_def *def_rflags = ir_cond_str_op_def_rflags (iclass)
			? &node->cond_str_op.def_rflags
			: (ir_cond_str_op_rdi (iclass) ? &flat->dummy : 0);
  ir_append_ra (ras, TRANS_RFLAGS,
		node->cond_str_op.rflags.def, def_rflags);
  ir_append_ra (ras, TRANS_REG_NUM, node->cond_str_op.taken.def,
		&node->cond_str_op.dst);
  if (node->cond_str_op.fall.def->node)
    ir_append_ra (ras, TRANS_REG_NUM, node->cond_str_op.fall.def, 0);

  if (ir_cond_str_op_rdi (iclass))
    {
      ir_append_ra (ras, TRANS_REG_NUM,
		    node->cond_str_op.map_start.def, 0);
      ir_append_ra (ras, TRANS_REG_NUM,
		    node->cond_str_op.map_end.def, 0);
    }
}

static uint8_t
ir_assign_encode_cjmp_set_fall (eri_file_t log, uint8_t *bytes,
				struct ir_def *def, struct ir_ra *a)
{
  return def->node
	? ir_encode_mov (log, bytes, (a - 2)->host_idx, (a - 1)->host_idx)
	: ir_encode_load_imm (log, bytes, (a - 1)->host_idx, def->imm);
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

static uint32_t
ir_assign_encode_rec_str_op_access (struct ir_flat *flat,
	uint8_t *bytes, uint8_t addr_size, uint64_t idx, uint64_t cond_idx)
{
  struct active_local_layout_args layout;
  ir_active_local_layout (&layout, flat->dag);

  uint64_t local_idx = ((uint64_t) layout.accesses >> 3) + idx;
  uint64_t local_cond_idx = (uint64_t) layout.access_conds + cond_idx;
  uint8_t reg_idx = flat->access->type == ERI_ACCESS_READ
			? TRANS_RSI : TRANS_RDI;

  eri_file_t log = flat->dag->log;

  uint8_t len = 0;
  if (addr_size == 4)
    {
      struct ir_enc_mem_args mem = {
	reg_idx, TRANS_REG_NUM, .addr_size = 4
      };
      len = ir_encode_lea (log, bytes, reg_idx, &mem);
    }

  struct ir_enc_mem_args rec;
  ir_assign_init_local_enc_mem_args (flat, local_idx, &rec);
  len += ir_encode_store (log, bytes + len, &rec, reg_idx);
  ir_assign_init_local_enc_mem_args_size (flat, local_cond_idx, &rec, 1);
  return len + ir_encode_store_imm (log, bytes + len, &rec, 1);
}

static void
ir_assign_emit_cond_str_op (struct ir_flat *flat,
			    struct ir_node *node, struct ir_ra *a)
{
  xed_iclass_enum_t iclass = node->cond_str_op.iclass;
  uint8_t addr_size = node->cond_str_op.addr_size;

  uint32_t inst_num = IR_ASSIGN_ENCODE_REC_STR_OP_ACCESS_INST_NUM * 2
			+ IR_ASSIGN_ENCODE_REC_CHECK_WRITE_INST_NUM + 2;
  uint8_t op[INST_BYTES * inst_num];
  uint32_t len = 0;
  if (ir_cond_str_op_rsi (iclass))
    len = ir_assign_encode_rec_str_op_access (flat, op, addr_size,
	node->cond_str_op.read_idx, node->cond_str_op.read_cond_idx);
  if (ir_cond_str_op_rdi (iclass))
    {
      len += ir_assign_encode_rec_str_op_access (flat, op + len, addr_size,
	node->cond_str_op.write_idx, node->cond_str_op.write_cond_idx);
      uint8_t map_end = (--a)->host_idx;
      uint8_t map_start = (--a)->host_idx;
      len += ir_assign_encode_rec_check_write (flat, op + len,
				TRANS_RDI, map_start, map_end);
    }

  eri_file_t log = flat->dag->log;
  uint32_t str_op_len = ir_encode_str_op (log, op + len,
					  xed_norep_map (iclass), addr_size);
  uint32_t str_op_off = len += str_op_len;

  uint8_t fall[INST_BYTES];
  uint8_t fall_len = ir_assign_encode_cjmp_set_fall (log,
				 fall, node->cond_str_op.fall.def, a);
  len += ir_encode_cjmp_relbr (log, op + len,
	ir_cjmp_iclass_from_cond_str_op (iclass), addr_size, fall_len);

  ir_emit (cjmp_relbr, flat, addr_size == 8
		? XED_ICLASS_JRCXZ : XED_ICLASS_JECXZ, addr_size, len);

  uint64_t str_op_rip_off = flat->insts.o + str_op_off;
  if (ir_cond_str_op_rsi (iclass))
    ir_trace_inc_access (flat, str_op_rip_off, str_op_len);
  if (ir_cond_str_op_rdi (iclass))
    ir_trace_inc_access (flat, str_op_rip_off, str_op_len);

  ir_emit_raw (flat, op, len);
  ir_emit_raw (flat, fall, fall_len);
}

static void
ir_assign_gen_cond_branch_ras (struct ir_node *node, struct eri_buf *ras)
{
  xed_iclass_enum_t iclass = node->cond_branch.iclass;
  ir_append_ra (ras, TRANS_RFLAGS, node->cond_branch.rflags.def, 0);
  if (ir_cond_branch_loop (iclass))
    ir_append_ra (ras, TRANS_RCX, node->cond_branch.rcx.def,
		  &node->cond_branch.def_rcx)->exclusive = 1;
  else ir_append_ra (ras, TRANS_RCX, node->cond_branch.rcx.def, 0);

  if (! ir_cond_branch_rflags_only (iclass))
    {
      ir_append_ra (ras, TRANS_REG_NUM, node->cond_branch.taken.def,
		    &node->cond_branch.dst);
      if (node->cond_branch.fall.def->node)
	ir_append_ra (ras, TRANS_REG_NUM, node->cond_branch.fall.def, 0);
    }
  else
    {
      ir_append_ra (ras, TRANS_REG_NUM, node->cond_branch.fall.def,
		    &node->cond_branch.dst);
      ir_append_ra (ras, TRANS_REG_NUM, node->cond_branch.taken.def, 0);
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
ir_assign_emit_cond_branch (struct ir_flat *flat,
			    struct ir_node *node, struct ir_ra *a)
{
  xed_iclass_enum_t iclass = node->cond_branch.iclass;

  if (! ir_cond_branch_rflags_only (iclass))
    {
      uint8_t bytes[INST_BYTES];
      uint8_t len = ir_assign_encode_cjmp_set_fall (flat->dag->log, bytes,
					node->cond_branch.fall.def, a);
      ir_emit (cjmp_relbr, flat, iclass, node->cond_branch.addr_size, len);
      ir_emit_raw (flat, bytes, len);
    }
  else ir_emit (cmov, flat, ir_cmov_iclass (iclass),
		(a - 2)->host_idx, (a - 1)->host_idx);
}

static void
ir_assign_gen_ras (struct ir_flat *flat,
		   struct ir_node *node, struct eri_buf *ras)
{
  eri_file_t log = flat->dag->log;
  switch (node->tag)
    {
    case IR_INST: ir_assign_gen_inst_ras (log, node, ras); break;
    case IR_END:
    case IR_ERR_END:
      ir_assign_gen_end_ras (flat, node, ras); break;
    case IR_REC_MEM: ir_assign_gen_rec_mem_ras (flat, node, ras); break;
    case IR_STORE: ir_assign_gen_store_ras (log, node, ras); break;
    case IR_LOAD: ir_assign_gen_load_ras (node, ras); break;
    case IR_ADD: ir_assign_gen_add_ras (flat, node, ras); break;
    case IR_COND_STR_OP:
      ir_assign_gen_cond_str_op_ras (flat, node, ras); break;
    case IR_COND_BRANCH: ir_assign_gen_cond_branch_ras (node, ras); break;
    default: eri_assert_unreachable ();
    }
}

static void
ir_assign_emit (struct ir_flat *flat,
		struct ir_node *node, struct ir_ra *ras, uint32_t n)
{
  switch (node->tag)
    {
    case IR_INST: ir_assign_emit_inst (flat, node, ras); break;
    case IR_END:
    case IR_ERR_END:
      ir_assign_emit_end (flat, node);
      if (node->tag == IR_ERR_END)
	flat->sig_info = node->end.sig_info;
      break;
    case IR_REC_MEM: ir_assign_emit_rec_mem (flat, node, ras); break;
    case IR_STORE: ir_assign_emit_store (flat, node, ras); break;
    case IR_LOAD: ir_assign_emit_load (flat, node, ras); break;
    case IR_ADD: ir_assign_emit_add (flat, node, ras); break;
    case IR_COND_STR_OP:
      ir_assign_emit_cond_str_op (flat, node, ras + n); break;
    case IR_COND_BRANCH:
      ir_assign_emit_cond_branch (flat, node, ras + n); break;
    default: eri_assert_unreachable ();
    }
}

static void
ir_assign_hosts (struct ir_flat *flat, struct ir_node *node)
{
  eri_file_t log = flat->dag->log;
  eri_log4 (log, "%s\n", ir_node_tag_str (node->tag));
  eri_lassert (log, flat->local.range.next_ridx == -1);

  ir_assign_update_usage (flat, node);

  struct eri_buf ras_buf;
  eri_assert_buf_mtpool_init (&ras_buf, flat->dag->pool, 32, struct ir_ra);
  ir_assign_gen_ras (flat, node, &ras_buf);

  struct ir_ra *ras = ras_buf.buf;
  uint32_t n = ras_buf.o;

  if (eri_global_enable_debug >= 8) ir_dump_ras (log, ras, n);

  struct ir_assign assigns[TRANS_REG_NUM] = { 0 };

  uint32_t i;
  for (i = 0; i < n; ++i)
    if (ras[i].host_idx != TRANS_REG_NUM)
      {
	uint8_t idx = ras[i].host_idx;
	struct ir_assign *a = assigns + idx;
	if (ras[i].dep)
	  {
	    eri_lassert (log, ! a->dep);
	    a->dep = ras[i].dep;
	  }

	if (ras[i].def)
	  {
	    eri_lassert (log, ! a->def);
	    a->def = ras[i].def;
	  }

	a->exclusive = ras[i].exclusive;
      }

  ir_assign_check_rflags (flat, assigns, ras, n);

  for (i = 0; i < n; ++i)
    if (ras[i].dep && ras[i].host_idx == TRANS_REG_NUM)
      {
	ir_assign_dep_try_reuse (assigns, ras + i);
	if (ras[i].host_idx == TRANS_REG_NUM)
	  ir_assign_dep_try_current (assigns, ras + i);
      }

  for (i = 0; i < n; ++i)
    if (ras[i].dep && ras[i].host_idx == TRANS_REG_NUM)
      {
	ir_assign_dep_try_reuse (assigns, ras + i);
	if (ras[i].host_idx == TRANS_REG_NUM)
	  ir_assign_dep_pick (flat, assigns, ras + i);
      }

  for (i = 0; i < n; ++i)
    if (ras[i].host_idx == TRANS_REG_NUM)
      ir_assign_def_pick (flat, assigns, ras + i);

  ir_assign_dep_on_rflags (flat, assigns);
  ir_assign_dep (flat, assigns, TRANS_RFLAGS);
  ir_assign_def (flat, assigns, TRANS_RFLAGS);

  for (i = 0; i < TRANS_GPREG_NUM; ++i)
    if (assigns[i].dep) ir_assign_dep (flat, assigns, i);
  for (i = 0; i < TRANS_GPREG_NUM; ++i)
    if (assigns[i].def) ir_assign_def (flat, assigns, i);

  ir_assign_emit (flat, node, ras, n);
  eri_assert_buf_fini (&ras_buf);

  ir_assign_update_free_deps (flat, node);

  if (node->tag != IR_END && node->tag != IR_ERR_END)
    for (i = 0; i < TRANS_REG_NUM; ++i)
      if (assigns[i].check_guest)
	ir_try_update_guest_loc (flat, assigns[i].check_guest);
}

static void
ir_gen_init (struct ir_flat *flat, struct ir_node *node)
{
  uint8_t i;
  for (i = 0; i < TRANS_REG_NUM; ++i)
    {
      if (i != TRANS_RIP)
	node->next_guests[i]->locs.local = ir_get_local (flat);
      flat->guest_locs[i].def = node->next_guests[i];
      ir_set_guest_loc (flat, i);
    }
}

static struct eri_trans *
ir_output (struct ir_dag *dag, struct ir_flat *flat)
{
  struct ir_accesses *a = &dag->accesses;
  struct eri_trans *res = eri_assert_mtmalloc_struct (dag->pool,
	typeof (*res), (insts, flat->insts.o),
	(traces, eri_buf_off (&flat->traces)),
	(accesses.accesses, eri_buf_off (&a->accesses)));

  eri_log8 (dag->log, "res->buf: %lx\n", res->buf);

  eri_memcpy (res->insts, flat->insts.buf, flat->insts.o);
  res->insts_len = flat->insts.o;

  eri_memcpy (res->traces, flat->traces.buf, eri_buf_off (&flat->traces));
  res->traces_num = flat->traces.o;

  eri_memcpy (res->final_locs, flat->final_locs, sizeof res->final_locs);

  res->sig_info = flat->sig_info;

  eri_memcpy (res->accesses.accesses,
	      a->accesses.buf, eri_buf_off (&a->accesses));

  struct active_local_layout_args layout;
  ir_active_local_layout (&layout, dag);
  res->accesses.num = a->accesses.o;
  res->accesses.vars_count = layout.access_vars_count;
  res->accesses.conds_count = layout.access_conds_count;

  res->local_num = flat->local_num;
  return res;
}

static struct eri_trans *
ir_generate (struct ir_dag *dag, void *analysis)
{
  struct ir_flat flat = { dag, { 0, 0, { -1, -1 } }, .analysis = analysis };
  ERI_LST_INIT_LIST (ir_flat, &flat);

  struct active_local_layout_args layout;
  ir_active_local_layout (&layout, dag);
  flat.local_num = (uint64_t) layout.dynamics >> 3;

  struct ir_node *last = dag->last->node;
  ir_mark_ref (dag, last);
  ir_flatten (&flat, last);

  uint8_t local = TRANS_RBP;
  uint8_t i;
  for (i = 0; i < TRANS_REG_NUM; ++i)
    ir_init_host (&flat, i, i == local ? &flat.local : &flat.dummy);

  struct eri_mtpool *pool = dag->pool;
  eri_assert_buf_mtpool_init (&flat.insts, pool, 512, uint8_t);
  eri_assert_buf_mtpool_init (&flat.traces, pool, 32, struct trace_guest);
  struct eri_buf *acc = &dag->accesses.accesses;
  flat.access = acc->buf;

  if (local != TRANS_RDI)
    ir_emit (mov, &flat, local, TRANS_RDI);

  struct ir_node *node;
  ERI_LST_FOREACH (ir_flat, &flat, node)
    if (node->tag == IR_INIT) ir_gen_init (&flat, node);
    else if (node->tag == IR_ERR_END && ! node->end.sig_info.sig)
      ir_emit_raw (&flat, node->end.bytes, node->end.len);
    else ir_assign_hosts (&flat, node);

  if ((uint64_t) flat.access != (uint64_t) acc->buf + eri_buf_off (acc))
    {
      eri_log (dag->log, "%lu %lu\n", ((uint64_t) flat.access
			- (uint64_t) acc->buf) / sizeof (struct access),
	       acc->o);
      eri_lassert (dag->log, 0);
    }

  struct eri_trans *res = ir_output (dag, &flat);

  eri_assert_buf_fini (&flat.insts);
  eri_assert_buf_fini (&flat.traces);
  return res;
}

static void
ir_free_all (struct ir_dag *dag)
{
  struct ir_alloc *a, *na;
  ERI_LST_FOREACH_SAFE (ir_alloc, dag, a, na)
    {
      ir_alloc_lst_remove (dag, a);
      eri_assert_mtfree (dag->pool, a);
    }
}

struct eri_trans *
eri_translate (struct eri_translate_args *args)
{
  eri_file_t log = args->log;

  eri_log2 (log, "rip = %lx\n", args->rip);

  struct ir_dag dag = { args->pool, log };
  ERI_LST_INIT_LIST (ir_alloc, &dag);

  uint32_t max_inst_count = args->tf ? 1 : args->max_inst_count;

  dag.map_start = ir_get_load_imm (&dag, args->map_range->start);
  dag.map_end = ir_get_load_imm (&dag, args->map_range->end);

  eri_assert_buf_mtpool_init (&dag.accesses.accesses,
			      dag.pool, max_inst_count, struct access);

  struct ir_node *init = ir_alloc_node (&dag, IR_INIT, 0);
  dag.init = &init->seq;

  uint8_t i;
  for (i = 0; i < TRANS_REG_NUM; ++i)
    {
      struct ir_def *def = i != TRANS_RIP
				? ir_define (init, init->init.regs + i)
				: ir_get_load_imm (&dag, args->rip);

      init->next_guests[i] = def;
      ir_set_sym (&dag, i, def);
    }

  uint8_t new_tf = 0;
  struct eri_trans *res = 0;

  i = 0;
  while (1)
    {
      struct ir_node *node = ir_create_inst (args, &dag);
      if (! node) break;

      eri_log8 (log, "\n");
      ir_build_inst_operands (&dag, node);

      ir_dump_inst (log, node);

      xed_decoded_inst_t *dec = &node->inst.dec;
      xed_category_enum_t cate = xed_decoded_inst_get_category (dec);
      xed_iclass_enum_t iclass = xed_decoded_inst_get_iclass (dec);

#if 0
      eri_lassert (log, iclass != XED_ICLASS_BOUND);
      eri_lassert (log, iclass != XED_ICLASS_INT);
      eri_lassert (log, iclass != XED_ICLASS_INT1);
      eri_lassert (log, iclass != XED_ICLASS_JMP_FAR);
      eri_lassert (log, iclass != XED_ICLASS_CALL_FAR);
      eri_lassert (log, iclass != XED_ICLASS_RET_FAR);
#endif
      eri_lassert (log, iclass != XED_ICLASS_IRET); /* XXX: ??? */
      eri_lassert (log, iclass != XED_ICLASS_IRETD);
      eri_lassert (log, iclass != XED_ICLASS_IRETQ);

      /* TODO: warn lock */

      if (cate == XED_CATEGORY_SYSCALL)
	{
	  /* XXX: diagnositic */
	  eri_log_info (log, "raw syscall detected\n");
	  goto out;
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

      eri_lassert (log, node->tag == IR_INST);
      ir_finish_inst (&dag, node);
      if (++i == max_inst_count)
	{
	  eri_memset (node->next_guests, 0, sizeof node->next_guests);
	  ir_end (&dag, 0);
	  break;
	}
    }

  eri_log2 (dag.log, "\n");
  res = ir_generate (&dag, args->analysis);
  res->data = args->data;
  res->rip = args->rip;
  res->tf = args->tf;
  res->new_tf = new_tf;

out:
  ir_free_all (&dag);
  eri_assert_buf_fini (&dag.accesses.accesses);
  if (args->len) *args->len = dag.len;
  return res;
}

void
eri_trans_destroy (struct eri_mtpool *pool, struct eri_trans *tr)
{
  eri_assert_mtfree (pool, tr);
}

static void
trans_active_local_layout (struct active_local_layout_args *args,
			   struct eri_trans_active *act)
{
  struct eri_trans *tr = act->trans;
  args->access_vars_count = tr->accesses.vars_count;
  args->access_conds_count = tr->accesses.conds_count;
  args->local = act->local;

  active_local_layout (args);
}

struct eri_trans_active *
eri_trans_create_active (struct eri_trans_create_active_args *args)
{
  struct eri_trans *tr = args->trans;
  struct eri_registers *regs = args->regs;

  struct eri_trans_active *act = eri_assert_mtmalloc (args->pool,
					sizeof *act + tr->local_num * 8);

  act->data = args->data;
  act->trans = tr;
  act->stack = args->stack;

  act->local[LOCAL_INVALID_WRITE] = 0; // TODO detailed check
  struct active_local_layout_args layout;
  trans_active_local_layout (&layout, act);

  eri_memset (layout.access_conds, 0, tr->accesses.conds_count);

  uint64_t *l = layout.dynamics;

#define SAVE_LOCAL_REG(creg, reg) \
  if (ERI_PASTE (TRANS_, creg) != TRANS_RIP)				\
    *l++ = ERI_PASTE (TRANS_, creg) == TRANS_RFLAGS			\
		? regs->reg & ~ERI_RFLAGS_TF : regs->reg;
  ERI_FOREACH_REG (SAVE_LOCAL_REG)
  return act;
}

void
eri_trans_destroy_active (struct eri_mtpool *pool,
			  struct eri_trans_active *act)
{
  eri_assert_mtfree (pool, act);
}

eri_noreturn void
eri_trans_enter_active (struct eri_trans_active *act)
{
  eri_jump (0, act->trans->insts, act->local, 0, 0);
}

static void
collect_accesses (eri_file_t log, struct eri_buf *buf,
		  struct accesses *acc, uint64_t *addrs, uint8_t *conds)
{
  uint64_t i, v = 0, c = 0;
  for (i = 0; i < acc->num; ++i)
    {
      struct access *a = acc->accesses + i;
      uint64_t addr = a->var ? addrs[v++] : a->addr;
      if (! a->cond || conds[c++])
	eri_append_access (buf, addr, a->size, a->type);
    }
  eri_lassert (log, v == acc->vars_count);
  eri_lassert (log, c == acc->conds_count);
}

uint8_t
eri_trans_leave_active (struct eri_trans_leave_active_args *args,
			struct eri_siginfo *info)
{
  struct eri_trans_active *act = args->act;
  eri_file_t log = args->log;

  struct eri_trans *tr = act->trans;
  struct trans_loc *finals = tr->final_locs;
  uint64_t *local = act->local;

  struct eri_registers *regs = args->regs;
#define GET_FINAL_REG(creg, reg) \
  do {									\
    struct trans_loc *_l = finals + ERI_PASTE (TRANS_, creg);		\
    regs->reg = _l->tag == TRANS_LOC_IMM ? _l->val : local[_l->val];	\
  } while (0);
  ERI_FOREACH_REG (GET_FINAL_REG)
  if (! tr->new_tf && tr->tf) regs->rflags |= ERI_RFLAGS_TF;

  struct active_local_layout_args layout;
  trans_active_local_layout (&layout, act);

  collect_accesses (log, args->accesses, &tr->accesses,
		    layout.accesses, layout.access_conds);

  *info = tr->sig_info;
  return tr->tf;
}

static uint64_t
get_reg_from_mctx_by_idx (const struct eri_mcontext *mctx, uint8_t idx)
{
  switch (idx)
   {
#define GET_REG_FROM_CTX(creg, reg) \
   case (ERI_PASTE (TRANS_, creg)): return mctx->reg;
   ERI_FOREACH_REG (GET_REG_FROM_CTX)
   default: eri_assert_unreachable ();
   }
}

uint8_t
eri_trans_sig_within_active (struct eri_trans_active *act, uint64_t rip)
{
  struct eri_trans *tr = act->trans;
  struct eri_range range = {
    (uint64_t) tr->insts, (uint64_t) tr->insts + tr->insts_len
  };
  return eri_within (&range, rip);
}

static void
sig_collect_accesses (struct eri_buf *buf, uint64_t rip_off,
		const struct eri_siginfo *info,
		struct accesses *acc, uint64_t *addrs, uint8_t *conds)
{
  uint64_t i, v = 0, c = 0;
  for (i = 0; i < acc->num; ++i)
    {
      struct access *a = acc->accesses + i;
      if (a->rip_off <= rip_off
	  || (si_map_err (info) && a->rip_off - a->inst_len == rip_off))
	{
	  uint64_t addr = a->var ? addrs[v++] : a->addr;
	  if (! a->cond || conds[c++])
	    eri_append_access (buf, addrs[i], a->rip_off <= rip_off
		? a->size : info->fault.addr + 1 - addr, a->type);
	}
    }
}

void
eri_trans_sig_leave_active (struct eri_trans_leave_active_args *args,
	const struct eri_siginfo *info, const struct eri_mcontext *mctx)
{
  struct eri_trans_active *act = args->act;
  eri_file_t log = args->log;

  struct eri_trans *tr = act->trans;
  uint64_t rip = mctx->rip;
  eri_log2 (log, "%lx\n", rip - (uint64_t) tr->insts);

  struct active_local_layout_args layout;
  trans_active_local_layout (&layout, act);

  struct trans_loc locs[TRANS_REG_NUM];

  uint64_t rip_off = rip - (uint64_t) tr->insts;
  struct trace_guest *traces = tr->traces;

  uint64_t i;
  for (i = 0; i < tr->traces_num && traces[i].rip_off <= rip_off; ++i)
    locs[traces[i].reg_idx] = traces[i].loc;

  struct eri_registers *regs = args->regs;
#define GET_REG(creg, reg) \
  do {									\
    struct trans_loc *_loc = locs + ERI_PASTE (TRANS_, creg);		\
    if (_loc->tag == TRANS_LOC_REG)					\
      regs->reg = get_reg_from_mctx_by_idx (mctx, _loc->val);		\
    else if (_loc->tag == TRANS_LOC_LOCAL)				\
      regs->reg = act->local[_loc->val];				\
    else								\
      regs->reg = _loc->val;						\
  } while (0);
  ERI_FOREACH_REG (GET_REG)

  sig_collect_accesses (args->accesses, rip_off, info, &tr->accesses,
			layout.accesses, layout.access_conds);
}

void *
eri_trans_active_get_data (struct eri_trans_active *act)
{
  return act->data;
}

void *
eri_trans_active_get_trans_data (struct eri_trans_active *act)
{
  return act->trans->data;
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

void abort (void) { eri_xassert (0, eri_info); }
int32_t fprintf (void *a1, void *a2, ...) { return 0; }
void *stderr;
