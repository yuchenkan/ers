#ifndef ERI_LIB_OFFSET_H
#define ERI_LIB_OFFSET_H

#define _ERI_DECLARE_SYMBOL_I(sym, val) \
  asm ("__AS_DEFINE__ " #sym "\t%c0" :: "n" ((uint64_t) (val)))
#define ERI_DECLARE_SYMBOL(sym, val) _ERI_DECLARE_SYMBOL_I (sym, val)

#define _ERI_STR_CAT_I(x, y) x##y
#define _ERI_STR_CAT(x, y) _ERI_STR_CAT_I (x, y)

#define ERI_DECLARE_OFFSET(pfx, sym, type, member) \
  ERI_DECLARE_SYMBOL (_ERI_STR_CAT (pfx, sym), __builtin_offsetof (type, member))

#endif
