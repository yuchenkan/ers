#ifndef _ERS_UTIL_COMMON_H
#define _ERS_UTIL_COMMON_H

#define ERS_NONE
#define ERS_OMIT(...)

#define _ERS_STR_I(...) #__VA_ARGS__
#define _ERS_STR(...) _ERS_STR_I (__VA_ARGS__)

#define _ERS_EVAL(...) __VA_ARGS__

#define _ERS_PP_IF_0(...)
#define _ERS_PP_IF_1(...) __VA_ARGS__
#define _ERS_PP_IF_I(c, ...) _ERS_PP_IF_##c (__VA_ARGS__)
#define _ERS_PP_IF(c, ...) _ERS_PP_IF_I (c, __VA_ARGS__)

#define _ERS_PP_NOT_0 1
#define _ERS_PP_NOT_1 0
#define _ERS_PP_NOT_I(x) _ERS_PP_NOT_##x
#define _ERS_PP_NOT(x) _ERS_PP_NOT_I (x)

#endif
