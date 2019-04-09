#ifndef _ERS_PUBLIC_UTIL_H
#define _ERS_PUBLIC_UTIL_H

#define __ERS_STR(...)		#__VA_ARGS__
#define _ERS_STR(...)		__ERS_STR (__VA_ARGS__)

#define __ERS_PASTE(x, y)	x##y
#define _ERS_PASTE(x, y)	__ERS_PASTE (x, y)

#define _ERS_PP_IF_0(...)
#define _ERS_PP_IF_1(...)	__VA_ARGS__
#define _ERS_PP_IF(t, ...)	_ERS_PASTE (_ERS_PP_IF_, t) (__VA_ARGS__)

#endif
