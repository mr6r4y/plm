/* plm_common.h - common header with basic utility definitions
*/

#ifndef PLM_COMMON_H
#define PLM_COMMON_H

#ifndef PLM_STATIC_ASSERT
#if defined(__cplusplus)
/* Keep C++ case alone: Some versions of gcc will define __STDC_VERSION__ even when compiling in C++ mode. */
#if (__cplusplus >= 201103L)
#define PLM_STATIC_ASSERT(name, x)  static_assert(x, #x)
#endif
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 202311L)
#define PLM_STATIC_ASSERT(name, x)  static_assert(x, #x)
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#define PLM_STATIC_ASSERT(name, x) _Static_assert(x, #x)
#endif
#endif /* !PLM_STATIC_ASSERT */

#endif /* PLM_COMMON_H */
