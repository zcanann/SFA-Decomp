#ifndef _global_h_
#define _global_h_

#include "dolphin/types.h"

#define F_PI 3.1415927f
#define SCREEN_WIDTH 640
#define SCREEN_HEIGHT 480

#define S16_TO_RAD(ANGLE) (F_PI * ANGLE / 32768.0f)

#define ARRAY_SIZE(o) (sizeof(o) / sizeof(o[0]))
#define ARRAY_SSIZE(o) ((s32)(sizeof(o) / sizeof(o[0])))

// Align X to the previous N bytes (N must be power of two)
#define ALIGN_PREV(X, N) ((X) & ~((N)-1))
// Align X to the next N bytes (N must be power of two)
#define ALIGN_NEXT(X, N) ALIGN_PREV(((X) + (N)-1), N)
#define IS_ALIGNED(X, N) (((X) & ((N)-1)) == 0)
#define IS_NOT_ALIGNED(X, N) (((X) & ((N)-1)) != 0)

#define JUT_EXPECT(...)
#define LOGF(FMT, ...)

#define _SDA_BASE_(dummy) 0
#define _SDA2_BASE_(dummy) 0

#ifndef offsetof
#define offsetof(type, member) ((unsigned int) & (((type*)0)->member))
#endif

#define SQUARE(x) ((x) * (x))

#ifdef _DEBUG // _DEBUG

#ifndef ASSERT
#define ASSERT(exp) (void)((exp) || (OSPanic(__FILE__, __LINE__, "Failed assertion " #exp), 0))
#endif

#ifndef ASSERTMSG
#if defined(__STDC_VERSION__) && (199901L <= __STDC_VERSION__) || defined(__MWERKS__) || defined(__SN__)
#define ASSERTMSG(exp, ...) (void)((exp) || (OSPanic(__FILE__, __LINE__, __VA_ARGS__), 0))
#else
#define ASSERTMSG(exp, msg) (void)((exp) || (OSPanic(__FILE__, __LINE__, (msg)), 0))
#endif
#endif

#ifndef ASSERTMSG1
#define ASSERTMSG1(exp, msg, param1) (void)((exp) || (OSPanic(__FILE__, __LINE__, (msg), (param1)), 0))
#endif

#ifndef ASSERTMSG2
#define ASSERTMSG2(exp, msg, param1, param2) (void)((exp) || (OSPanic(__FILE__, __LINE__, (msg), (param1), (param2)), 0))
#endif

#ifndef ASSERTMSG3
#define ASSERTMSG3(exp, msg, param1, param2, param3) (void)((exp) || (OSPanic(__FILE__, __LINE__, (msg), (param1), (param2), (param3)), 0))
#endif

#ifndef ASSERTMSG4
#define ASSERTMSG4(exp, msg, param1, param2, param3, param4)                                                                                         \
    (void)((exp) || (OSPanic(__FILE__, __LINE__, (msg), (param1), (param2), (param3), (param4)), 0))
#endif

#else // else _DEBUG

#ifndef ASSERTMSG
#if defined(__STDC_VERSION__) && (199901L <= __STDC_VERSION__) || defined(__MWERKS__) || defined(__SN__)
#define ASSERTMSG(exp, ...) ((void)0)
#else
#define ASSERTMSG(exp, msg) ((void)0)
#endif
#endif

#ifndef ASSERTMSG1
#define ASSERTMSG1(exp, msg, param1) ((void)0)
#endif
#ifndef ASSERTMSG2
#define ASSERTMSG2(exp, msg, param1, param2) ((void)0)
#endif
#ifndef ASSERTMSG3
#define ASSERTMSG3(exp, msg, param1, param2, param3) ((void)0)
#endif
#ifndef ASSERTMSG4
#define ASSERTMSG4(exp, msg, param1, param2, param3, param4) ((void)0)
#endif

#endif // _DEBUG

#ifdef __MWERKS__
#define GLUE(a, b) a##b
#define GLUE2(a, b) GLUE(a, b)
#define STATIC_ASSERT(cond) typedef char GLUE2(static_assertion_failed, __LINE__)[(cond) ? 1 : -1]
#define ALIGN_DECL(ALIGNMENT) __attribute__((aligned(ALIGNMENT)))
#define SECTION_DATA __declspec(section ".data")
#define SECTION_INIT __declspec(section ".init")
#define ASM asm
#define WEAKFUNC __declspec(weak)
#else
#define STATIC_ASSERT(...)
#define ALIGN_DECL(...)
#define SECTION_DATA
#define SECTION_INIT
#define ASM
#define WEAKFUNC
#endif

// Intrinsics
#ifdef __MWERKS__
int __cntlzw(unsigned int);
#endif
// extern int __rlwimi(int, int, int, int, int);
// extern void __dcbz(void*, int);
// extern void __sync();

#define VERSION_JPN 0
#define VERSION_USA 1
#define VERSION_PAL 2

#if VERSION <= VERSION_JPN
    #define VERSION_SELECT(JPN, USA, PAL) (JPN)
#elif VERSION == VERSION_USA
    #define VERSION_SELECT(JPN, USA, PAL) (USA)
#elif VERSION >= VERSION_PAL
    #define VERSION_SELECT(JPN, USA, PAL) (PAL)
#endif

#endif
