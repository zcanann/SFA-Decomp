/*
 * n64_mwcc.h — prefix shim for recompiling N64 (GCC/IDO-targeted) decomp C with
 * Metrowerks CodeWarrior GC/2.0 (mwcceppc) for the SFA reference-asm corpus.
 *
 * Force-included via MWCC's `-prefix` before every N64 translation unit. Its only
 * job is to neutralize GCC/IDO-isms MWCC's front-end rejects, so otherwise-portable
 * gameplay C keeps compiling. We are NOT trying to match the N64 binary — only to
 * observe the shape GC/2.0 emits for real, SFA-adjacent C. Anything that can't be
 * neutralized just fails that one unit (logged by the corpus builder, best-effort).
 */
#ifndef REFCORPUS_N64_MWCC_SHIM_H
#define REFCORPUS_N64_MWCC_SHIM_H

/* GCC attribute syntax — MWCC has no __attribute__. Drop it entirely. */
#ifndef __attribute__
#define __attribute__(x)
#endif

/* Inline-asm forms. MWCC's own asm{} differs; the N64 asm bodies are meaningless
 * on PPC anyway, so erase them. __asm__("...") statements become empty. */
#define __asm__(...)
#ifndef asm
#define asm(...)
#endif

/* decomp asm-injection macros (usually already no-op'd in the project's macros.h,
 * defined here too so units that include them out of order still compile). */
#ifndef GLOBAL_ASM
#define GLOBAL_ASM(...)
#endif
#ifndef INCLUDE_ASM
#define INCLUDE_ASM(...)
#endif
#ifndef INCLUDE_RODATA
#define INCLUDE_RODATA(...)
#endif

/* GCC varargs builtins — the N64 libc's <stdarg.h> is `typedef __builtin_va_list
 * va_list;`. MWCC has no __builtin_va_*; map to a plain pointer so prototypes and
 * va-using bodies parse (semantics are irrelevant to a shape corpus). */
#ifndef __builtin_va_list
#define __builtin_va_list char *
#endif
#define __builtin_va_start(ap, last) ((void)((ap) = 0))
#define __builtin_va_arg(ap, type) (*(type *)0)
#define __builtin_va_end(ap) ((void)0)
#define __builtin_va_copy(d, s) ((void)((d) = (s)))

/* GCC keyword spellings MWCC doesn't take. */
#define __inline__ inline
#define __inline inline
#define __const const
#define __volatile__ volatile
#define __restrict
#define restrict

/* Some libultra headers gate on the compiler; steer them off the GCC path without
 * pretending to be GCC (which would pull in __builtin_* we can't provide). */
#ifdef __GNUC__
#undef __GNUC__
#endif

#endif /* REFCORPUS_N64_MWCC_SHIM_H */
