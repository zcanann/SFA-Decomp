#ifndef MAIN_DLL_BADDIE_SETMOVE_H_
#define MAIN_DLL_BADDIE_SETMOVE_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "global.h"

/*
 * Baddie_SetMove (fn_8014D08C) - starts an animation move on a baddie:
 * computes the per-move speed timer at state+0x308 from the move speed,
 * stores the flags byte at state+0x323, switches the active anim move via
 * ObjAnim_SetCurrentMove, then re-enables outgoing hits on the actor.
 *
 * Call order is (obj, state, moveId, speed, p5, flags). moveId lands in r5,
 * speed (f32) in f1, p5 in r6, flags in r7 - matching the per-caller extern
 * spelling the baddie TUs originally used. A function-like macro (not a
 * static inline) keeps every call byte-identical even inside the per-file
 * "#pragma dont_inline on" regions these baddie TUs use.
 *
 * NOTE: this caller-facing prototype declares `int flags` (byte-neutral at
 * call sites). The DEFINITION in dll_00C9_enemy.c declares the last param as
 * `u8` so the body emits a direct `stb` (no clrlwi). The two prototypes are
 * ABI-equivalent but intentionally NOT shared in one TU (recipe #57:
 * per-file extern types are load-bearing). This header is therefore included
 * only by callers; the definition TU must NOT include it.
 */
void fn_8014D08C(GameObject* obj, int state, int moveId, f32 speed, int p5, int flags);
#define Baddie_SetMove(obj, state, moveId, speed, p5, flags)                                                           \
    fn_8014D08C((GameObject*)(obj), (int)(state), (moveId), (speed), (p5), (flags))

#endif
