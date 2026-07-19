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
 * Call order is (obj, state, moveId, speed, p5, flags). The linked owner TU
 * currently requires an ABI-equivalent parameter spelling, so it cannot
 * include this caller-facing declaration yet.
 */
void fn_8014D08C(GameObject* obj, int state, int moveId, f32 speed, int p5, int flags);
#define Baddie_SetMove(obj, state, moveId, speed, p5, flags)                                                           \
    fn_8014D08C((GameObject*)(obj), (int)(state), (moveId), (speed), (p5), (flags))

#endif
