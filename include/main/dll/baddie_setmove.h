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
 * Call order is (obj, state, moveId, speed, moveControlFlags, stateByte).
 */
void fn_8014D08C(GameObject* obj, int state, u8 moveId, f32 speed, int moveControlFlags, u8 stateByte);
#define Baddie_SetMove(obj, state, moveId, speed, moveControlFlags, stateByte)                                        \
    fn_8014D08C((GameObject*)(obj), (int)(state), (moveId), (speed), (moveControlFlags), (stateByte))

#endif
