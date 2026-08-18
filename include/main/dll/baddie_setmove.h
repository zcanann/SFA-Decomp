#ifndef MAIN_DLL_BADDIE_SETMOVE_H_
#define MAIN_DLL_BADDIE_SETMOVE_H_

#include "types.h"
#include "game/objects/object.h"
#include "global.h"

/*
 * Baddie_SetMove (baddieSetMove) - starts an animation move on a baddie:
 * computes the per-move speed timer at state+0x308 from the move speed,
 * stores the flags byte at state+0x323, switches the active anim move via
 * ObjAnim_SetCurrentMove, then re-enables outgoing hits on the actor.
 *
 * Call order is (obj, state, moveId, speed, moveControlFlags, stateByte).
 */
void baddieSetMove(GameObject* obj, void* state, u8 moveId, f32 speed, u8 moveControlFlags, u8 stateByte);
#define Baddie_SetMove(obj, state, moveId, speed, moveControlFlags, stateByte)                                        \
    baddieSetMove((GameObject*)(obj), (void*)(state), (moveId), (speed), (moveControlFlags), (stateByte))

#endif
