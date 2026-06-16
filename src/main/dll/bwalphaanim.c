/*
 * bwalphaanim (BW DLL) - SnowBike / CloudRunner sequence free-callback.
 *
 * SB_CloudRunner_onSeqFree runs when the object's animation sequence is
 * freed: it snapshots the rider's local position and orientation back
 * into the shared SnowBikeState extra block (the same fields the bike's
 * SeqFn seeds on entry, see SB/dll_0259_sbcloudrunner.c). rotX is
 * rebased by 0x4000 (quarter-turn) to recover the rider yaw.
 */
#include "main/dll/BW/BWalphaanim.h"
#include "main/game_object.h"

void SB_CloudRunner_onSeqFree(int* obj)
{
    SnowBikeState* state = ((GameObject*)obj)->extra;
    state->riderPosX = ((GameObject*)obj)->anim.localPosX;
    state->riderPosY = ((GameObject*)obj)->anim.localPosY;
    state->riderPosZ = ((GameObject*)obj)->anim.localPosZ;
    state->riderYawOnFree = (s16)(((GameObject*)obj)->anim.rotX - 0x4000);
    state->riderPitchOnFree = ((GameObject*)obj)->anim.rotZ;
}
