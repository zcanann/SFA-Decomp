/*
 * Shared bob-and-sway motion helper for the DIM BossGut2 tendrils.
 *
 * dimbossgut2_updateBobAndSway advances one frame of a gut tendril's vertical
 * bob and lateral sway. The motion values are part of Dimbossgut2Curve, which
 * the owner state references directly.
 */
#include "main/dll/mmsh_waterspike.h"
#include "main/dll/DIM/dll_01E3_dimbossgut2.h"
#include "main/game_object.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"

void dimbossgut2_updateBobAndSway(GameObject* obj, Dimbossgut2State* state)
{
    Dimbossgut2Curve* motion;
    f32 heightDelta;
    s16 rollDelta;

    motion = state->curveData;
    heightDelta = motion->surfaceY - obj->anim.localPosY;

    motion->bobPhase += 0x400;
    heightDelta = heightDelta + (f32)(int)cos16(motion->bobPhase) / 65535.0f;

    motion->verticalVelocity =
        timeDelta * (heightDelta / 50.0f - motion->turnHeightBias) + motion->verticalVelocity;

    obj->anim.localPosY = obj->anim.localPosY + motion->verticalVelocity;

    obj->anim.rotY = (s16)(2048.0f * motion->verticalVelocity);

    rollDelta = (s16) - (u16)obj->anim.rotZ;
    if (rollDelta > 0x8000)
    {
        rollDelta = (s16)((rollDelta - 0x10000) + 1);
    }
    if (rollDelta < (s16)-0x8000)
    {
        rollDelta = (s16)((rollDelta + 0x10000) - 1);
    }

    motion->swayVelocity = motion->swayVelocity + (f32)((int)(rollDelta / 16) * framesThisStep);
    obj->anim.rotZ = (s16)((f32)(int)obj->anim.rotZ + motion->swayVelocity);

    motion->verticalVelocity = motion->verticalVelocity / 1.07f;
    motion->swayVelocity = motion->swayVelocity / 1.04f;
}
