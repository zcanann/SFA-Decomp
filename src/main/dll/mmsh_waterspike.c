/*
 * mmsh_waterspike (DLL 0x18E) - shared spike/stalk bob-and-sway motion helper.
 *
 * fn_801BEEA0 advances one frame of a water-spike's vertical bob and lateral
 * sway. It is exported and reused by dimbossgut2 (DLL 0x1E3) to drive the
 * gut-tendril stalks. The per-instance motion state lives in a small block
 * pointed to from the owner state at +0x40C (laid out by the caller as its
 * curve struct):
 *   +0x00 f32 ySpeed   - current vertical velocity, low-pass smoothed
 *   +0x04 f32 zSpin    - accumulated rotZ sway velocity
 *   +0x08 f32 targetY  - desired height offset
 *   +0x0C f32 baseY    - rest height the spike bobs around
 *   +0x14 s16 phase    - bob phase angle, advanced +0x400/frame
 */
#include "main/dll/mmsh_waterspike.h"
#include "main/game_object.h"
#include "main/frame_timing.h"

f32 gDimBossGut2Pi = 3.1415927f;
f32 gDimBossGut2AngleUnitToRadians = 32768.0f;

extern int cos16(s16 angle);

typedef struct WaterSpikeMotion
{
    /* 0x00 */ f32 ySpeed;  /* current vertical velocity, low-pass smoothed */
    /* 0x04 */ f32 zSpin;   /* accumulated rotZ sway velocity */
    /* 0x08 */ f32 targetY; /* desired height offset */
    /* 0x0C */ f32 baseY;   /* rest height the spike bobs around */
    /* 0x10 */ u8 pad10[4];
    /* 0x14 */ s16 phase; /* bob phase angle, advanced +0x400/frame */
} WaterSpikeMotion;

void fn_801BEEA0(s16* obj, u8* state)
{
    WaterSpikeMotion* motion;
    f32 heightDelta;
    s16 turnDelta;

    motion = (WaterSpikeMotion*)*(int*)(state + 0x40C);
    heightDelta = motion->baseY - ((GameObject*)obj)->anim.localPosY;

    motion->phase += 0x400;
    heightDelta = heightDelta + (f32)(int)cos16(motion->phase) / 65535.0f;

    motion->ySpeed = timeDelta * (heightDelta / 50.0f - motion->targetY) + motion->ySpeed;

    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + motion->ySpeed;

    ((GameObject*)obj)->anim.rotY = (s16)(2048.0f * motion->ySpeed);

    turnDelta = (s16) - (u16)((GameObject*)obj)->anim.rotZ;
    if (turnDelta > 0x8000)
    {
        turnDelta = (s16)((turnDelta - 0x10000) + 1);
    }
    if (turnDelta < (s16)-0x8000)
    {
        turnDelta = (s16)((turnDelta + 0x10000) - 1);
    }

    motion->zSpin = motion->zSpin + (f32)((int)(turnDelta / 16) * framesThisStep);
    ((GameObject*)obj)->anim.rotZ = (s16)((f32)(int)((GameObject*)obj)->anim.rotZ + motion->zSpin);

    motion->ySpeed = motion->ySpeed / 1.07f;
    motion->zSpin = motion->zSpin / 1.04f;
}

