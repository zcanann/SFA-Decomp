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
 * The lbl_803E4D0x floats are shared .sdata2 damping/scale divisors.
 */
#include "main/dll/mmsh_waterspike.h"
#include "main/game_object.h"

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E4D00;
extern f32 lbl_803E4D04;
extern f32 lbl_803E4D08;
extern f32 lbl_803E4D0C;
extern f32 lbl_803E4D10;

extern int cos16(s16 angle);

void fn_801BEEA0(s16* obj, u8* state)
{
    u8* motion;
    f32 heightDelta;
    s16 turnDelta;

    motion = (u8*)*(int*)(state + 0x40C);
    heightDelta = *(f32*)(motion + 0xC) - ((GameObject*)obj)->anim.localPosY;

    *(s16*)(motion + 0x14) += 0x400;
    heightDelta = heightDelta + (f32)(int)cos16(*(s16*)(motion + 0x14)) / lbl_803E4D00;

    *(f32*)(motion + 0x0) = timeDelta * (heightDelta / lbl_803E4D04 - *(f32*)(motion + 0x8))
        + *(f32*)(motion + 0x0);

    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + *(f32*)(motion + 0x0);

    ((GameObject*)obj)->anim.rotY = (s16)(lbl_803E4D08 * *(f32*)(motion + 0x0));

    /* normalize the negated rotZ into the signed s16 angle range */
    turnDelta = (s16) - (u16)((GameObject*)obj)->anim.rotZ;
    if (turnDelta > 0x8000)
    {
        turnDelta = (s16)((turnDelta - 0x10000) + 1);
    }
    if ((s16)turnDelta < (s16) - 0x8000)
    {
        turnDelta = (s16)((turnDelta + 0x10000) - 1);
    }

    *(f32*)(motion + 0x4) = *(f32*)(motion + 0x4) + (f32)((int)((s16)turnDelta / 16) * (int)framesThisStep);
    ((GameObject*)obj)->anim.rotZ = (s16)((f32)(int)((GameObject*)obj)->anim.rotZ + *(f32*)(motion + 0x4));

    *(f32*)(motion + 0x0) = *(f32*)(motion + 0x0) / lbl_803E4D0C;
    *(f32*)(motion + 0x4) = *(f32*)(motion + 0x4) / lbl_803E4D10;
}
