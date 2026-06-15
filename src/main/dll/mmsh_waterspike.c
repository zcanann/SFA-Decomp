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
    heightDelta = heightDelta + (f32)(int)
    cos16(*(s16*)(motion + 0x14)) / lbl_803E4D00;

    *(f32*)(motion + 0x0) = timeDelta * (heightDelta / lbl_803E4D04 - *(f32*)(motion + 0x8))
        + *(f32*)(motion + 0x0);

    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + *(f32*)(motion + 0x0);

    {
        f32 pitch = lbl_803E4D08 * *(f32*)(motion + 0x0);
        ((GameObject*)obj)->anim.rotY = pitch;
    }

    turnDelta = (s16) - (u16)((GameObject*)obj)->anim.rotZ;
    if (turnDelta > 0x8000)
    {
        turnDelta = (s16)((turnDelta - 0x10000) + 1);
    }
    if ((s16)turnDelta < (s16) - 0x8000)
    {
        turnDelta = (s16)((turnDelta + 0x10000) - 1);
    }

    {
        f32 turnVel = *(f32*)(motion + 0x4) + (f32)((int)((s16)turnDelta / 16) * (int)framesThisStep);
        *(f32*)(motion + 0x4) = turnVel;
        ((GameObject*)obj)->anim.rotZ = turnVel + (f32)(int)((GameObject*)obj)->anim.rotZ;
    }

    *(f32*)(motion + 0x0) = *(f32*)(motion + 0x0) / lbl_803E4D0C;
    *(f32*)(motion + 0x4) = *(f32*)(motion + 0x4) / lbl_803E4D10;
}
