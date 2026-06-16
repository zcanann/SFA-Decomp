#include "main/dll/BW/BWalphaanim.h"
#include "main/game_object.h"


void SB_CloudRunner_onSeqFree(int* obj)
{
    SnowBikeState* p = (SnowBikeState*)obj[0xb8 / 4];
    p->riderPosX = ((GameObject*)obj)->anim.localPosX;
    p->riderPosY = ((GameObject*)obj)->anim.localPosY;
    p->riderPosZ = ((GameObject*)obj)->anim.localPosZ;
    {
        s32 v = ((GameObject*)obj)->anim.rotX - 0x4000;
        p->riderYawOnFree = (s16)v;
    }
    p->riderPitchOnFree = ((GameObject*)obj)->anim.rotZ;
}
