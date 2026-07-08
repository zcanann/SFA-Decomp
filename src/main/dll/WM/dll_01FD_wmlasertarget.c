/*
 * wmlasertarget (DLL 0x01FD) - the laser target at Krazoa Palace.
 *
 * Each priority hit queues a toggle; once the cooldown runs out the
 * target flips its model bank and its two game bits together, then
 * rearms the cooldown from the placement.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/frame_timing.h"
#include "main/dll/WM/dll_01FD_wmlasertarget.h"

extern f32 lbl_803E5D90; /* 1.0: render scale */
extern void Obj_SetActiveModelIndex(int* obj, int idx);

int WM_LaserTarget_getExtraSize(void)
{
    return sizeof(WmLaserTargetState);
}
int WM_LaserTarget_getObjectTypeId(void)
{
    return 0x0;
}

void WM_LaserTarget_free(void)
{
}

void WM_LaserTarget_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E5D90);
}

void WM_LaserTarget_hitDetect(void)
{
}

void WM_LaserTarget_update(int* obj)
{

    u8* def;
    WmLaserTargetState* sub;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    if (ObjHits_GetPriorityHit((int)obj, 0, 0, 0) != 0)
    {
        sub->toggleQueued = 1;
        sub->cooldown = ((WmLaserTargetPlacement*)def)->cooldown;
    }
    if (sub->cooldown <= 0 && sub->toggleQueued != 0)
    {
        if (mainGetBit(((WmLaserTargetPlacement*)def)->toggleGameBit) != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
            mainSetBits(((WmLaserTargetPlacement*)def)->toggleGameBit, 0);
            mainSetBits(((WmLaserTargetPlacement*)def)->pairedGameBit, 0);
        }
        else
        {
            Obj_SetActiveModelIndex(obj, 1);
            mainSetBits(((WmLaserTargetPlacement*)def)->toggleGameBit, 1);
            mainSetBits(((WmLaserTargetPlacement*)def)->pairedGameBit, 1);
        }
        sub->toggleQueued = 0;
        sub->cooldown = ((WmLaserTargetPlacement*)def)->cooldown;
    }
    else if (sub->cooldown > 0)
    {
        u8 fs = framesThisStep;
        sub->cooldown -= fs;
    }
}

void WM_LaserTarget_init(char* obj, s8* def)
{
    WmLaserTargetState* inner = ((GameObject*)obj)->extra;
    ((ObjAnimComponent*)obj)->bankIndex = mainGetBit(((WmLaserTargetPlacement*)def)->toggleGameBit);
    inner->cooldown = ((WmLaserTargetPlacement*)def)->cooldown;
    inner->toggleQueued = 0;
}

void WM_LaserTarget_release(void)
{
}

void WM_LaserTarget_initialise(void)
{
}
