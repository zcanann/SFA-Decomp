/*
 * wmlasertarget (DLL 0x01FD) - the laser target at Krazoa Palace.
 *
 * Each priority hit queues a toggle; once the cooldown runs out the
 * target flips its model bank and its two game bits together, then
 * rearms the cooldown from the placement.
 */
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/dll/WM/dll_01FD_wmlasertarget.h"
#include "main/object_render.h"


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

void WM_LaserTarget_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void WM_LaserTarget_hitDetect(void)
{
}

void WM_LaserTarget_update(GameObject* obj)
{

    WmLaserTargetPlacement* placement;
    WmLaserTargetState* state;

    placement = (WmLaserTargetPlacement*)obj->anim.placementData;
    state = obj->extra;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
    {
        state->toggleQueued = 1;
        state->cooldown = placement->cooldown;
    }
    if (state->cooldown <= 0 && state->toggleQueued != 0)
    {
        if (mainGetBit(placement->toggleGameBit) != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
            mainSetBits(placement->toggleGameBit, 0);
            mainSetBits(placement->pairedGameBit, 0);
        }
        else
        {
            Obj_SetActiveModelIndex(obj, 1);
            mainSetBits(placement->toggleGameBit, 1);
            mainSetBits(placement->pairedGameBit, 1);
        }
        state->toggleQueued = 0;
        state->cooldown = placement->cooldown;
    }
    else if (state->cooldown > 0)
    {
        u8 fs = framesThisStep;
        state->cooldown -= fs;
    }
}

void WM_LaserTarget_init(GameObject* obj, WmLaserTargetPlacement* placement)
{
    WmLaserTargetState* state = obj->extra;
    obj->anim.bankIndex = mainGetBit(placement->toggleGameBit);
    state->cooldown = placement->cooldown;
    state->toggleQueued = 0;
}

void WM_LaserTarget_release(void)
{
}

void WM_LaserTarget_initialise(void)
{
}
