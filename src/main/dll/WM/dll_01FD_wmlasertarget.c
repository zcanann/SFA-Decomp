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

typedef struct WmLaserTargetPlacement
{
    ObjPlacement base;
    u8 pad18[2];
    s16 cooldown;       /* 0x1A: frames between accepted toggles */
    u8 pad1C[2];
    s16 toggleGameBit;  /* 0x1E: the bit the target toggles (also picks
                           the model bank at init) */
    s16 pairedGameBit;  /* 0x20: second bit kept in sync */
    u8 pad22[0x28 - 0x22];
} WmLaserTargetPlacement;

STATIC_ASSERT(offsetof(WmLaserTargetPlacement, cooldown) == 0x1A);
STATIC_ASSERT(offsetof(WmLaserTargetPlacement, toggleGameBit) == 0x1E);
STATIC_ASSERT(offsetof(WmLaserTargetPlacement, pairedGameBit) == 0x20);
STATIC_ASSERT(sizeof(WmLaserTargetPlacement) == 0x28);

typedef struct WmLaserTargetState
{
    s16 cooldown;
    u8 toggleQueued;
    u8 pad3;
} WmLaserTargetState;

STATIC_ASSERT(sizeof(WmLaserTargetState) == 0x4);

extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E5D90; /* 1.0: render scale */

int wmlasertarget_getExtraSize(void) { return sizeof(WmLaserTargetState); }
int wmlasertarget_getObjectTypeId(void) { return 0x0; }

void wmlasertarget_free(void)
{
}

void wmlasertarget_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5D90);
}

void wmlasertarget_hitDetect(void)
{
}

void wmlasertarget_update(int* obj)
{
    extern u8 framesThisStep;

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
        if (GameBit_Get(((WmLaserTargetPlacement*)def)->toggleGameBit) != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
            GameBit_Set(((WmLaserTargetPlacement*)def)->toggleGameBit, 0);
            GameBit_Set(((WmLaserTargetPlacement*)def)->pairedGameBit, 0);
        }
        else
        {
            Obj_SetActiveModelIndex(obj, 1);
            GameBit_Set(((WmLaserTargetPlacement*)def)->toggleGameBit, 1);
            GameBit_Set(((WmLaserTargetPlacement*)def)->pairedGameBit, 1);
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

void wmlasertarget_init(char* obj, s8* def)
{
    WmLaserTargetState* inner = ((GameObject*)obj)->extra;
    ((ObjAnimComponent*)obj)->bankIndex =
        GameBit_Get(((WmLaserTargetPlacement*)def)->toggleGameBit);
    inner->cooldown = ((WmLaserTargetPlacement*)def)->cooldown;
    inner->toggleQueued = 0;
}

void wmlasertarget_release(void)
{
}

void wmlasertarget_initialise(void)
{
}
