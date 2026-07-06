/* DLL 0x0120 (trickyguardspot) — Tricky guard spot object [0x8018B7B0-0x8018B9F0). */

#include "main/dll/CF/CFtoggleswitch.h"
#include "main/dll/cannon.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"

typedef struct TrickyguardspotPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 triggerRange;   /* 0x1A: Tricky must be within this XZ distance to activate */
    u8 pad1C[0x1E - 0x1C];
    s16 trickyInRangeGameBit;
} TrickyguardspotPlacement;

extern f32 Vec_xzDistance(f32* a, f32* b);
extern u8 framesThisStep;
extern void ObjGroup_AddObject(u32 obj, int group);

void trickyguardspot_render(void)
{
}

#define TRICKY_GUARD_SPOT_VTABLE(tricky) \
    (*(TrickyGuardSpotInterfaceVTable **)((tricky)->dll))

void trickyguardspot_update(TrickyGuardSpotObject* obj)
{

    u8* state;
    u8* placement;
    ObjAnimComponent* tricky;
    TrickyGuardSpotStateFlags* flags;

    state = ((GameObject*)obj)->extra;
    placement = *(u8**)&((GameObject*)obj)->anim.placementData;
    tricky = (ObjAnimComponent*)getTrickyObject();
    flags = (TrickyGuardSpotStateFlags*)(state + 4);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG);
    flags->trickyInRange = 0;
    if (tricky != NULL)
    {
        if ((u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(tricky) != 0)
        {
            if (Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX,
                               (f32*)((char*)tricky + 0x18)) < (f32)(s32)((TrickyguardspotPlacement*)placement)->triggerRange)
            {
                *(int*)state = *(int*)state - framesThisStep;
                flags->trickyInRange = 1;
            }
        }
    }
    if (*(u32*)state != 0)
    {
        if (tricky != NULL && (u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(tricky) == 0)
        {
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & TRICKY_GUARD_SPOT_VISIBLE_HITBOX_FLAG) != 0)
            {
                TRICKY_GUARD_SPOT_VTABLE(tricky)->setGuardSpotAction(
                    tricky, obj, TRICKY_GUARD_SPOT_ACTION, TRICKY_GUARD_SPOT_ACTION_PARAM);
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
                (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG);
            objRenderFn_80041018((int)obj);
        }
    }
    else if (tricky != NULL)
    {
        TRICKY_GUARD_SPOT_VTABLE(tricky)->resetGuardSpotAction(tricky);
        *(int*)state = placement[0x19] * 0x3c;
    }
    GameBit_Set(((TrickyguardspotPlacement*)placement)->trickyInRangeGameBit, flags->trickyInRange);
}

int trickyguardspot_getExtraSize(void) { return 0x8; }

void trickyguardspot_free(TrickyGuardSpotObject* obj) { ObjGroup_RemoveObject(obj, TRICKY_GUARD_SPOT_GROUP); }

void trickyguardspot_init(TrickyGuardSpotObject* obj, TrickyGuardSpotPlacement* def)
{
    TrickyGuardSpotState* state = obj->state;
    ObjGroup_AddObject((int)obj, TRICKY_GUARD_SPOT_GROUP);
    state->resetTimer = def->resetSeconds * 60;
    obj->objAnim.rotX = (s16)(s32)
    def->initialYaw;
}

