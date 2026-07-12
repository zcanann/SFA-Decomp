/* DLL 0x0120 (trickyguardspot) — Tricky guard spot object. */

#include "main/dll/dll_0120_trickyguardspot.h"
#include "main/objprint_dolphin.h"
#include "main/dll/cannon.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
#include "main/objlib.h"

typedef struct TrickyguardspotPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 triggerRange;
    u8 pad1C[0x1E - 0x1C];
    s16 trickyInRangeGameBit;
} TrickyguardspotPlacement;

extern f32 Vec_xzDistance(f32* a, f32* b);
extern u8 framesThisStep;

int TrickyGuardSpot_getExtraSize(void) { return 0x8; }

void TrickyGuardSpot_free(TrickyGuardSpotObject* obj) { ObjGroup_RemoveObject((int)obj, TRICKY_GUARD_SPOT_GROUP); }

void TrickyGuardSpot_render(void)
{
}

#define TRICKY_GUARD_SPOT_VTABLE(tricky) \
    (*(TrickyGuardSpotInterfaceVTable **)((tricky)->dll))

void TrickyGuardSpot_update(TrickyGuardSpotObject* obj)
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
            objRenderFn_80041018((GameObject*)obj);
        }
    }
    else if (tricky != NULL)
    {
        TRICKY_GUARD_SPOT_VTABLE(tricky)->resetGuardSpotAction(tricky);
        *(int*)state = placement[0x19] * 0x3c;
    }
    mainSetBits(((TrickyguardspotPlacement*)placement)->trickyInRangeGameBit, flags->trickyInRange);
}

void TrickyGuardSpot_init(TrickyGuardSpotObject* obj, TrickyGuardSpotPlacement* def)
{
    TrickyGuardSpotState* state = obj->state;
    ObjGroup_AddObject((int)obj, TRICKY_GUARD_SPOT_GROUP);
    state->resetTimer = def->resetSeconds * 60;
    obj->objAnim.rotX = (s16)(s32)
    def->initialYaw;
}
