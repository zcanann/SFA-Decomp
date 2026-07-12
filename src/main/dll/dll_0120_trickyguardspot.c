/* DLL 0x0120 (trickyguardspot) — Tricky guard spot object. */

#include "main/dll/dll_0120_trickyguardspot.h"
#include "main/dll/cannon.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
#include "main/objlib.h"

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

    TrickyGuardSpotState* state;
    TrickyGuardSpotPlacement* placement;
    ObjAnimComponent* tricky;
    TrickyGuardSpotStateFlags* flags;

    state = obj->state;
    placement = (TrickyGuardSpotPlacement*)obj->objAnim.placementData;
    tricky = (ObjAnimComponent*)getTrickyObject();
    flags = &state->flags;
    *(u8*)&obj->objAnim.resetHitboxMode =
        (u8)(*(u8*)&obj->objAnim.resetHitboxMode | TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG);
    flags->trickyInRange = 0;
    if (tricky != NULL)
    {
        if ((u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(tricky) != 0)
        {
            if (Vec_xzDistance(&obj->objAnim.worldPosX,
                               (f32*)((char*)tricky + 0x18)) < (f32)(s32)placement->triggerRadius)
            {
                state->resetTimer -= framesThisStep;
                flags->trickyInRange = 1;
            }
        }
    }
    if (state->resetTimer != 0)
    {
        if (tricky != NULL && (u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(tricky) == 0)
        {
            if ((*(u8*)&obj->objAnim.resetHitboxMode & TRICKY_GUARD_SPOT_VISIBLE_HITBOX_FLAG) != 0)
            {
                TRICKY_GUARD_SPOT_VTABLE(tricky)->setGuardSpotAction(
                    tricky, obj, TRICKY_GUARD_SPOT_ACTION, TRICKY_GUARD_SPOT_ACTION_PARAM);
            }
            *(u8*)&obj->objAnim.resetHitboxMode =
                (u8)(*(u8*)&obj->objAnim.resetHitboxMode & ~TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG);
            objRenderFn_80041018((int)obj);
        }
    }
    else if (tricky != NULL)
    {
        TRICKY_GUARD_SPOT_VTABLE(tricky)->resetGuardSpotAction(tricky);
        state->resetTimer = placement->resetSeconds * 0x3c;
    }
    mainSetBits(placement->rangeGameBit, flags->trickyInRange);
}

void TrickyGuardSpot_init(TrickyGuardSpotObject* obj, TrickyGuardSpotPlacement* def)
{
    TrickyGuardSpotState* state = obj->state;
    ObjGroup_AddObject((int)obj, TRICKY_GUARD_SPOT_GROUP);
    state->resetTimer = def->resetSeconds * 60;
    obj->objAnim.rotX = (s16)(s32)
    def->initialYaw;
}
