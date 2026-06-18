/* DLL 0x0120 (trickyguardspot) — Tricky guard spot object [0x8018B7B0-0x8018B9F0). */

#include "main/dll/CF/CFtoggleswitch.h"
#include "main/dll/cannon.h"
#include "main/game_object.h"

typedef struct TrickyguardspotPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
} TrickyguardspotPlacement;

extern int* getTrickyObject(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern void objRenderFn_80041018(int obj);
extern u8 framesThisStep;
extern void ObjGroup_AddObject(int obj, int g);

void trickyguardspot_render(void)
{
}

#define TRICKY_GUARD_SPOT_VTABLE(tricky) \
    (*(TrickyGuardSpotInterfaceVTable **)((tricky)->dll))

void trickyguardspot_update(TrickyGuardSpotObject* obj)
{
    extern u64 GameBit_Set(int eventId, int value);
    u8* sub;
    u8* def;
    ObjAnimComponent* tricky;
    TrickyGuardSpotStateFlags* flags;

    sub = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    tricky = (ObjAnimComponent*)getTrickyObject();
    flags = (TrickyGuardSpotStateFlags*)(sub + 4);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG);
    flags->trickyInRange = 0;
    if (tricky != NULL)
    {
        if ((u8)TRICKY_GUARD_SPOT_VTABLE(tricky)->isGuardSpotActionReady(tricky) != 0)
        {
            if (Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX,
                               (f32*)((char*)tricky + 0x18)) < (f32)(s32)((TrickyguardspotPlacement*)def)->unk1A)
            {
                *(int*)sub = *(int*)sub - framesThisStep;
                flags->trickyInRange = 1;
            }
        }
    }
    if (*(u32*)sub != 0)
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
        *(int*)sub = def[0x19] * 0x3c;
    }
    GameBit_Set(((TrickyguardspotPlacement*)def)->unk1E, flags->trickyInRange);
}

int trickyguardspot_getExtraSize(void) { return 0x8; }

void trickyguardspot_free(TrickyGuardSpotObject* obj) { ObjGroup_RemoveObject(obj, TRICKY_GUARD_SPOT_GROUP); }

void trickyguardspot_init(TrickyGuardSpotObject* obj, TrickyGuardSpotPlacement* def)
{
    TrickyGuardSpotState* state = obj->state;
    ObjGroup_AddObject((int)obj, TRICKY_GUARD_SPOT_GROUP);
    state->resetTimer = (int)def->resetSeconds * 60;
    obj->objAnim.rotX = (s16)(s32)
    def->initialYaw;
}

void infotext_init(int obj, s8* def);
