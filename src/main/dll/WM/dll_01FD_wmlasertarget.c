/*
 * wmlasertarget (DLL 0x01FD) - the laser target at Krazoa Palace.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/game_object.h"

typedef struct WmlasertargetPlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x1A - 0x10];
    s16 cooldown;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} WmlasertargetPlacement;

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* wmlasertarget_getExtraSize == 0x4. */
typedef struct WmLaserTargetState
{
    s16 cooldown;
    u8 toggleQueued;
    u8 pad3;
} WmLaserTargetState;

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern int ObjHits_GetPriorityHit();

extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E5D90;
extern int GameBit_Get(int id);
extern int Obj_GetPlayerObject(void);
extern void GameBit_Set(int slot, int val);

void wmlasertarget_free(void)
{
}

void wmlasertarget_hitDetect(void)
{
}

void wmlasertarget_release(void)
{
}

void wmlasertarget_initialise(void)
{
}

void wmlasertarget_update(int* obj)
{
    extern u8 framesThisStep;
    extern void GameBit_Set(int slot, int val);
    extern u32 GameBit_Get(int slot);
    u8* def;
    WmLaserTargetState* sub;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    sub = ((GameObject*)obj)->extra;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0)
    {
        sub->toggleQueued = 1;
        sub->cooldown = ((WmlasertargetPlacement*)def)->cooldown;
    }
    if (sub->cooldown <= 0 && sub->toggleQueued != 0)
    {
        if (GameBit_Get(((WmlasertargetPlacement*)def)->unk1E) != 0)
        {
            Obj_SetActiveModelIndex(obj, 0);
            GameBit_Set(((WmlasertargetPlacement*)def)->unk1E, 0);
            GameBit_Set(((WmlasertargetPlacement*)def)->unk20, 0);
        }
        else
        {
            Obj_SetActiveModelIndex(obj, 1);
            GameBit_Set(((WmlasertargetPlacement*)def)->unk1E, 1);
            GameBit_Set(((WmlasertargetPlacement*)def)->unk20, 1);
        }
        sub->toggleQueued = 0;
        sub->cooldown = ((WmlasertargetPlacement*)def)->cooldown;
    }
    else if (sub->cooldown > 0)
    {
        u8 fs = framesThisStep;
        sub->cooldown -= fs;
    }
}

void dll_200_free_nop(void);

int wmlasertarget_getExtraSize(void) { return 0x4; }
int wmlasertarget_getObjectTypeId(void) { return 0x0; }
int dll_200_getExtraSize_ret_40(void);

void wmlasertarget_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5D90);
}

void WM_colrise_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void wmlasertarget_init(char* obj, s8* p)
{
    WmLaserTargetState* inner = ((GameObject*)obj)->extra;
    ((ObjAnimComponent*)obj)->bankIndex = (s8)GameBit_Get(*(s16*)(p + 0x1e));
    inner->cooldown = *(s16*)(p + 0x1a);
    inner->toggleQueued = 0;
}

#pragma opt_strength_reduction off

typedef struct LightSourceFlagByte
{
    u8 looped : 1;
} LightSourceFlagByte;

#pragma opt_common_subs off
#pragma opt_common_subs reset
