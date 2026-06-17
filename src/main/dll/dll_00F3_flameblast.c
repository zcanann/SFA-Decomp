/*
 * flameblast (DLL 0xF3) - Tricky's fire-breath projectile, a member of
 * the pushable/transporter object family (shares the FUN_80176920 /
 * FUN_801778d0 / FUN_801778e0 sequence helpers with pushable, warppoint,
 * invhit and iceblast).
 *
 * Spawned by Tricky (getTrickyObject), the blast flies along the rotated
 * fire direction: fn_8017805C seeds the velocity from Tricky's heading and
 * the path/queued-particle origin, and flameblast_update integrates the
 * launch position over a per-frame timer while arming the damage hit
 * volume once the timer passes a threshold. The object frees itself when
 * Tricky is gone or its free flag (state.freeRequested) is set.
 */
#include "main/game_object.h"
#include "main/dll/dll_00EF_pushable.h"
#include "main/objhits.h"

typedef struct FlameblastState
{
    f32 timer;          /* 0x00: per-frame flight timer */
    f32 launchPosX;     /* 0x04: launch origin used by the localPos integration */
    f32 launchPosY;     /* 0x08 */
    f32 launchPosZ;     /* 0x0C */
    u8 freeRequested;   /* 0x10: set externally to free the object next tick */
    u8 hitVolumeDelay;  /* 0x11: frames to delay before clearing hit volumes */
    u8 pad12[0x14 - 0x12];
} FlameblastState;

STATIC_ASSERT(offsetof(FlameblastState, freeRequested) == 0x10);
STATIC_ASSERT(offsetof(FlameblastState, hitVolumeDelay) == 0x11);
STATIC_ASSERT(sizeof(FlameblastState) == 0x14);

extern undefined4 FUN_80017748();
extern int FUN_80017a90();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_80053c98();
extern int FUN_801365ac();
extern undefined4 FUN_801365b8();

extern void Obj_FreeObject(int* obj);
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
int fn_8017805C(int* obj, f32* state);
extern void vecRotateZXY(void* in, void* out);
extern s16* getTrickyObject(void);
extern int fn_80138F90(void);
extern f32* trickyGetQueuedPathParticlePos(s16* tricky);
extern f32 timeDelta;

extern f32 lbl_803E42B0;
extern f32 lbl_803E42B4;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42BC;
extern f32 lbl_803E3618;
extern f32 lbl_803E361C;
extern f32 lbl_803E3620;
extern f32 lbl_803E3624;
extern f32 lbl_803E3628;
extern f32 lbl_803E362C;
extern f32 lbl_803E3630;
extern f32 lbl_803E3634;
extern f32 lbl_803E3638;

static inline int* Transporter_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

undefined4
FUN_80176920(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;

    if (((*(char*)(*(int*)(param_9 + 0x4c) + 0x1d) != '\x02') &&
            (animUpdate->triggerCommand == 1)) &&
        (iVar1 = (int)*(char*)(*(int*)(param_9 + 0x4c) + 0x1a), -1 < iVar1))
    {
        FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar1, '\x01',
                     (int)animUpdate, param_12, param_13, param_14, param_15, param_16);
        animUpdate->triggerCommand = 0;
    }
    return 0;
}

void FUN_801778d0(int param_1)
{
    ((FlameblastState*)((GameObject*)param_1)->extra)->freeRequested = 1;
    return;
}

undefined4
FUN_801778e0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             int param_10)
{
    f32 reach;
    s16* tricky;
    undefined4 uVar3;
    int dirAdjust;
    f32* origin;
    u16 dirX;
    s16 dirY;
    s16 dirZ;
    f32 posW;
    f32 zero;
    f32 posY;
    f32 posZ;

    tricky = (s16*)FUN_80017a90();
    zero = lbl_803E42B0;
    if ((*(char*)(param_10 + 0x10) == '\0') && (tricky != (s16*)0x0))
    {
        *(f32*)(param_9 + 0x24) = lbl_803E42B0;
        *(f32*)(param_9 + 0x28) = zero;
        *(f32*)(param_9 + 0x2c) = lbl_803E42B4;
        posY = zero;
        posZ = zero;
        posW = lbl_803E42B8;
        dirZ = tricky[2];
        dirY = tricky[1];
        dirAdjust = FUN_801365ac((int)tricky);
        dirX = *tricky + (s16)dirAdjust;
        FUN_80017748(&dirX, (f32*)(param_9 + 0x24));
        if ((tricky[0x58] & 0x800U) == 0)
        {
            origin = (f32*)(tricky + 6);
        }
        else
        {
            origin = (f32*)FUN_801365b8((int)tricky);
        }
        reach = lbl_803E42BC;
        *(f32*)(param_10 + 4) = -(lbl_803E42BC * *(f32*)(param_9 + 0x24) - *origin);
        *(f32*)(param_10 + 8) = -(reach * *(f32*)(param_9 + 0x28) - origin[1]);
        *(f32*)(param_10 + 0xc) = -(reach * *(f32*)(param_9 + 0x2c) - origin[2]);
        if (*(char*)(param_10 + 0x11) == '\0')
        {
            ObjHits_ClearHitVolumes(param_9);
        }
        else
        {
            *(char*)(param_10 + 0x11) = *(char*)(param_10 + 0x11) + -1;
        }
        uVar3 = 1;
    }
    else
    {
        FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
        uVar3 = 0;
    }
    return uVar3;
}

int flameblast_getExtraSize(void) { return sizeof(FlameblastState); }

#pragma scheduling off
void flameblast_render(int* obj)
{
    f32 color[3];
    f32 scale = lbl_803E362C * ((FlameblastState*)((GameObject*)obj)->extra)->timer + lbl_803E3628;
    color[0] = lbl_803E3618;
    color[1] = lbl_803E3620;
    color[2] = lbl_803E3618;
    fn_80098B18((int)obj, scale, 2, 0, 0, (int)color);
}

void objSetAnimSpeedTo1(int* obj)
{
    ((FlameblastState*)((GameObject*)obj)->extra)->freeRequested = 1;
}

#pragma peephole off
void flameblast_update(int* obj)
{
    FlameblastState* state = ((GameObject*)obj)->extra;
    state->timer = state->timer + timeDelta;
    if (state->timer > lbl_803E3630)
    {
        state->timer = state->timer - lbl_803E3630;
        if (fn_8017805C(obj, (f32*)state) == 0)
        {
            return;
        }
    }
    else
    {
        if (state->timer > lbl_803E3634)
        {
            if (state->hitVolumeDelay == 0)
            {
                ObjHits_SetHitVolumeSlot((u32)obj, 0x1a, 1, 0);
            }
        }
    }
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * state->timer + state->launchPosX;
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * state->timer + state->launchPosY;
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * state->timer + state->launchPosZ;
}

void flameblast_init(int* obj, u8* def)
{
    FlameblastState* state = ((GameObject*)obj)->extra;
    fn_8017805C(obj, (f32*)state);
    state->timer = lbl_803E3638 * (f32)(s32) * (s16*)(def + 0x1a);
    state->hitVolumeDelay = 2;
}

#pragma opt_common_subs off
int fn_8017805C(int* obj, f32* state)
{
    s16* tricky;
    f32* origin;
    f32 reach;
    struct
    {
        s16 dir[3];
        s16 pad;
        f32 pos[4];
    } vec;

    tricky = getTrickyObject();
    if (((FlameblastState*)state)->freeRequested != 0 || tricky == NULL)
    {
        Obj_FreeObject(obj);
        return 0;
    }
    {
        f32 zero = lbl_803E3618;
        ((GameObject*)obj)->anim.velocityX = zero;
        ((GameObject*)obj)->anim.velocityY = zero;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E361C;
        vec.pos[1] = zero;
        vec.pos[2] = zero;
        vec.pos[3] = zero;
        vec.pos[0] = lbl_803E3620;
    }
    vec.dir[2] = tricky[2];
    vec.dir[1] = tricky[1];
    vec.dir[0] = tricky[0] + fn_80138F90();
    vecRotateZXY(&vec, &((GameObject*)obj)->anim.velocityX);
    if ((((GameObject*)tricky)->objectFlags & 0x800) != 0)
    {
        origin = trickyGetQueuedPathParticlePos(tricky);
    }
    else
    {
        origin = &((GameObject*)tricky)->anim.localPosX;
    }
    reach = lbl_803E3624;
    state[1] = -(reach * ((GameObject*)obj)->anim.velocityX - origin[0]);
    state[2] = -(reach * ((GameObject*)obj)->anim.velocityY - origin[1]);
    state[3] = -(reach * ((GameObject*)obj)->anim.velocityZ - origin[2]);
    if (((FlameblastState*)state)->hitVolumeDelay != 0)
    {
        ((FlameblastState*)state)->hitVolumeDelay -= 1;
    }
    else
    {
        ObjHits_ClearHitVolumes((int)obj);
    }
    return 1;
}
#pragma opt_common_subs reset
