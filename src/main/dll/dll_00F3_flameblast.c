#include "main/game_object.h"
#include "main/dll/dll_00EF_pushable.h"
#include "main/objhits.h"

typedef struct FlameblastState
{
    u8 pad0[0x10 - 0x0];
    u8 unk10;
    u8 unk11;
    u8 pad12[0x14 - 0x12];
} FlameblastState;

extern undefined4 FUN_80017748();
extern int FUN_80017a90();
extern undefined8 FUN_80017ac8();
extern void Obj_FreeObject(int* obj);
extern undefined4 FUN_80053c98();
extern int FUN_801365ac();
extern undefined4 FUN_801365b8();
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B4;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42BC;
extern void fn_80098B18(int obj, float f, int a, int b, int c, int d);
extern f32 lbl_803E3618;
extern f32 lbl_803E3620;
extern f32 lbl_803E3628;
extern f32 lbl_803E362C;
extern f32 timeDelta;
extern f32 lbl_803E3630;
extern f32 lbl_803E3634;
extern int fn_8017805C(int* obj, f32* state);
extern void vecRotateZXY(void* in, void* out);
extern f32 lbl_803E3638;
extern s16* getTrickyObject(void);
extern int fn_80138F90(void);
extern f32* trickyGetQueuedPathParticlePos(s16 * tricky);
extern f32 lbl_803E361C;
extern f32 lbl_803E3624;

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
    *(u8*)(*(int*)&((GameObject*)param_1)->extra + 0x10) = 1;
    return;
}

undefined4
FUN_801778e0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             int param_10)
{
    float fVar1;
    short* psVar2;
    undefined4 uVar3;
    int iVar4;
    float* pfVar5;
    ushort local_28;
    short local_26;
    short local_24;
    float local_20;
    float local_1c;
    float local_18;
    float local_14;

    psVar2 = (short*)FUN_80017a90();
    local_1c = lbl_803E42B0;
    if ((*(char*)(param_10 + 0x10) == '\0') && (psVar2 != (short*)0x0))
    {
        *(float*)(param_9 + 0x24) = lbl_803E42B0;
        *(float*)(param_9 + 0x28) = local_1c;
        *(float*)(param_9 + 0x2c) = lbl_803E42B4;
        local_18 = local_1c;
        local_14 = local_1c;
        local_20 = lbl_803E42B8;
        local_24 = psVar2[2];
        local_26 = psVar2[1];
        iVar4 = FUN_801365ac((int)psVar2);
        local_28 = *psVar2 + (short)iVar4;
        FUN_80017748(&local_28, (float*)(param_9 + 0x24));
        if ((psVar2[0x58] & 0x800U) == 0)
        {
            pfVar5 = (float*)(psVar2 + 6);
        }
        else
        {
            pfVar5 = (float*)FUN_801365b8((int)psVar2);
        }
        fVar1 = lbl_803E42BC;
        *(float*)(param_10 + 4) = -(lbl_803E42BC * *(float*)(param_9 + 0x24) - *pfVar5);
        *(float*)(param_10 + 8) = -(fVar1 * *(float*)(param_9 + 0x28) - pfVar5[1]);
        *(float*)(param_10 + 0xc) = -(fVar1 * *(float*)(param_9 + 0x2c) - pfVar5[2]);
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


int flameblast_getExtraSize(void) { return 0x14; }

#pragma scheduling off
void flameblast_render(int* obj)
{
    f32 vec[3];
    f32 f = lbl_803E362C * *(f32*)((GameObject*)obj)->extra + lbl_803E3628;
    vec[0] = lbl_803E3618;
    vec[1] = lbl_803E3620;
    vec[2] = lbl_803E3618;
    fn_80098B18((int)obj, f, 2, 0, 0, (int)vec);
}

void objSetAnimSpeedTo1(int* obj)
{
    u8 v = 0x1;
    *((u8*)((int**)obj)[0xb8 / 4] + 0x10) = v;
}

#pragma peephole off
void flameblast_update(int* obj)
{
    f32* state = ((GameObject*)obj)->extra;
    state[0] = state[0] + timeDelta;
    if (state[0] > lbl_803E3630)
    {
        state[0] = state[0] - lbl_803E3630;
        if (fn_8017805C(obj, state) == 0)
        {
            return;
        }
    }
    else
    {
        if (state[0] > lbl_803E3634)
        {
            if (((FlameblastState*)state)->unk11 == 0)
            {
                ObjHits_SetHitVolumeSlot((u32)obj, 0x1a, 1, 0);
            }
        }
    }
    ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * state[0] + state[1];
    ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * state[0] + state[2];
    ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * state[0] + state[3];
}

void flameblast_init(int* obj, u8* def)
{
    f32* state = ((GameObject*)obj)->extra;
    fn_8017805C(obj, state);
    state[0] = lbl_803E3638 * (f32)(s32) * (s16*)((char*)def + 0x1a);
    ((FlameblastState*)state)->unk11 = 2;
}

void WarpPoint_init(int* obj, u8* def);

#pragma opt_common_subs off
int fn_8017805C(int* obj, f32* state)
{
    s16* tricky;
    f32* pf;
    f32 k;
    struct
    {
        s16 dir[3];
        s16 pad;
        f32 pos[4];
    } vec;

    tricky = getTrickyObject();
    if (*(u8*)((char*)state + 0x10) != 0 || tricky == NULL)
    {
        Obj_FreeObject(obj);
        return 0;
    }
    {
        f32 f = lbl_803E3618;
        ((GameObject*)obj)->anim.velocityX = f;
        ((GameObject*)obj)->anim.velocityY = f;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E361C;
        vec.pos[1] = f;
        vec.pos[2] = f;
        vec.pos[3] = f;
        vec.pos[0] = lbl_803E3620;
    }
    vec.dir[2] = tricky[2];
    vec.dir[1] = tricky[1];
    vec.dir[0] = tricky[0] + fn_80138F90();
    vecRotateZXY(&vec, &((GameObject*)obj)->anim.velocityX);
    if ((((GameObject*)tricky)->objectFlags & 0x800) != 0)
    {
        pf = trickyGetQueuedPathParticlePos(tricky);
    }
    else
    {
        pf = &((GameObject*)tricky)->anim.localPosX;
    }
    k = lbl_803E3624;
    state[1] = -(k * ((GameObject*)obj)->anim.velocityX - pf[0]);
    state[2] = -(k * ((GameObject*)obj)->anim.velocityY - pf[1]);
    state[3] = -(k * ((GameObject*)obj)->anim.velocityZ - pf[2]);
    if (*(u8*)((char*)state + 0x11) != 0)
    {
        *(u8*)((char*)state + 0x11) -= 1;
    }
    else
    {
        ObjHits_ClearHitVolumes((int)obj);
    }
    return 1;
}
#pragma opt_common_subs reset

#pragma opt_common_subs off

#pragma opt_common_subs reset
