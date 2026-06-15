#include "main/dll_000A_expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/pushable.h"
#include "main/dll/dll_00EF_pushable.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct WarpPointObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    void* unk1C;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} WarpPointObjectDef;

typedef struct WarpPointState
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    u8 unkC;
    u8 unkD;
    u8 padE[0x10 - 0xE];
    u8 unk10;
    u8 unk11;
    u8 pad12[0x18 - 0x12];
} WarpPointState;

extern undefined4 FUN_80017748();
extern int FUN_80017a90();
extern undefined8 FUN_80017ac8();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 FUN_80053c98();
extern int FUN_801365ac();
extern undefined4 FUN_801365b8();
extern f32 lbl_803E42B0;
extern f32 lbl_803E42B4;
extern f32 lbl_803E42B8;
extern f32 lbl_803E42BC;
extern unsigned long GameBit_Set(int eventId, int value);
extern void warpToMap(int mapId, int flag);
extern void* Obj_GetPlayerObject(void);
extern u32 GameBit_Get(int eventId);
extern f32 sqrtf(f32 x);
extern u8 framesThisStep;
extern int getCurMapLayer(void);
extern f32 Vec_distance(f32 * a, f32 * b);
extern s16 lbl_803DCEB8;
extern u8 lbl_803DCDE0;
extern f32 lbl_803E35D8;
extern f32 lbl_803E35DC;

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

void invhit_hitDetect(void);

int WarpPoint_getExtraSize(void) { return 0x10; }
int WarpPoint_getObjectTypeId(void) { return 0x1; }
int invhit_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void WarpPoint_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    int* p = *(int**)&((GameObject*)obj)->anim.placementData;
    if (visible == 0) return;
    if (*(s8*)((char*)p + 0x1d) == 1) return;
}

void invhit_free(int obj);

int WarpPoint_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* p = *(int**)&((GameObject*)obj)->anim.placementData;
    if (*(s8*)((char*)p + 0x1d) != 2)
    {
        if (animUpdate->triggerCommand == 1)
        {
            int v = (s8) * (u8*)((char*)p + 0x1a);
            if (v > -1)
            {
                warpToMap(v, 1);
                animUpdate->triggerCommand = 0;
            }
        }
    }
    return 0;
}

void WarpPoint_init(int* obj, u8* def)
{
    s16* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)WarpPoint_SeqFn;
    *(s16*)obj = (s16)((u32)def[0x18] << 8);
    state[0] = 0x1e;
    ((WarpPointState*)state)->unk8 = (f32)((s32) * (s8*)((char*)def + 0x1e) << 2);
    state[1] = ((WarpPointObjectDef*)def)->unk20;
    state[2] = (s16)(s32) * (s8*)((char*)def + 0x1b);
    if (*(s8*)((char*)def + 0x1c) != 0)
    {
        ((WarpPointState*)state)->unkC = 0;
    }
    else
    {
        ((WarpPointState*)state)->unkC = 1;
    }
    if (*(s8*)((char*)def + 0x1d) == 2)
    {
        state[0] = 0;
    }
    if (((ObjPlacement*)def)->mapId == 0x4B675 || ((ObjPlacement*)def)->mapId == 0x46882)
    {
        *(u8*)((char*)def + 0x1f) = 1;
    }
    else
    {
        *(u8*)((char*)def + 0x1f) = 0;
    }
}

void iceblast_update(int* obj);

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off

#pragma opt_common_subs reset

void WarpPoint_update(int* obj)
{
    char* def;
    s16* state;
    char* player;
    f32 dist;

    def = *(char**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    player = (char*)Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    *state -= framesThisStep;
    if (*state < 0)
    {
        *state = 0;
    }
    if (*(u8*)(def + 0x1f) != 0 && ((WarpPointState*)state)->unkD == 0 && lbl_803DCEB8 > -1 &&
        lbl_803DCEB8 == *(s8*)(def + 0x19))
    {
        (*gMapEventInterface)->savePoint((int)(player + 0xc), *(s16*)player,
                                            0, getCurMapLayer());
        ((WarpPointState*)state)->unkD = 1;
    }
    switch (*(s8*)(def + 0x1d))
    {
    case 0:
        if (lbl_803DCEB8 > -1 || GameBit_Get(0xd53) != 0)
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((PushableState*)player)->scale - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((PushableState*)player)->timer_0x14 - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (((WarpPointState*)state)->unkC == 0 && *(s8*)(def + 0x1c) != 0 &&
                dist < ((WarpPointState*)state)->unk8 &&
                *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
            {
                if (((GameObject*)obj)->anim.seqId == 0x27e)
                {
                    GameBit_Set(0xd53, 1);
                    (*gMapEventInterface)->savePoint(
                        (int)(player + 0xc), *(s16*)player, 0, getCurMapLayer());
                }
                (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
                GameBit_Set(0xd53, 0);
                lbl_803DCDE0 = 2;
                ((WarpPointState*)state)->unkC = 1;
            }
        }
        if (*(s8*)(def + 0x1a) > -1)
        {
            f32 d2 = Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18));
            if (d2 < ((WarpPointState*)state)->unk8)
            {
                warpToMap(*(s8*)(def + 0x1a), 1);
            }
        }
        break;
    case 1:
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((PushableState*)player)->scale - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((PushableState*)player)->timer_0x14 - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (lbl_803DCEB8 > -1 && *(s8*)(def + 0x1c) != 0 && dist < lbl_803E35D8 &&
                *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
            {
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
                lbl_803DCDE0 = 2;
            }
            if (*state == 0 && dist < (f32) * (s8*)(def + 0x1e) && *(s8*)(def + 0x1a) > -1 &&
                *(s8*)(def + 0x1a) > -1)
            {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
            }
            break;
        }
    case 2:
        if (lbl_803E35DC != (dist = ((WarpPointState*)state)->unk8))
        {
            f32 dx = ((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            f32 dy = ((PushableState*)player)->probeLocal[0].y - ((GameObject*)obj)->anim.worldPosY;
            f32 dz = ((PushableState*)player)->probeLocal[0].z - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (GameBit_Get(state[1]) != 0 && ((WarpPointState*)state)->unkC == 0 &&
            *(s8*)(def + 0x1c) != 0 && dist <= ((WarpPointState*)state)->unk8 &&
            *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
        {
            (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
            ((WarpPointState*)state)->unkC = 1;
        }
        else
        {
            if (((WarpPointState*)state)->unkC == 1 && GameBit_Get(state[1]) != 0 && *state == 0 &&
                dist <= ((WarpPointState*)state)->unk8 && *(s8*)(def + 0x1a) > -1)
            {
                GameBit_Set(state[1], 0);
                warpToMap(*(s8*)(def + 0x1a), 0);
            }
        }
        break;
    case 3:
        {
            f32 dx = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 dy = ((PushableState*)player)->scale - ((GameObject*)obj)->anim.localPosY;
            f32 dz = ((PushableState*)player)->timer_0x14 - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (GameBit_Get(state[1]) != 0 && ((WarpPointState*)state)->unkC == 0 &&
                *(s8*)(def + 0x1c) != 0 && dist < ((WarpPointState*)state)->unk8 &&
                *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
            {
                GameBit_Set(state[1], 0);
                (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
                ((WarpPointState*)state)->unkC = 1;
            }
            break;
        }
    case 4:
        if (lbl_803E35DC != (dist = ((WarpPointState*)state)->unk8))
        {
            f32 dx = ((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            f32 dy = ((PushableState*)player)->probeLocal[0].y - ((GameObject*)obj)->anim.worldPosY;
            f32 dz = ((PushableState*)player)->probeLocal[0].z - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
        }
        if (lbl_803DCEB8 > -1 && ((WarpPointState*)state)->unkC == 0 && *(s8*)(def + 0x1c) != 0 &&
            dist < ((WarpPointState*)state)->unk8 &&
            *(u32*)&((GameObject*)player)->anim.parent == *(u32*)&((GameObject*)obj)->anim.parent)
        {
            (*gObjectTriggerInterface)->runSequence(state[2], obj, -1);
            lbl_803DCDE0 = 2;
            ((WarpPointState*)state)->unkC = 1;
        }
        if (GameBit_Get(state[1]) != 0 && *state == 0 && dist <= ((WarpPointState*)state)->unk8 &&
            *(s8*)(def + 0x1a) > -1)
        {
            GameBit_Set(state[1], 0);
            warpToMap(*(s8*)(def + 0x1a), 1);
        }
        break;
    }
}
