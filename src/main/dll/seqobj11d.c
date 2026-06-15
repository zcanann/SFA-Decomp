#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/dll/baddie_state.h"
#include "main/object_transform.h"
#include "main/objseq.h"
#include "main/dll/player_target.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_8001766c();
extern int FUN_80017730();
extern undefined4 FUN_800305c4();
extern undefined4 FUN_800305f8();
extern int FUN_8014c78c();
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern char FUN_8014ffa8();
extern undefined4 FUN_801504f8();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();

extern undefined4 DAT_8031e980;
extern undefined4 DAT_8031feb8;
extern undefined4 DAT_803ad088;
extern undefined4 DAT_803ad08c;
extern undefined4 DAT_803dc8f0;
extern f64 DOUBLE_803e3408;
extern f32 lbl_803DC074;
extern f32 lbl_803E33D8;
extern f32 lbl_803E33E4;
extern f32 lbl_803E3438;
extern f32 lbl_803E3440;
extern void* PTR_DAT_8031fdbc;
extern void* PTR_DAT_8031fdc8;
extern void* PTR_DAT_8031fdd4;
extern void* PTR_DAT_8031fdd8;

#pragma scheduling on
#pragma peephole on
extern void fn_8014D08C(int obj, u8* state, int a, int b, int c, f32 f);
extern char lbl_8031F16C[];
extern char lbl_8031DD30[];
extern f32 lbl_803E27A4;
extern f32 lbl_803E27A8;
extern int fn_8014C11C(int obj, int a, int b, u8* tbl, f32 f);
extern int getAngle(f32 dx, f32 dz);
extern u8 lbl_803AC428[];
extern u8 lbl_803DBC88[8];
extern f32 lbl_803E27AC;
extern void fn_8001FEA8(void);
extern u8* Obj_GetPlayerObject(void);
extern void fn_8015039C(int obj, u8* state);
extern u8 fn_8014FFB4(int obj, u8* state, int a);
extern void fn_8014CF7C(int obj, u8* state, f32 x, f32 z, int a, int b);
extern f32 lbl_803E2740;
extern f32 timeDelta;
extern void baddieAfterUpdateBonesCb();
extern f32 lbl_803DBC98;
extern f32 lbl_803E2748;
extern f32 lbl_803E2754;
extern f32 lbl_803E27B0;
extern f32 lbl_803E27B4;
extern f32 lbl_803E27B8;
extern f32 lbl_803E27BC;
extern f32 lbl_803E27C0;
extern f32 lbl_803E27C4;
extern f32 lbl_803E27C8;
extern f32 lbl_803E27CC;
extern f32 lbl_803E27D0;
extern int playerGetMoney(u8 * player);
extern void playerAddMoney(u8* player, int amount);
extern void hudFn_8011f38c(int a);
extern u16 lbl_803DBCA0[4];
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E27D8;
extern f32 lbl_803E27DC;
extern f32 lbl_803E27E0;
extern f32 lbl_803E27E4;
extern f32 lbl_803E27E8;

void FUN_801511e8(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    float fVar1;
    int iVar2;
    short* psVar3;
    char cVar4;
    int iVar5;
    uint uVar6;
    undefined4 in_r6;
    undefined4 in_r7;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined* puVar7;
    undefined* puVar8;
    undefined* puVar9;
    double dVar10;
    double dVar11;
    undefined8 uVar12;

    uVar12 = FUN_8028683c();
    psVar3 = (short*)((ulonglong)uVar12 >> 0x20);
    iVar5 = (int)uVar12;
    uVar6 = (uint) * (byte*)(iVar5 + 0x33b);
    puVar9 = (&PTR_DAT_8031fdbc)[uVar6 * 10];
    puVar8 = (&PTR_DAT_8031fdd4)[uVar6 * 10];
    puVar7 = (&PTR_DAT_8031fdd8)[uVar6 * 10];
    if ((uVar6 == 5) && ((*(uint*)(iVar5 + 0x2dc) & 0x800000) != 0))
    {
        GameBit_Set(0x1c8, 1);
    }
    if ((*(int*)(iVar5 + 0x29c) != 0) && (*(short*)(*(int*)(iVar5 + 0x29c) + 0x44) == 1))
    {
        FUN_8001766c();
    }
    FUN_801504f8((uint)psVar3, iVar5);
    fVar1 = lbl_803E33D8;
    dVar11 = (double)*(float*)(iVar5 + 0x328);
    dVar10 = (double)lbl_803E33D8;
    if ((dVar11 != dVar10) && (*(short*)(iVar5 + 0x338) != 0))
    {
        *(float*)(iVar5 + 0x328) = (float)(dVar11 - (double)lbl_803DC074);
        if ((double)*(float*)(iVar5 + 0x328) <= dVar10)
        {
            *(float*)(iVar5 + 0x328) = fVar1;
            *(uint*)(iVar5 + 0x2dc) = *(uint*)(iVar5 + 0x2dc) | 0x40000000;
            *(ushort*)(iVar5 + 0x338) =
                (ushort)(byte)
            puVar7[(uint) * (ushort*)(iVar5 + 0x338) * 0x10 + 10];
        }
    }
    cVar4 = FUN_8014ffa8(dVar10, dVar11, param_3, param_4, param_5, param_6, param_7, param_8, psVar3, iVar5, 0,
                         in_r6, in_r7, in_r8, in_r9, in_r10);
    if (cVar4 == '\0')
    {
        if (((*(uint*)(iVar5 + 0x2dc) & 0x20000000) != 0) &&
            ((*(uint*)(iVar5 + 0x2e0) & 0x20000000) == 0))
        {
            FUN_80006824((uint)psVar3, SFXdn_boar5_c);
            *(uint*)(iVar5 + 0x2dc) = *(uint*)(iVar5 + 0x2dc) | 0x40000000;
        }
        if ((*(uint*)(iVar5 + 0x2dc) & 0x40000000) != 0)
        {
            if (*(ushort*)(iVar5 + 0x338) == 0)
            {
                *(u8*)(iVar5 + 0x2f2) = 0;
                *(u8*)(iVar5 + 0x2f3) = 0;
                *(u8*)(iVar5 + 0x2f4) = 0;
                iVar2 = (uint) * (ushort*)(iVar5 + 0x2a0) * 0xc;
                if ((byte)puVar8[iVar2 + 8] == 0)
                {
                    *(u8*)(iVar5 + 0x323) = 3;
                    FUN_800305f8((double)lbl_803E33D8, dVar11, param_3, param_4, param_5, param_6, param_7, param_8
                                 , psVar3, (uint)(byte)puVar9[0x2c], 0, in_r6, in_r7, in_r8, in_r9, in_r10);
                }
                else
                {
                    FUN_8014d4c8((double)*(float*)(puVar8 + iVar2), dVar11, param_3, param_4, param_5, param_6,
                                 param_7, param_8, (int)psVar3, iVar5, (uint)(byte)puVar8[iVar2 + 8], 0, 0xb, in_r8,
                                 in_r9, in_r10);
                    FUN_800305c4((double)*(float*)(&DAT_8031e980 +
                                     (uint)(byte)puVar8[(uint) * (ushort*)(iVar5 + 0x2a0) * 0xc +
                                     8] * 4), (int)psVar3
                    )
                    ;
                }
            }
            else
            {
                *(char*)(iVar5 + 0x2f2) =
                    (char)*(undefined4*)(puVar7 + (uint) * (ushort*)(iVar5 + 0x338) * 0x10 + 0xc);
                iVar2 = (uint) * (ushort*)(iVar5 + 0x338) * 0x10;
                FUN_8014d4c8((double)*(float*)(puVar7 + iVar2), dVar11, param_3, param_4, param_5, param_6,
                             param_7, param_8, (int)psVar3, iVar5, (uint)(byte)puVar7[iVar2 + 8], 0,
                             *(uint*)(puVar7 + iVar2 + 4) & 0xff, in_r8, in_r9, in_r10);
                FUN_800305c4((double)*(float*)(&DAT_8031e980 +
                                 (uint)(byte)puVar7[(uint) * (ushort*)(iVar5 + 0x338) * 0x10 +
                                 8] * 4), (int)psVar3
                )
                ;
                *(ushort*)(iVar5 + 0x338) =
                    (ushort)(byte)
                puVar7[(uint) * (ushort*)(iVar5 + 0x338) * 0x10 + 9];
            }
        }
        if (psVar3[0x50] == (ushort)(byte)puVar9[0x2c]
        )
        {
            *(float*)(iVar5 + 0x308) =
                *(float*)(iVar5 + 0x2fc) *
                (((float)((double)CONCAT44(0x43300000, (uint) * (ushort*)(iVar5 + 0x2a4)) - DOUBLE_803e3408
                ) / *(float*)(iVar5 + 0x2a8)) / lbl_803E33E4) *
                *(float*)(&DAT_8031feb8 + (uint) * (byte*)(iVar5 + 0x33b) * 4);
            if (*(float*)(iVar5 + 0x308) < lbl_803E3438)
            {
                *(float*)(iVar5 + 0x308) = lbl_803E3438;
            }
        }
        if ((*(byte*)(iVar5 + 0x323) & 8) == 0)
        {
            FUN_8014d3d0(psVar3, iVar5, 0xf, 0);
        }
    }
    FUN_80286888();
    return;
}

void FUN_80151844(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  short* param_9, int param_10)
{
    short sVar1;
    int iVar2;
    uint uVar3;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined* puVar4;
    double dVar5;

    puVar4 = (&PTR_DAT_8031fdc8)[(uint) * (byte*)(param_10 + 0x33b) * 10];
    iVar2 = FUN_8014c78c(param_9, 1, 0x10, &DAT_803ad088);
    if (0 < iVar2)
    {
        if (((DAT_803ad08c < 0x29) && (*(short*)(param_10 + 0x2a0) != 3)) &&
            (*(short*)(param_10 + 0x2a0) != 4))
        {
            iVar2 = FUN_80017730();
            sVar1 = (short)iVar2 - *param_9;
            uVar3 = (uint)sVar1;
            if (0x8000 < (int)uVar3)
            {
                uVar3 = (uint)(short)(sVar1 + 1);
            }
            if ((short)uVar3 < -0x8000)
            {
                uVar3 = (uint)(short)((short)uVar3 + -1);
            }
            *(u8*)(param_10 + 0x33a) =
                puVar4[8] + (&DAT_803dc8f0)[(short)((uVar3 & 0xffff) >> 0xd)];
        }
        else if (DAT_803ad08c < 0x47)
        {
            while ((puVar4[(uint) * (byte*)(param_10 + 0x33a) * 0x10 + 10] & 1) != 0)
            {
                *(char*)(param_10 + 0x33a) = *(char*)(param_10 + 0x33a) + '\x01';
                if ((byte)puVar4[8] < *(byte*)(param_10 + 0x33a))
                {
                    *(u8*)(param_10 + 0x33a) = 1;
                }
            }
        }
    }
    dVar5 = (double)(float)((double)CONCAT44(0x43300000, (uint) * (ushort*)(param_10 + 0x2a4)) -
        DOUBLE_803e3408);
    if (dVar5 < (double)(lbl_803E3440 * *(float*)(param_10 + 0x2ac)))
    {
        *(char*)(param_10 + 0x33a) = puVar4[8] + '\x01';
    }
    while (true)
    {
        if ((*(uint*)(puVar4 + (uint) * (byte*)(param_10 + 0x33a) * 0x10 + 4) == 0) ||
            ((*(uint*)(param_10 + 0x2dc) &
                *(uint*)(puVar4 + (uint) * (byte*)(param_10 + 0x33a) * 0x10 + 4)) != 0))
            break;
        *(char*)(param_10 + 0x33a) = *(char*)(param_10 + 0x33a) + '\x01';
        if ((byte)puVar4[8] < *(byte*)(param_10 + 0x33a))
        {
            *(u8*)(param_10 + 0x33a) = 1;
        }
    }
    *(u8*)(param_10 + 0x2f2) = puVar4[(uint) * (byte*)(param_10 + 0x33a) * 0x10 + 10];
    *(u8*)(param_10 + 0x2f3) = puVar4[(uint) * (byte*)(param_10 + 0x33a) * 0x10 + 0xb];
    *(u8*)(param_10 + 0x2f4) = puVar4[(uint) * (byte*)(param_10 + 0x33a) * 0x10 + 0xc];
    iVar2 = (uint) * (byte*)(param_10 + 0x33a) * 0x10;
    FUN_8014d4c8((double)*(float*)(puVar4 + iVar2), dVar5, param_3, param_4, param_5, param_6, param_7,
                 param_8, (int)param_9, param_10, (uint)(byte)puVar4[iVar2 + 8], 0, 3, in_r8, in_r9, in_r10);
    FUN_800305c4((double)*(float*)(&DAT_8031e980 +
                     (uint)(byte)puVar4[(uint) * (byte*)(param_10 + 0x33a) * 0x10 + 8] *
                 4), (int)param_9
    )
    ;
    *(char*)(param_10 + 0x33a) = *(char*)(param_10 + 0x33a) + '\x01';
    if ((byte)puVar4[8] < *(byte*)(param_10 + 0x33a))
    {
        *(u8*)(param_10 + 0x33a) = 1;
    }
    return;
}

#pragma scheduling off
#pragma peephole off
void fn_80152004(int obj, int* state)
{
    Sfx_PlayFromObject((u32)obj, SFXen_cavedirt22);
    ((GroundBaddieState*)state)->baddie.reactionFlags |= 0x10;
}

typedef struct
{
    f32 speed;
    u32 mask;
    u8 anim;
    u8 pad9;
    u8 r;
    u8 g;
    u8 b;
    u8 pad13[3];
} SeqEntry;

#pragma dont_inline on
void fn_801511E8(int obj, u8* state)
{
    u8* entry;
    u32 idx;

    entry = *(u8**)(lbl_8031F16C + state[0x33b] * 40 + 12);
    if ((f32) * (u16*)(state + 0x2a4) > lbl_803E27A4 * ((GroundBaddieState*)state)->baddie.speedScale)
    {
        if ((f32) * (u16*)(state + 0x2a4) > lbl_803E27A8 * ((GroundBaddieState*)state)->baddie.speedScale)
        {
            state[0x33a] = (u8)(entry[8] + 2);
        }
        else
        {
            state[0x33a] = (u8)(entry[8] + 3);
        }
    }
    while (*(u32*)(entry + (idx = state[0x33a]) * 16 + 4) != 0
        && (((GroundBaddieState*)state)->baddie.controlFlags & *(u32*)(entry + idx * 16 + 4)) == 0)
    {
        (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
        if (state[0x33a] > entry[8])
        {
            state[0x33a] = 1;
        }
    }
    *(u8*)(state + 0x2f2) = (entry + state[0x33a] * 16)[10];
    *(u8*)(state + 0x2f3) = (entry + state[0x33a] * 16)[11];
    *(u8*)(state + 0x2f4) = (entry + state[0x33a] * 16)[12];
    fn_8014D08C(obj, state, ((SeqEntry*)(entry + state[0x33a] * 16))->anim, 0, 3, *(f32*)(entry + state[0x33a] * 16));
    ObjAnim_SetMoveProgress(
        *(f32*)(lbl_8031DD30 + ((SeqEntry*)(entry + state[0x33a] * 16))->anim * 4),
        (ObjAnimComponent*)obj);
    (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
    if (state[0x33a] > entry[8])
    {
        state[0x33a] = 1;
    }
}
#pragma dont_inline reset

void fn_801513AC(int obj, u8* state)
{
    u8* entry;
    u32 idx;
    s16 d;

    entry = *(u8**)(lbl_8031F16C + state[0x33b] * 40 + 12);
    if (fn_8014C11C(obj, 1, 16, lbl_803AC428, lbl_803E27AC) >= 1)
    {
        if (*(u16*)(lbl_803AC428 + 4) <= 40
            && *(u16*)(state + 0x2a0) != 3
            && *(u16*)(state + 0x2a0) != 4)
        {
            d = getAngle(((GameObject*)obj)->anim.localPosX - *(f32*)(*(int*)lbl_803AC428 + 0xc),
                         ((GameObject*)obj)->anim.localPosZ - *(f32*)(*(int*)lbl_803AC428 + 0x14))
                - (u16) * (s16*)obj;
            if (d > 0x8000)
            {
                d -= 0xFFFF;
            }
            if (d < -0x8000)
            {
                d += 0xFFFF;
            }
            state[0x33a] = (u8)(entry[8] + lbl_803DBC88[(s16)((u32)(u16)d >> 13)]);
        }
        else if (*(u16*)(lbl_803AC428 + 4) <= 70)
        {
            while ((*(u8*)(entry + state[0x33a] * 16 + 10) & 1) != 0)
            {
                (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
                if (state[0x33a] > entry[8])
                {
                    state[0x33a] = 1;
                }
            }
        }
    }
    if ((f32) * (u16*)(state + 0x2a4) < lbl_803E27A8 * ((GroundBaddieState*)state)->baddie.speedScale)
    {
        state[0x33a] = (u8)(entry[8] + 1);
    }
    while (*(u32*)(entry + (idx = state[0x33a]) * 16 + 4) != 0
        && (((GroundBaddieState*)state)->baddie.controlFlags & *(u32*)(entry + idx * 16 + 4)) == 0)
    {
        (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
        if (state[0x33a] > entry[8])
        {
            state[0x33a] = 1;
        }
    }
    *(u8*)(state + 0x2f2) = (entry + state[0x33a] * 16)[10];
    *(u8*)(state + 0x2f3) = (entry + state[0x33a] * 16)[11];
    *(u8*)(state + 0x2f4) = (entry + state[0x33a] * 16)[12];
    fn_8014D08C(obj, state, ((SeqEntry*)(entry + state[0x33a] * 16))->anim, 0, 3, *(f32*)(entry + state[0x33a] * 16));
    ObjAnim_SetMoveProgress(
        *(f32*)(lbl_8031DD30 + ((SeqEntry*)(entry + state[0x33a] * 16))->anim * 4),
        (ObjAnimComponent*)obj);
    (((GroundBaddieState*)state)->baddie.seqEntryIndex)++;
    if (state[0x33a] > entry[8])
    {
        state[0x33a] = 1;
    }
}

void fn_8015165C(int obj, u8* state)
{
    u8* player;
    ObjHitsPriorityState* hitState;
    u8* p20;
    u8* p28;
    u8 t;
    f32 tv;
    f32 fz;

    t = state[0x33b];
    p20 = *(u8**)(lbl_8031F16C + t * 40 + 20);
    p28 = *(u8**)(lbl_8031F16C + t * 40 + 28);
    if (t == 5 && (((GroundBaddieState*)state)->baddie.controlFlags & 0x800000) != 0)
    {
        GameBit_Set(456, 1);
    }
    if (((GroundBaddieState*)state)->baddie.trackedObj != NULL && *(s16*)(*(int*)&((GroundBaddieState*)state)->baddie.
        trackedObj + 0x44) == 1)
    {
        fn_8001FEA8();
    }
    fn_8015039C(obj, state);
    tv = *(f32*)(state + 0x328);
    fz = lbl_803E2740;
    if (tv != fz && *(u16*)(state + 0x338) != 0)
    {
        *(f32*)(state + 0x328) = tv - timeDelta;
        if (*(f32*)(state + 0x328) <= fz)
        {
            *(f32*)(state + 0x328) = fz;
            ((GroundBaddieState*)state)->baddie.controlFlags |= 0x40000000LL;
            *(u16*)(state + 0x338) = (p28 + *(u16*)(state + 0x338) * 16)[10];
        }
    }
    if ((u8)fn_8014FFB4(obj, state, 1) == 0)
    {
        if ((((GroundBaddieState*)state)->baddie.controlFlags & 0x40000000) != 0)
        {
            player = Obj_GetPlayerObject();
            fn_8014C11C(obj, 3, 16, lbl_803AC428, lbl_803E27AC);
            if (*(u16*)(state + 0x338) != 0)
            {
                *(u8*)(state + 0x2f2) = (u8) * (u32*)((p28 + *(u16*)(state + 0x338) * 16) + 12);
                fn_8014D08C(obj, state, (p28 + *(u16*)(state + 0x338) * 16)[8], 0,
                            (u8) * (u32*)&(p28 + *(u16*)(state + 0x338) * 16)[4],
                            *(f32*)(p28 + *(u16*)(state + 0x338) * 16));
                ObjAnim_SetMoveProgress(
                    *(f32*)(lbl_8031DD30 + (p28 + *(u16*)(state + 0x338) * 16)[8] * 4),
                    (ObjAnimComponent*)obj);
                *(u16*)(state + 0x338) = (p28 + *(u16*)(state + 0x338) * 16)[9];
            }
            else
            {
                if (player != NULL && ((((GroundBaddieState*)state)->baddie.controlFlags & 0x800080) != 0 ||
                    Player_GetTargetObject((int)player) == 0))
                {
                    fn_801511E8(obj, state);
                }
                else
                {
                    fn_801513AC(obj, state);
                }
            }
        }
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->hitVolumePriority = 0;
        hitState->hitVolumeId = 0;
        if (((GameObject*)obj)->anim.currentMove == p20[8])
        {
            hitState->hitVolumePriority = (s8) * (int*)(p20 + 4);
            hitState->hitVolumeId = (s8)p20[9];
        }
        if (((GameObject*)obj)->anim.currentMove == p20[0x14])
        {
            hitState->hitVolumePriority = (s8) * (int*)(p20 + 0x10);
            hitState->hitVolumeId = (s8)p20[0x15];
        }
        if (((GameObject*)obj)->anim.currentMove == p20[0x20])
        {
            hitState->hitVolumePriority = (s8) * (int*)(p20 + 0x1c);
            hitState->hitVolumeId = (s8)p20[0x21];
        }
        if ((state[0x323] & 8) == 0)
        {
            fn_8014CF7C(obj, state, *(f32*)(*(int*)&((GroundBaddieState*)state)->baddie.trackedObj + 0xc),
                        *(f32*)(*(int*)&((GroundBaddieState*)state)->baddie.trackedObj + 0x14), 10, 0);
        }
    }
}

void fn_80151954(int obj, u8* state)
{
    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    f32 fz;
    int z;

    ((GroundBaddieState*)state)->baddie.unk2E4 = 11;
    *(u32*)&((GroundBaddieState*)state)->baddie.unk2E4 |= 0x402B0LL;
    *(u32*)&((GroundBaddieState*)state)->baddie.unk2E4 |= 0x3040;
    *(u32*)&((GroundBaddieState*)state)->baddie.unk2E4 |= 0x40300000LL;
    *(u32*)&((GroundBaddieState*)state)->baddie.unk2E4 |= 0xC00;
    ((GroundBaddieState*)state)->baddie.unk308 = lbl_803E2754;
    ((GroundBaddieState*)state)->baddie.unk300 = lbl_803E27B0;
    ((GroundBaddieState*)state)->baddie.unk304 = lbl_803E27B4;
    state[0x320] = 35;
    fz = lbl_803E2748;
    *(f32*)&((GroundBaddieState*)state)->baddie.eventFlags = fz;
    state[0x321] = 34;
    ((GroundBaddieState*)state)->baddie.unk318 = lbl_803E27B8;
    state[0x322] = 6;
    ((GroundBaddieState*)state)->baddie.unk31C = fz;
    ((GroundBaddieState*)state)->baddie.pathStep *= lbl_803E27BC;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 314:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 51;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 40;
        state[0x33b] = 0;
        break;
    case 17:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 51;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 40;
        state[0x33b] = 1;
        break;
    case 1505:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 1529;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 50;
        state[0x33b] = 2;
        break;
    case 1463:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 1530;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C4;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 50;
        state[0x33b] = 3;
        break;
    case 1464:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 1534;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 60;
        state[0x33b] = 4;
        break;
    case 1465:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 51;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 1;
        state[0x33b] = 1;
        break;
    case 1958:
        if (*(s8*)(setup + 0x27) != 0)
        {
            *(s16*)(state + 0x2b6) = 1957;
        }
        ((GroundBaddieState*)state)->baddie.speedScale = lbl_803E27C0;
        *(s16*)&((GroundBaddieState*)state)->baddie.hitCounter = 160;
        state[0x33b] = 5;
        z = 0;
        state[0x320] = z;
        *(f32*)&((GroundBaddieState*)state)->baddie.eventFlags = fz;
        state[0x321] = 21;
        ((GroundBaddieState*)state)->baddie.unk318 = lbl_803E27B8;
        state[0x322] = z;
        ((GroundBaddieState*)state)->baddie.unk31C = fz;
        *(int*)(state + 0x36c) = (int)ObjModelChain_Alloc(&lbl_803DBC98, 1);
        ObjModelChain_SetOrigin((ObjModelChain*)*(int*)(state + 0x36c), lbl_803E27C8, lbl_803E27CC, lbl_803E27D0);
        *(int*)(obj + 0x108) = (int)baddieAfterUpdateBonesCb;
        ObjModelChain_SetEnabled((ObjModelChain*)*(int*)(state + 0x36c), 1);
        break;
    }
    if (*(s8*)(setup + 0x2e) != -1)
    {
        ((GroundBaddieState*)state)->baddie.controlFlags |= 1;
    }
}

void fn_80151C68(int obj, u8* state)
{
    u8* player;
    u8* setup;

    player = Obj_GetPlayerObject();
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    if ((*gGameUIInterface)->isEventReady(446) != 0)
    {
        if (player != NULL && playerGetMoney(player) >= 25)
        {
            playerAddMoney(player, -25);
            GameBit_Set(*(s16*)(setup + 0x1c), 1);
            *(u16*)(state + 0x338) = lbl_803DBCA0[2];
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            hudFn_8011f38c(2);
            (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
        }
        else
        {
            hudFn_8011f38c(2);
            *(u16*)(state + 0x338) = lbl_803DBCA0[1];
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
    }
    else
    {
        hudFn_8011f38c(2);
        *(u16*)(state + 0x338) = lbl_803DBCA0[0];
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
    }
}

void fn_80151DB8(int obj, u8* state)
{
    GameObject* player;
    ObjPlacement* setup;
    f32 dy;
    f32 px0;
    f32 pz0;
    f32 cosA;
    f32 sinA;
    f32 base;
    f32 f5;
    f32 f2v;
    f32 dx;
    f32 dz;

    player = (GameObject*)Obj_GetPlayerObject();
    setup = ((GameObject*)obj)->anim.placement;
    dy = player->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
    dy = (dy >= lbl_803E27D8) ? dy : -dy;
    if (dy > lbl_803E27DC)
    {
        return;
    }
    px0 = setup->posX - lbl_803E27DC * mathSinf(lbl_803E27E0 * (f32) * (s16*)obj / lbl_803E27E4);
    pz0 = setup->posZ - lbl_803E27DC * mathCosf(lbl_803E27E0 * (f32) * (s16*)obj / lbl_803E27E4);
    dx = player->anim.worldPosX - px0;
    dz = player->anim.worldPosZ - pz0;
    if (sqrtf(dx * dx + dz * dz) < *(f32*)(state + 0x2ac))
    {
        cosA = mathSinf(lbl_803E27E0 * (f32) * (s16*)obj / lbl_803E27E4);
        sinA = mathCosf(lbl_803E27E0 * (f32) * (s16*)obj / lbl_803E27E4);
        base = -(cosA * (px0 - cosA) + sinA * (pz0 - sinA));
        f5 = base + (cosA * player->anim.previousWorldPosX + sinA * player->anim.previousWorldPosZ);
        f2v = base + (cosA * player->anim.worldPosX + sinA * player->anim.worldPosZ);
        if (f2v > lbl_803E27D8)
        {
            if (!(f5 >= lbl_803E27E8))
            {
                return;
            }
            player->anim.worldPosX = player->anim.worldPosX - cosA * f5;
            player->anim.worldPosZ = player->anim.worldPosZ - sinA * f5;
            Obj_TransformWorldPointToLocal(player->anim.worldPosX, player->anim.worldPosY, player->anim.worldPosZ,
                                           &player->anim.localPosX, &player->anim.localPosY, &player->anim.localPosZ,
                                           (u32)player->anim.parent);
        }
    }
}
