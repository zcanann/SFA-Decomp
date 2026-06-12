#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dim_partfx.h"


extern u32 randomGetRange(int min, int max);

extern undefined4 DAT_8039d0b8;
extern undefined4 DAT_8039d0bc;
extern undefined4 DAT_803de090;
extern f32 lbl_803DC4B0;
extern f32 lbl_803DC4B4;
extern f32 lbl_803E0E38;
extern f32 lbl_803E0E3C;
extern f32 lbl_803E0E40;
extern f32 lbl_803E0E44;
extern f32 lbl_803E0E48;
extern f32 lbl_803E0E4C;
extern f32 lbl_803E0E50;
extern f32 lbl_803E0E54;
extern f32 lbl_803E0E58;
extern f32 lbl_803E0E5C;
extern f32 lbl_803E0E60;
extern f32 lbl_803E0E64;
extern f32 lbl_803E0E68;
extern f32 lbl_803E0E6C;
extern f32 lbl_803E0E70;
extern f32 lbl_803E0E74;
extern f32 lbl_803E0E78;
extern f32 lbl_803E0E7C;
extern f32 lbl_803E0E80;
extern f32 lbl_803E0E84;
extern f32 lbl_803E0E88;
extern f32 lbl_803E0E8C;

/*
 * --INFO--
 *
 * Function: Effect16_func04
 * EN v1.0 Address: 0x800C8008
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800C8294
 * EN v1.1 Size: 4100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* Effect16_func04 is defined further below (full recovered body). */


/*
 * --INFO--
 *
 * Function: FUN_800c8110
 * EN v1.0 Address: 0x800C8110
 * EN v1.0 Size: 904b
 * EN v1.1 Address: 0x800CABBC
 * EN v1.1 Size: 3116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800c8110(int param_1, undefined4 param_2, undefined2* param_3, uint param_4, u8 param_5,
             int param_6)
{
    undefined4 uVar1;
    uint uVar2;
    int local_98[3];
    undefined2 local_8c;
    undefined2 local_8a;
    undefined2 local_88;
    undefined4 local_84;
    float local_80;
    float local_7c;
    float local_78;
    float local_74;
    float local_70;
    float local_6c;
    float local_68;
    float local_64;
    float local_60;
    float local_5c;
    undefined2 local_58;
    undefined2 local_56;
    uint local_54;
    undefined4 local_50;
    undefined4 local_4c;
    uint local_48;
    uint local_44;
    undefined2 local_40;
    undefined2 local_3e;
    undefined2 local_3c;
    u8 local_3a;
    u8 local_38;
    u8 local_37;
    u8 local_36;
    undefined4 local_30;
    uint uStack_2c;
    undefined4 local_28;
    uint uStack_24;
    undefined4 local_20;
    uint uStack_1c;
    undefined4 local_18;
    uint uStack_14;

    lbl_803DC4B0 = lbl_803DC4B0 + lbl_803E0E38;
    if (lbl_803E0E40 < lbl_803DC4B0)
    {
        lbl_803DC4B0 = lbl_803E0E3C;
    }
    lbl_803DC4B4 = lbl_803DC4B4 + lbl_803E0E44;
    if (lbl_803E0E40 < lbl_803DC4B4)
    {
        lbl_803DC4B4 = lbl_803E0E48;
    }
    if (param_1 == 0)
    {
        uVar1 = 0xffffffff;
    }
    else
    {
        if ((param_4 & 0x200000) != 0)
        {
            if (param_3 == (undefined2*)0x0)
            {
                return 0xffffffff;
            }
            local_80 = ((PartFxSpawnParams*)param_3)->unkC;
            local_7c = ((PartFxSpawnParams*)param_3)->unk10;
            local_78 = ((PartFxSpawnParams*)param_3)->unk14;
            local_84 = *(undefined4*)&((PartFxSpawnParams*)param_3)->unk8;
            local_88 = ((PartFxSpawnParams*)param_3)->unk4;
            local_8a = ((PartFxSpawnParams*)param_3)->unk2;
            local_8c = *param_3;
            local_36 = param_5;
        }
        local_54 = 0;
        local_50 = 0;
        local_3a = (undefined)param_2;
        local_68 = lbl_803E0E4C;
        local_64 = lbl_803E0E4C;
        local_60 = lbl_803E0E4C;
        local_74 = lbl_803E0E4C;
        local_70 = lbl_803E0E4C;
        local_6c = lbl_803E0E4C;
        local_5c = lbl_803E0E4C;
        local_98[2] = 0;
        local_98[1] = 0xffffffff;
        local_38 = 0xff;
        local_37 = 0;
        local_56 = 0;
        local_40 = 0xffff;
        local_3e = 0xffff;
        local_3c = 0xffff;
        local_4c = 0xffff;
        local_48 = 0xffff;
        local_44 = 0xffff;
        local_58 = 0;
        local_98[0] = param_1;
        switch (param_2)
        {
        case 0x73a:
            uStack_2c = randomGetRange(8, 10);
            local_70 = lbl_803E0E50 * (f32)(s32)
            uStack_2c;
            uVar2 = randomGetRange(0, 0x28);
            if (uVar2 == 0)
            {
                uStack_2c = randomGetRange(0x15, 0x29);
                local_5c = lbl_803E0E38 *
                    (f32)(s32)
                uStack_2c;
                local_98[2] = 0x1cc;
            }
            else
            {
                uStack_2c = randomGetRange(8, 0x14);
                local_5c = lbl_803E0E38 *
                    (f32)(s32)
                uStack_2c;
                local_98[2] = randomGetRange(0x5a, 0x78);
            }
            local_54 = 0x80180200;
            local_50 = 0x1000020;
            local_56 = 0xc0b;
            local_38 = 0x7f;
            local_3c = 0x3fff;
            local_3e = 0x3fff;
            local_40 = 0x3fff;
            local_44 = 0xffff;
            local_48 = 0xffff;
            local_4c = 0xffff;
            local_64 = lbl_803E0E54;
            break;
        case 0x73b:
            uStack_2c = randomGetRange(0xffffffec, 0x14);
            local_74 = lbl_803E0E50 * (f32)(s32)
            uStack_2c;
            uStack_24 = randomGetRange(8, 0x14);
            local_70 = lbl_803E0E50 * (f32)(s32)
            uStack_24;
            uStack_1c = randomGetRange(0xffffffec, 0x14);
            local_6c = lbl_803E0E50 * (f32)(s32)
            uStack_1c;
            local_5c = lbl_803E0E58;
            local_98[2] = 0x32;
            local_54 = 0x3000200;
            local_50 = 0x200020;
            local_56 = 0x33;
            local_38 = 0xff;
            local_40 = 0xffff;
            local_3e = 0xffff;
            local_3c = 0xffff;
            local_4c = 0xffff;
            local_48 = randomGetRange(0, 0x8000);
            local_64 = lbl_803E0E5C;
            local_44 = local_48;
            break;
        default:
            return 0xffffffff;
        case 0x73d:
            uStack_1c = randomGetRange(0xfffffff6, 10);
            local_68 = lbl_803E0E3C * (f32)(s32)
            uStack_1c;
            uStack_24 = randomGetRange(0xfffffff6, 100);
            local_64 = lbl_803E0E50 * (f32)(s32)
            uStack_24;
            uStack_2c = randomGetRange(0xfffffff6, 10);
            local_60 = lbl_803E0E3C * (f32)(s32)
            uStack_2c;
            uStack_14 = randomGetRange(7, 9);
            local_5c = lbl_803E0E60 *
                lbl_803E0E64 * (f32)(s32)
            uStack_14;
            local_98[2] = 0x3c;
            local_54 = 0x80100;
            local_37 = 0x10;
            local_56 = 0xde;
            break;
        case 0x73e:
            uStack_14 = randomGetRange(0xfffffff6, 10);
            local_68 = lbl_803E0E3C * (f32)(s32)
            uStack_14;
            uStack_1c = randomGetRange(0xfffffff6, 100);
            local_64 = lbl_803E0E50 * (f32)(s32)
            uStack_1c;
            uStack_24 = randomGetRange(0xfffffff6, 10);
            local_60 = lbl_803E0E3C * (f32)(s32)
            uStack_24;
            uStack_2c = randomGetRange(7, 9);
            local_5c = lbl_803E0E60 *
                lbl_803E0E64 * (f32)(s32)
            uStack_2c;
            local_98[2] = 0x3c;
            local_54 = 0x80100;
            local_37 = 0x10;
            local_56 = 0xdf;
            break;
        case 0x73f:
            if (param_6 == 0)
            {
                uStack_14 = randomGetRange(0xfffffff6, 10);
                local_68 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_14;
                uStack_1c = randomGetRange(0xfffffff6, 100);
                local_64 = lbl_803E0E50 *
                    (f32)(s32)
                uStack_1c;
                uStack_24 = randomGetRange(0xfffffff6, 10);
                uStack_24 = uStack_24 ^ 0x80000000;
                local_60 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_24;
            }
            else
            {
                uStack_14 = randomGetRange(0xfffffff6, 10);
                local_68 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_14 +
                    lbl_803E0E68;
                uStack_1c = randomGetRange(0xfffffff6, 100);
                local_64 = lbl_803E0E50 *
                    (f32)(s32)
                uStack_1c +
                    lbl_803E0E6C;
                uStack_24 = randomGetRange(0xfffffff6, 10);
                uStack_24 = uStack_24 ^ 0x80000000;
                local_60 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_24 +
                    lbl_803E0E70;
            }
            local_28 = 0x43300000;
            uStack_14 = randomGetRange(7, 9);
            local_5c = lbl_803E0E74 *
                lbl_803E0E64 * (f32)(s32)
            uStack_14;
            local_98[2] = 0x3c;
            local_54 = 0x80100;
            local_37 = 0x10;
            local_56 = 0xde;
            break;
        case 0x740:
            if (param_6 == 0)
            {
                uStack_14 = randomGetRange(0xfffffff6, 10);
                local_68 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_14;
                uStack_1c = randomGetRange(0xfffffff6, 100);
                local_64 = lbl_803E0E50 *
                    (f32)(s32)
                uStack_1c;
                uStack_24 = randomGetRange(0xfffffff6, 10);
                uStack_24 = uStack_24 ^ 0x80000000;
                local_60 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_24;
            }
            else
            {
                uStack_14 = randomGetRange(0xfffffff6, 10);
                local_68 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_14 +
                    lbl_803E0E68;
                uStack_1c = randomGetRange(0xfffffff6, 100);
                local_64 = lbl_803E0E50 *
                    (f32)(s32)
                uStack_1c +
                    lbl_803E0E6C;
                uStack_24 = randomGetRange(0xfffffff6, 10);
                uStack_24 = uStack_24 ^ 0x80000000;
                local_60 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_24 +
                    lbl_803E0E70;
            }
            local_28 = 0x43300000;
            uStack_14 = randomGetRange(7, 9);
            local_5c = lbl_803E0E74 *
                lbl_803E0E64 * (f32)(s32)
            uStack_14;
            local_98[2] = 0x3c;
            local_54 = 0x80100;
            local_37 = 0x10;
            local_56 = 0xdf;
            break;
        case 0x741:
            if (param_3 != (undefined2*)0x0)
            {
                local_64 = ((PartFxSpawnParams*)param_3)->unk10;
            }
            local_5c = lbl_803E0E78;
            local_98[2] = randomGetRange(0, 0x1e);
            local_98[2] = local_98[2] + 0x50;
            local_38 = 0x60;
            local_54 = 0x80110;
            local_56 = 0x7b;
            local_37 = 0x20;
            break;
        case 0x742:
            local_6c = lbl_803E0E7C;
            uStack_14 = randomGetRange(0xffffffec, 0x14);
            local_74 = lbl_803E0E80 * (f32)(s32)
            uStack_14;
            uStack_1c = randomGetRange(0xffffffec, 0x14);
            local_70 = lbl_803E0E80 * (f32)(s32)
            uStack_1c;
            local_5c = lbl_803E0E84;
            local_98[2] = randomGetRange(0x46, 0x50);
            local_38 = 0xff;
            local_54 = 0x82000104;
            local_50 = 0x400;
            local_56 = 0x3f4;
            break;
        case 0x743:
            local_6c = lbl_803E0E7C;
            uStack_14 = randomGetRange(0xffffffec, 0x14);
            local_74 = lbl_803E0E80 * (f32)(s32)
            uStack_14;
            uStack_1c = randomGetRange(0xffffffec, 0x14);
            local_70 = lbl_803E0E80 * (f32)(s32)
            uStack_1c;
            local_5c = lbl_803E0E84;
            local_98[2] = randomGetRange(0x46, 0x50);
            local_38 = 0xff;
            local_54 = 0x82000104;
            local_50 = 0x400;
            local_56 = 0x500;
            break;
        case 0x744:
            uVar2 = randomGetRange(0, 4);
            if (uVar2 == 4)
            {
                local_5c = lbl_803E0E88;
                local_38 = 0x9b;
                local_54 = 0x480000;
                local_98[2] = randomGetRange(0x1e, 0x28);
            }
            else
            {
                local_5c = lbl_803E0E8C;
                local_38 = 0x7d;
                local_54 = 0x180000;
                local_98[2] = 0x50;
            }
            local_50 = 0x2000000;
            local_56 = 0x88;
        }
        local_54 = local_54 | param_4;
        if (((local_54 & 1) != 0) && ((local_54 & 2) != 0))
        {
            local_54 = local_54 ^ 2;
        }
        if ((local_54 & 1) != 0)
        {
            if ((param_4 & 0x200000) == 0)
            {
                if (local_98[0] != 0)
                {
                    local_68 = local_68 + *(float*)(local_98[0] + 0x18);
                    local_64 = local_64 + *(float*)(local_98[0] + 0x1c);
                    local_60 = local_60 + *(float*)(local_98[0] + 0x20);
                }
            }
            else
            {
                local_68 = local_68 + local_80;
                local_64 = local_64 + local_7c;
                local_60 = local_60 + local_78;
            }
        }
        uVar1 = (*gExpgfxInterface)->spawnEffect(local_98, 0xffffffff, param_2, 0);
    }
    return uVar1;
}


/*
 * --INFO--
 *
 * Function: FUN_800c9030
 * EN v1.0 Address: 0x800C9030
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x800D57BC
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800c9030(uint param_1, int* param_2)
{
    int iVar1;
    int iVar2;
    int iVar3;

    *param_2 = -1;
    if ((int)param_1 < 0)
    {
        return 0;
    }
    iVar1 = DAT_803de090 + -1;
    iVar2 = 0;
    while (true)
    {
        while (true)
        {
            if (iVar1 < iVar2)
            {
                *param_2 = -1;
                return 0;
            }
            iVar3 = iVar1 + iVar2 >> 1;
            if (param_1 <= (uint)(&DAT_8039d0b8)[iVar3 * 2]) break;
            iVar2 = iVar3 + 1;
        }
        if ((uint)(&DAT_8039d0b8)[iVar3 * 2] <= param_1) break;
        iVar1 = iVar3 + -1;
    }
    *param_2 = iVar3;
    return (&DAT_8039d0bc)[iVar3 * 2];
}


/* sda21 globals used by leaf accessors below. */
extern s16 lbl_803DD414;
extern s16 lbl_803DD416;



/* Globals for tick functions Effect16_func05 / Effect17_func05 / Effect18_func05 / Effect19_func05 / Effect20_func05. */







typedef struct WaterfxCfg
{
    s16 x;
    s16 y;
    s16 z;
    u8 pad6[2];
    f32 f8;
    f32 fc;
    f32 f10;
    f32 f14;
} WaterfxCfg;



extern f32 lbl_803E0110;
extern f32 lbl_803E0114;
extern f32 lbl_803E0118;
extern f32 lbl_803E011C;
extern f32 lbl_803E0120;
extern f32 lbl_803E0124;
extern f32 lbl_803E0128;
extern f32 lbl_803E012C;
extern f32 lbl_803E0130;
extern f32 lbl_803E0134;
extern f32 lbl_803E0138;
extern f32 lbl_803E013C;
extern f32 lbl_803E0140;
extern f32 lbl_803E0144;
extern f32 lbl_803E0148;
extern f32 lbl_803E014C;
extern f32 lbl_803E0150;
extern f32 lbl_803E0154;
extern f32 lbl_803E0158;
extern f32 lbl_803E015C;
extern f32 lbl_803E0160;
extern f32 lbl_803E0164;
extern f32 lbl_803E0168;
extern f32 lbl_803E016C;
extern f32 lbl_803E0170;
extern f32 lbl_803E0174;
extern WaterfxCfg lbl_8039C428;





/* Binary search for key in lbl_8039C458 (count = lbl_803DD410). */
#pragma dont_inline on



/* Build particle quad positions from a checkpoint pair. */
#pragma dont_inline off

/* Set *p to lbl_803DD414 (sign-extended) and return lbl_803DD418. */

/* Swap lbl_803DD418 with lbl_803DD41C; copy 416 into 414 then clear 416. */
void fn_800D6584(void)
{
    extern u32 lbl_803DD418; /* #57 */
    extern u32 lbl_803DD41C; /* #57 */
    u32 tmp = lbl_803DD418;
    lbl_803DD418 = lbl_803DD41C;
    lbl_803DD41C = tmp;
    lbl_803DD414 = lbl_803DD416;
    lbl_803DD416 = 0;
}

/* Rank object r3 against array at lbl_803DD418 by (int@0x1c, float@0xc) descending. */

/* NOTE: 96.8% ? register choice differs (r5 vs r7 for rank). */

/* Find item in lbl_803DD418 array whose rank equals target_rank. */

/* Init random offsets / chain advance with lookup. */

/* Walk a chain via Checkpoint_find lookups starting from o->_0x10. */

/* Append v to array pointed to by lbl_803DD41C, capped at 10 entries.
 * NOTE: stuck at ~78% ? instruction scheduling differs. */

/* Tick: counter1, counter2 + rate*timeDelta; clamp; periodic sin. */



/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */
typedef struct PartFxSpawn
{
    void* attachedSource;
    int quadVertex3Pad06;
    int lifetimeFrames;
    s16 sourceVecX;
    s16 sourceVecY;
    s16 sourceVecZ;
    u8 pad12[2];
    f32 sourcePosX;
    f32 sourcePosY;
    f32 sourcePosZ;
    f32 sourcePosW;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    f32 startPosX;
    f32 startPosY;
    f32 startPosZ;
    f32 scale;
    s16 textureSetupFlags;
    s16 textureId;
    u32 behaviorFlags;
    u32 renderFlags;
    u32 overrideColor0;
    u32 overrideColor1;
    u32 overrideColor2;
    u16 colorWord0;
    u16 colorWord1;
    u16 colorWord2;
    u8 effectIdByte;
    u8 pad5f[1];
    u8 initialAlpha;
    u8 linkGroup;
    u8 modelIdByte;
} PartFxSpawn;





int Effect15_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                    u8 modelId, f32* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803E0110;
    cfg.startPosY = lbl_803E0110;
    cfg.startPosZ = lbl_803E0110;
    cfg.velocityX = lbl_803E0110;
    cfg.velocityY = lbl_803E0110;
    cfg.velocityZ = lbl_803E0110;
    cfg.scale = lbl_803E0110;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = -1;
    cfg.initialAlpha = 0xff;
    cfg.linkGroup = 0;
    cfg.textureId = 0;
    cfg.colorWord0 = 0xffff;
    cfg.colorWord1 = 0xffff;
    cfg.colorWord2 = 0xffff;
    cfg.overrideColor0 = 0xffff;
    cfg.overrideColor1 = 0xffff;
    cfg.overrideColor2 = 0xffff;
    switch (effectId)
    {
    case 0x3e8:
        cfg.scale = lbl_803E0114 * (f32)(s32)
        randomGetRange(0x5a, 0x64);
        cfg.velocityX = lbl_803E0118 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E0110;
        cfg.velocityZ = lbl_803E0118 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.lifetimeFrames = 0x28;
        cfg.behaviorFlags |= 0x80218LL;
        cfg.renderFlags = 0x20;
        switch (randomGetRange(0, 2))
        {
        case 0:
            cfg.textureId = 0x156;
            break;
        case 1:
            cfg.textureId = 0x157;
            break;
        case 2:
            cfg.textureId = 0xc0e;
            break;
        default:
            cfg.textureId = 0x156;
            break;
        }
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xd6d8;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0x7530;
        cfg.overrideColor2 = 0xffff;
        cfg.initialAlpha = 0xff;
        break;
    case 0x3e9:
        if (spawnParams == 0)
        {
            lbl_8039C428.fc = lbl_803E0110;
            lbl_8039C428.f10 = lbl_803E0110;
            lbl_8039C428.f14 = lbl_803E0110;
            lbl_8039C428.f8 = lbl_803E011C;
            lbl_8039C428.x = 0;
            lbl_8039C428.y = 0;
            lbl_8039C428.z = 0;
            spawnParams = (s16*)&lbl_8039C428;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E0120;
        cfg.behaviorFlags |= 0x180110LL;
        cfg.renderFlags = 0x20;
        cfg.lifetimeFrames = 0x12;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x159;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xc350;
        cfg.overrideColor2 = 0xffff;
        break;
    case 0x3ea:
        if (spawnParams == 0)
        {
            lbl_8039C428.fc = lbl_803E0110;
            lbl_8039C428.f10 = lbl_803E0110;
            lbl_8039C428.f14 = lbl_803E0110;
            lbl_8039C428.f8 = lbl_803E011C;
            lbl_8039C428.x = 0;
            lbl_8039C428.y = 0;
            lbl_8039C428.z = 0;
            spawnParams = (s16*)&lbl_8039C428;
        }
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803E0124;
        cfg.startPosY = (f32)(s32)(-(s32)randomGetRange(0x64, 0x96)) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803E0124;
        cfg.behaviorFlags |= 0x80208LL;
        cfg.renderFlags = 0x10000;
        cfg.velocityX = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.initialAlpha = 0xff;
        cfg.lifetimeFrames = 0x3c;
        cfg.textureId = 0x7b;
        cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 *
            (lbl_803E0130 * (lbl_803E0134 * (f32)(s32)
        randomGetRange(0x32, 0x64)
        )
        )
        +
            lbl_803E012C;
        break;
    case 0x3eb:
        cfg.velocityX = lbl_803E0138 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803E013C * (f32)(s32)
        randomGetRange(-5, 5);
        cfg.velocityZ = lbl_803E0138 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosX = lbl_803E0110;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-6, 2);
        cfg.startPosZ = lbl_803E0110;
        cfg.scale = lbl_803E013C;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x80080208;
        cfg.textureId = 0x60;
        cfg.colorWord0 = 0x7f00;
        cfg.colorWord1 = 0x6400;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0x5a00;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x3ec:
        return -1;
    case 0x3ed:
        cfg.velocityX = lbl_803E013C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E0120 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityZ = lbl_803E013C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803E0140 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x80210;
        cfg.renderFlags = 0x8000800;
        cfg.textureId = 0x79;
        break;
    case 0x3ee:
        cfg.startPosX = cfg.startPosX + (f32)(s32)
        randomGetRange(-0xa, 0xa) / lbl_803E0144;
        cfg.startPosY = cfg.startPosY + (f32)(s32)
        randomGetRange(-0x1e, 0) / lbl_803E0148;
        cfg.startPosZ = cfg.startPosZ + (f32)(s32)
        randomGetRange(-0xa, 0xa) / lbl_803E0144;
        cfg.velocityX = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E014C * (f32)(s32)(-(s32)randomGetRange(0x28, 0x64));
        cfg.velocityZ = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E012C * (f32)(s32)
        randomGetRange(0xf, 0x16);
        cfg.lifetimeFrames = 0x258;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0xc10;
        cfg.initialAlpha = (u8)randomGetRange(0x96, 0xfa);
        break;
    case 0x3ef:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x4b0, 0x4b0) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x4b0, 0x4b0) / lbl_803E0128;
        cfg.velocityY = lbl_803E014C * (f32)(s32)
        randomGetRange(0x1e, 0x46);
        cfg.scale = lbl_803E0154 * (f32)(s32)
        randomGetRange(0, 0x14) + lbl_803E0150;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x33;
        cfg.initialAlpha = 0xb4;
        cfg.renderFlags = 0x8100800;
        break;
    case 0x3f0:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8) / lbl_803E0128;
        cfg.velocityY = lbl_803E0158 * (f32)(s32)
        randomGetRange(0x1e, 0x46);
        cfg.scale = lbl_803E0154 * (f32)(s32)
        randomGetRange(0, 0x14) + lbl_803E015C;
        cfg.lifetimeFrames = 0xfa;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x33;
        cfg.renderFlags = 0x8000800;
        cfg.initialAlpha = 0xb4;
        break;
    case 0x3f1:
        cfg.startPosX = lbl_803E0110;
        cfg.startPosY = lbl_803E0110;
        cfg.startPosZ = lbl_803E0110;
        cfg.behaviorFlags = 0x80800;
        cfg.textureId = 0x76;
        cfg.initialAlpha = 0xd2;
        cfg.scale = lbl_803E0160;
        cfg.lifetimeFrames = 0x64;
        break;
    case 0x3f2:
        if (extraArgs == 0) return 0;
        if (spawnParams == 0)
        {
            lbl_8039C428.fc = lbl_803E0110;
            lbl_8039C428.f10 = lbl_803E0110;
            lbl_8039C428.f14 = lbl_803E0110;
            lbl_8039C428.f8 = lbl_803E011C;
            lbl_8039C428.x = 0;
            lbl_8039C428.y = 0;
            lbl_8039C428.z = 0;
            spawnParams = (s16*)&lbl_8039C428;
        }
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        if (extraArgs != 0)
        {
            cfg.velocityX = extraArgs[0];
            cfg.velocityY = lbl_803E0164 * (f32)(s32)
            randomGetRange(0, 0x14);
            cfg.velocityZ = extraArgs[1];
        }
        cfg.scale = lbl_803E0168 *
            (lbl_803E0170 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803E016C
        )
        ;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x81088000;
        cfg.textureId = 0x23c;
        break;
    case 0x3f3:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.velocityX = lbl_803E0118 * (f32)(s32)
        randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityX = -cfg.velocityX;
        cfg.velocityY = lbl_803E0118 * (f32)(s32)
        randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityY = -cfg.velocityY;
        cfg.velocityZ = lbl_803E0118 * (f32)(s32)
        randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityZ = -cfg.velocityZ;
        cfg.scale = lbl_803E0154 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803E012C;
        cfg.lifetimeFrames = 0x46;
        cfg.behaviorFlags = 0x80208;
        cfg.textureId = 0x76;
        cfg.initialAlpha = 0xb4;
        cfg.renderFlags = 0x100000;
        break;
    case 0x3f4:
    case 0x3f5:
    case 0x3f6:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
        }
        if ((int)randomGetRange(0, 0x28) == 0) cfg.scale = lbl_803E0130;
        else cfg.scale = lbl_803E015C;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        switch (effectId - 0x3f4)
        {
        case 0:
            cfg.textureId = 0x156;
            break;
        case 1:
            cfg.textureId = 0x157;
            break;
        case 2:
            cfg.textureId = 0xc0e;
            break;
        default:
            cfg.textureId = 0x156;
            break;
        }
        break;
    case 0x3f7:
    case 0x3f8:
    case 0x3f9:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.velocityZ = lbl_803E0174;
        }
        cfg.scale = lbl_803E015C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480210;
        cfg.renderFlags = 0x100000;
        switch (effectId - 0x3f7)
        {
        case 0:
            cfg.textureId = 0x4fb;
            break;
        case 1:
            cfg.textureId = 0x4fc;
            break;
        case 2:
            cfg.textureId = 0x4fd;
            break;
        default:
            cfg.textureId = 0x4fb;
            break;
        }
        break;
    case 0x3fa:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.velocityZ = lbl_803E0134;
        }
        cfg.scale = lbl_803E015C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480210;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0x4fb;
        break;
    case 0x3fb:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8;
        }
        cfg.lifetimeFrames = 5;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80800;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5ea;
        break;
    case 0x3fc:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8;
        }
        cfg.lifetimeFrames = 5;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80800;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5eb;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
            cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
            cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
        }
        else
        {
            if (cfg.attachedSource != 0)
            {
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

int Effect18_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, void* extraArgs);


/* ---- Effect20_func04 (FUN_800cd430, v1.0) ---- */




/* Trivial 4b 0-arg blr leaves. */



void Effect15_func05_nop(void)
{
}

void Effect15_func03_nop(void)
{
}

void Effect15_release(void)
{
}

void Effect15_initialise(void)
{
}

void Effect13_func05_nop(void);
















/* 8b "li r3, N; blr" returners. */


/* Advance along the checkpoint curve by dist; write position/angles to out. */


/* segment pragma-stack balance (re-split): */
#pragma dont_inline reset
#pragma dont_inline reset

/* === moved from main/dll/df_partfx.c [800D6660-800D7568) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"



/*
 * --INFO--
 *
 * Function: Checkpoint_func07
 * EN v1.0 Address: 0x800D6660
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800D6844
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset


/*
 * --INFO--
 *
 * Function: FUN_800d7780
 * EN v1.0 Address: 0x800D7780
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800D7CFC
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */





























/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* Pattern wrappers. */

/* 12b 3-insn patterns. */


/* misc 8b leaves */

/* Pattern wrappers. */

/* sda21 writers. */
#pragma peephole off
#pragma peephole reset

/* fcmp-eq-to-bool. */

/* multi-store leaf (single float broadcast). */


/* Checkpoint table initialiser. */

#pragma scheduling off
#pragma peephole off







#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset


#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

/* Checkpoint_Add: sorted insertion of (entry->_14 as key, entry as pointer) into lbl_8039C458 table. */

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off

#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma scheduling off
#pragma peephole off

#pragma scheduling off
#pragma peephole off
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset




#pragma scheduling reset
#pragma peephole reset
