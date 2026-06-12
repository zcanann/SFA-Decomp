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
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 mathSinf(f32 x);












extern f32 lbl_803DB888;
extern f32 lbl_803DB88C;
extern f32 lbl_803E0310;
extern f32 lbl_803E0314;
extern f32 lbl_803E0318;
extern f32 lbl_803E0320;
extern s32 lbl_803DD400;
extern s32 lbl_803DD404;
extern f32 lbl_803DD408;
extern f32 lbl_803DD40C;
extern f32 lbl_803E0344;
extern f32 lbl_803E0348;



/* Binary search for key in lbl_8039C458 (count = lbl_803DD410). */
#pragma dont_inline on

extern f32 mathCosf(f32 x);


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








/* ---- Effect20_func04 (FUN_800cd430, v1.0) ---- */
extern f32 lbl_803DB880;
extern f32 lbl_803DB884;
extern f32 lbl_803E031C;
extern f32 lbl_803E0324;
extern f32 lbl_803E0328;
extern f32 lbl_803E032C;
extern f32 lbl_803E0330;
extern f32 lbl_803E0334;
extern f32 lbl_803E0338;
extern f32 lbl_803E033C;
extern f32 lbl_803E0340;
extern f32 lbl_803E034C;
extern f32 lbl_803E0350;
extern f32 lbl_803E0354;
extern f32 lbl_803E0358;
extern f32 lbl_803E035C;
extern f32 lbl_803E0360;
extern f32 lbl_803E0364;
extern f32 lbl_803E0368;
extern f32 lbl_803E036C;
extern f32 lbl_803E0370;
extern f32 lbl_803E0374;
extern f32 lbl_803E0378;
extern f32 lbl_803E037C;
extern f32 lbl_803E0380;
extern f32 lbl_803E0384;
extern f32 lbl_803E0388;
extern f32 lbl_803E038C;
extern f32 lbl_803E0390;
extern f32 lbl_803E0394;
extern f32 lbl_803E0398;
extern f32 lbl_803E039C;
extern f32 lbl_803E03A0;
extern f32 lbl_803E03A4;
extern f32 lbl_803E03A8;
extern f32 lbl_803E03AC;
extern f32 lbl_803E03B0;
extern f32 lbl_803E03B4;
extern f32 lbl_803E03B8;
extern f32 lbl_803E03BC;
extern f32 lbl_803E03C0;
extern f32 lbl_803E03C4;
extern f32 lbl_803E03C8;
extern f32 lbl_803E03CC;
extern f32 lbl_803E03D0;
extern f32 lbl_803E03D4;
extern f32 lbl_803E03D8;
extern f32 lbl_803E03DC;
extern f32 lbl_803E03E0;
extern f32 lbl_803E03E4;
extern f32 lbl_803E03E8;
extern f32 lbl_803E03EC;
extern f32 lbl_803E03F0;
extern f32 lbl_803E03F4;
extern f32 lbl_803E03F8;
extern f32 lbl_803E03FC;
extern f32 lbl_803E0400;
extern f32 lbl_803E0404;
extern f32 lbl_803E0408;
extern f32 lbl_803E040C;
extern f32 lbl_803E0410;
extern f32 lbl_803E0414;
extern f32 lbl_803E0418;
extern f32 lbl_803E041C;
extern f32 lbl_803E0420;
extern f32 lbl_803E0424;
extern f32 lbl_803E0428;
extern f32 lbl_803E042C;
extern f32 lbl_803E0430;
extern f32 lbl_803E0434;
extern f32 lbl_803E0438;
extern f32 lbl_803E043C;
extern f32 lbl_803E0440;
extern f32 lbl_803E0444;
extern f32 lbl_803E0448;
extern f32 lbl_803E044C;
extern f32 lbl_803E0450;
extern f32 lbl_803E0454;
extern f32 lbl_803E0458;
extern f32 lbl_803E045C;
extern f64 lbl_803E0460;
extern f32 lbl_803E0468;
extern f32 lbl_803E046C;
extern f32 lbl_803E0470;
extern f32 lbl_803E0474;
extern f32 lbl_803E0478;
extern f32 lbl_803E047C;
extern f32 lbl_803E0480;
extern f32 lbl_803E0484;
extern f32 lbl_803E0488;
extern f32 lbl_803E048C;
extern f32 lbl_803E0490;
extern f32 lbl_803E0494;
extern f32 lbl_803E0498;
extern f32 lbl_803E049C;
extern f32 lbl_803E04A0;
extern f32 lbl_803E04A4;
extern f32 lbl_803E04A8;
extern f32 lbl_803E04AC;
extern f32 lbl_803E04B0;
extern f32 lbl_803E04B4;
extern f32 lbl_803E04B8;
extern f32 lbl_803E04BC;
extern f32 lbl_803E04C0;
extern f32 lbl_803E04C4;
extern f32 lbl_803E04C8;
extern void vecRotateZXY(void* params, f32* vec);
extern int randFn_80080100(int range);

int Effect20_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                    u8 modelId, f32* extraArgs)
{
    int ret;
    int intVal;
    int variant;
    f32 trigVal;
    f32 angle;
    f32 radius;
    PartFxSpawn cfg;

    ret = 0;
    lbl_803DB880 = lbl_803DB880 + lbl_803E0310;
    if (lbl_803DB880 > 1.0f) lbl_803DB880 = lbl_803E0314;
    lbl_803DB884 = lbl_803DB884 + lbl_803E031C;
    if (lbl_803DB884 > 1.0f) lbl_803DB884 = lbl_803E0320;
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
    cfg.startPosX = lbl_803E0324;
    cfg.startPosY = lbl_803E0324;
    cfg.startPosZ = lbl_803E0324;
    cfg.velocityX = lbl_803E0324;
    cfg.velocityY = lbl_803E0324;
    cfg.velocityZ = lbl_803E0324;
    cfg.scale = lbl_803E0324;
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
    case 0x79e:
        if (extraArgs != NULL)
        {
            cfg.velocityX = lbl_803E0320 * *extraArgs + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0320 * extraArgs[1] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0320 * extraArgs[2] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
        }
        cfg.scale = lbl_803E0328 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.lifetimeFrames = 100;
        cfg.behaviorFlags = 0x80480200;
        cfg.renderFlags = 0x8000800;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x84;
        break;
    case 0x79f:
        trigVal = lbl_803E0310 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.scale = (extraArgs != NULL ? *extraArgs : lbl_803E0318) * trigVal;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x180010;
        cfg.renderFlags = 0x8000;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc80;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        break;
    case 0x7a0:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80080210;
            cfg.renderFlags = 0x8000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
        }
        else
        {
            cfg.velocityX = lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = randomGetRange(0x14, 0x28);
            cfg.behaviorFlags = 0x80010;
            cfg.renderFlags = 0x8480800;
            cfg.scale = lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100);
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xdb;
        break;
    case 0x7a1:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80080210;
            cfg.renderFlags = 0x8000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
        }
        else
        {
            cfg.velocityX = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = randomGetRange(0x14, 0x28);
            cfg.behaviorFlags = 0x80010;
            cfg.renderFlags = 0x8480800;
            cfg.scale = lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100);
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x157;
        break;
    case 0x7a2:
        if (extraArgs != NULL)
        {
            cfg.velocityX = lbl_803E0338 * *extraArgs + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0338 * extraArgs[1] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0338 * extraArgs[2] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
        }
        cfg.lifetimeFrames = randomGetRange(10, 0x1e);
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x400800;
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xde;
        break;
    case 0x7a3:
        intVal = randomGetRange(0xffff8001, 0x7fff);
        angle = (lbl_803E0344 * (f32)(s32)
        intVal
        )
        /
        lbl_803E0348;
        trigVal = mathCosf(angle);
        cfg.velocityX = (lbl_803E0340 * (f32)(s32)
        randomGetRange(100, 0x96)
        )
        *trigVal;
        trigVal = mathSinf(angle);
        cfg.velocityY = (lbl_803E0340 * (f32)(s32)
        randomGetRange(100, 0x96)
        )
        *trigVal;
        cfg.velocityZ = lbl_803E0324;
        cfg.lifetimeFrames = randomGetRange(0x14, 0x1e);
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x480800;
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xde;
        break;
    case 0x7a4:
        if (extraArgs != NULL)
        {
            cfg.velocityX = lbl_803E0338 * *extraArgs + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0338 * extraArgs[1] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0338 * extraArgs[2] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
        }
        cfg.lifetimeFrames = randomGetRange(10, 0x1e);
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x400800;
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc22;
        break;
    case 0x7a5:
        intVal = randomGetRange(0xffff8001, 0x7fff);
        angle = (lbl_803E0344 * (f32)(s32)
        intVal
        )
        /
        lbl_803E0348;
        trigVal = mathCosf(angle);
        cfg.velocityX = (lbl_803E0330 * (f32)(s32)
        randomGetRange(100, 0x96)
        )
        *trigVal;
        trigVal = mathSinf(angle);
        cfg.velocityY = (lbl_803E0330 * (f32)(s32)
        randomGetRange(100, 0x96)
        )
        *trigVal;
        cfg.velocityZ = lbl_803E0324;
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x28);
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x480800;
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc22;
        break;
    case 0x7a6:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80080210;
            cfg.renderFlags = 0x8000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
        }
        else
        {
            cfg.velocityX = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = randomGetRange(0x14, 0x28);
            cfg.behaviorFlags = 0x80010;
            cfg.renderFlags = 0x8480800;
            cfg.scale = lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100);
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc7e;
        break;
    case 0x7a7:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80080210;
            cfg.renderFlags = 0x8000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
        }
        else
        {
            cfg.velocityX = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = randomGetRange(0x14, 0x28);
            cfg.behaviorFlags = 0x80010;
            cfg.renderFlags = 0x8480800;
            cfg.scale = lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100);
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc13;
        break;
    case 0x7a8:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80200);
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7a9:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0358 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80200);
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7aa:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E035C * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0314 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0314 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0360 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x23) + 0x19;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80200);
            cfg.renderFlags = 0x4040800;
            cfg.renderFlags |= 0x20;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0xffff;
            cfg.overrideColor2 = randomGetRange(0, 0xffff);
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = randomGetRange(0, 0x7fff);
            cfg.colorWord2 = (ushort)cfg.overrideColor2;
        }
        break;
    case 0x7ab:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0364 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0368 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0368 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x23, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x12) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80080200);
            cfg.renderFlags = 0x4010800;
            ret = 1;
        }
        break;
    case 0x7ac:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0364 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E036C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E036C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x17) + 5;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80080200);
            cfg.renderFlags = 0x40800;
        }
        break;
    case 0x7ad:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0370 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0374 * (f32)(s32)
            randomGetRange(0xf, 0x14) + ((PartFxSpawnParams*)spawnParams)->unk10
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0378 * (f32)(s32)
            randomGetRange(0x50, 0x8c)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0, 10) + 0x32;
            cfg.textureId = 0xc10;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80100;
            cfg.renderFlags = 0x4010020;
            cfg.colorWord0 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.colorWord1 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.colorWord2 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.overrideColor0 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.overrideColor1 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.overrideColor2 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7ae:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E037C * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0374 * (f32)(s32)
            randomGetRange(0xf, 0x14) + ((PartFxSpawnParams*)spawnParams)->unk10
            )
            ;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0384 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0, 10) + 0x32;
            cfg.textureId = 0xc0d;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80480000;
            cfg.renderFlags = 0x410800;
        }
        break;
    case 0x7af:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0388 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosY = (lbl_803E038C + ((PartFxSpawnParams*)spawnParams)->unk10) * ((PartFxSpawnParams*)
                spawnParams)->unk8;
            cfg.scale = lbl_803E0390 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = 5;
            cfg.textureId = 0x5e6;
            cfg.initialAlpha = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80200;
            cfg.renderFlags = 0x4088000;
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = 0xffff;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0xffff;
            cfg.overrideColor2 = 0xffff;
        }
        break;
    case 0x7b0:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0388 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosY = (lbl_803E038C + ((PartFxSpawnParams*)spawnParams)->unk10) * ((PartFxSpawnParams*)
                spawnParams)->unk8;
            cfg.scale = lbl_803E0390 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = 0xf;
            cfg.textureId = 0x5e6;
            cfg.initialAlpha = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80100;
            cfg.renderFlags = 0x4088000;
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = 0xffff;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0xffff;
            cfg.overrideColor2 = 0xffff;
        }
        break;
    case 0x7b1:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0394 * (f32)(s32)
            randomGetRange(0xffffffe5, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0398 * (f32)(s32)
            randomGetRange(10, 0x14)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x23, 100);
            cfg.initialAlpha = 0xff;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80480100;
            cfg.renderFlags = 0x8010800;
        }
        break;
    case 0x7b2:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.scale = lbl_803E039C * (f32)(s32)
            randomGetRange(0x1c, 0x20);
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.textureId = *spawnParams;
            cfg.behaviorFlags = 0x480204;
            cfg.renderFlags = 0x808;
        }
        break;
    case 0x7b3:
        if (spawnParams != NULL)
        {
            cfg.scale = lbl_803E03A0 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk10 * (f32)(s32)
            randomGetRange(0x154, 0x2d5);
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.textureId = *spawnParams;
            cfg.behaviorFlags = 0x80114;
            cfg.renderFlags = 0x4000800;
        }
        break;
    case 0x7b4:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.scale = lbl_803E039C * (f32)(s32)
            randomGetRange(0x1c, 0x20);
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.textureId = *spawnParams;
            cfg.behaviorFlags = 0x480004;
            cfg.renderFlags = 0x480800;
        }
        break;
    case 0x7b5:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E031C * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
                randomGetRange(6, 10);
                cfg.behaviorFlags = 0xc1080000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = 10;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0xc1180000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 10;
            }
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.velocityZ = lbl_803E0314 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A4 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0xc0a;
            cfg.renderFlags = cfg.renderFlags | 0x20;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0xffff;
            cfg.overrideColor2 = randomGetRange(0, 0xffff);
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = randomGetRange(0, 0x7fff);
            cfg.colorWord2 = (ushort)cfg.overrideColor2;
        }
        break;
    case 0x7b6:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E031C * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
                randomGetRange(6, 10);
                cfg.behaviorFlags = 0x81080000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = 10;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0x81180000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 10;
            }
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityZ = lbl_803E0314 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A4 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0x5f5;
        }
        break;
    case 0x7b7:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.velocityX = lbl_803E0320 * *extraArgs + lbl_803E0310 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                if (lbl_803E0324 != cfg.velocityY)
                {
                    cfg.velocityY = lbl_803E0320 * extraArgs[1] + lbl_803E0310 * (f32)(s32)
                    randomGetRange(0xffffff9c, 100);
                }
                cfg.velocityZ = lbl_803E0320 * extraArgs[2] + lbl_803E0310 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
            }
            else
            {
                cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
                randomGetRange(0x5a, 100)
                )
                ;
            }
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14);
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14);
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14);
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0310 * (f32)(s32)
            randomGetRange(0x5a, 100)
            )
            ;
            cfg.initialAlpha = randomGetRange(0x9b, 0xff);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk4 + randomGetRange(1, 0x14);
            if (((PartFxSpawnParams*)spawnParams)->unk2 != 0)
            {
                cfg.behaviorFlags = 0x80080000;
            }
            else
            {
                cfg.behaviorFlags = 0x80480000;
            }
            if (*spawnParams != 0)
            {
                cfg.renderFlags = 0x4400800;
            }
            else
            {
                cfg.renderFlags = 0x4400000;
            }
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.linkGroup = 0xf;
        }
        break;
    case 0x7b8:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E03AC * (f32)(s32)
        randomGetRange(0x46, 0x50);
        cfg.lifetimeFrames = 5;
        cfg.textureId = 0x2d;
        cfg.behaviorFlags = 0x180200;
        cfg.renderFlags = 0;
        break;
    case 0x7b9:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = (int)*(short*)((int)extraArgs + 6);
            cfg.textureId = *(short*)extraArgs;
            cfg.scale = lbl_803E039C * (f32)(s32)
            randomGetRange(0x1c, 0x20);
            cfg.behaviorFlags = 0x480200;
            cfg.renderFlags = 0x808;
        }
        break;
    case 0x7ba:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)*(short*)((int)extraArgs + 6);
            cfg.textureId = *(short*)extraArgs;
            cfg.scale = lbl_803E03A0 * extraArgs[2];
            cfg.behaviorFlags = 0x80110;
            cfg.renderFlags = 0x4000800;
        }
        break;
    case 0x7bb:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E03B0 * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
                randomGetRange(7, 10);
                cfg.behaviorFlags = 0xc0080200;
                cfg.renderFlags = 0x4010000;
                cfg.lifetimeFrames = 10;
                cfg.initialAlpha = 0x7f;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0xc0180200;
                cfg.renderFlags = 0x4010000;
                cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 10;
                cfg.initialAlpha = randomGetRange((s32)((PartFxSpawnParams*)spawnParams)->unk4,
                                                  ((PartFxSpawnParams*)spawnParams)->unk4 + 10);
            }
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.velocityZ = lbl_803E03B4 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7bc:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E03B0 * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
                randomGetRange(7, 10);
                cfg.behaviorFlags = 0xc1080200;
                cfg.renderFlags = 0x5010000;
                cfg.lifetimeFrames = 10;
                cfg.initialAlpha = 0x7f;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0xc1180200;
                cfg.renderFlags = 0x5010000;
                cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 10;
                cfg.initialAlpha = randomGetRange((s32)((PartFxSpawnParams*)spawnParams)->unk4,
                                                  ((PartFxSpawnParams*)spawnParams)->unk4 + 10);
            }
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.velocityZ = lbl_803E03B4 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B8 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7bd:
        if (spawnParams != NULL)
        {
            cfg.scale = *(f32*)&lbl_803E0310 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.behaviorFlags = 0x83000200;
            cfg.renderFlags = 0x1200000;
            cfg.lifetimeFrames = randomGetRange(10, 0x18);
            cfg.initialAlpha = 0xff;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.velocityX = lbl_803E03BC * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff6a, 0x96)
            )
            )
            ;
            cfg.velocityY = lbl_803E03BC * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff6a, 0x96)
            )
            )
            ;
            cfg.velocityZ = lbl_803E0314 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03C0 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7be:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
                if (extraArgs[2] > lbl_803E0324)
                {
                    cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 *
                        (lbl_803E03C4 * (f32)(s32)
                    randomGetRange(100, 0x6b)
                    )
                    )
                    ;
                }
                else if (extraArgs[2] < lbl_803E0324)
                {
                    cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 *
                        (lbl_803E03C4 * (f32)(s32)
                    randomGetRange(100, 0x6b)
                    )
                    )
                    ;
                }
                else
                {
                    cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 *
                        (lbl_803E03B8 * (f32)(s32)
                    randomGetRange(100, 0x6b)
                    )
                    )
                    ;
                }
            }
            else
            {
                cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 * (
                    lbl_803E03B8 * (f32)(s32)
                randomGetRange(100, 0x6b)
                )
                )
                ;
            }
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03C8 * (f32)(s32)
            randomGetRange(0x1c, 0x22)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x14, 0x1b);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80004;
            cfg.renderFlags = 0x8002820;
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.colorWord0 = 0xff2d;
                cfg.colorWord1 = 0xa8f;
                cfg.colorWord2 = 0x2c;
                cfg.overrideColor0 = 0xf78f;
                cfg.overrideColor1 = 0x9126;
                cfg.overrideColor2 = 0x4828;
            }
            else
            {
                cfg.colorWord0 = 0x69;
                cfg.colorWord1 = 0x863;
                cfg.colorWord2 = 0x7fff;
                cfg.overrideColor0 = 0x7fff;
                cfg.overrideColor1 = 0x2d1a;
                cfg.overrideColor2 = 0x8000;
            }
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7bf:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = (lbl_803E0374 + ((PartFxSpawnParams*)spawnParams)->unkC) * (((PartFxSpawnParams*)spawnParams)->
                unk8 * (lbl_803E03CC * (f32)(s32)
            randomGetRange(10, 0xd)
            )
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 2) + 2;
            cfg.behaviorFlags = 0x80014;
            cfg.renderFlags = 0x4000820;
            cfg.initialAlpha = (int)(lbl_803E03D0 * ((PartFxSpawnParams*)spawnParams)->unkC) + 0x40;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.colorWord0 = 0xff87;
                cfg.colorWord1 = 0x4817;
                cfg.colorWord2 = 0x23;
                cfg.overrideColor0 = 0xf78f;
                cfg.overrideColor1 = 0xffa9;
                cfg.overrideColor2 = 0xb32b;
            }
            else
            {
                cfg.colorWord0 = 0x7fff;
                cfg.colorWord1 = 0x1806;
                cfg.colorWord2 = 0x4cb3;
                cfg.overrideColor0 = 0xf48c;
                cfg.overrideColor1 = 0x9882;
                cfg.overrideColor2 = 0xd97d;
            }
        }
        break;
    case 0x7c0:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03D4 * (f32)(s32)
            randomGetRange(0x2d, 0x3a)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 7) + 0x1e;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80004;
            cfg.renderFlags = 0x8440820;
            cfg.colorWord0 = 0xfb54;
            cfg.colorWord1 = 0;
            cfg.colorWord2 = 0;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0x8347;
            cfg.overrideColor2 = 0x9b49;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 * (
                lbl_803E03D8 * (f32)(s32)
            randomGetRange(100, 0x6c)
            )
            )
            ;
            cfg.velocityY = lbl_803E0324;
            cfg.velocityX = lbl_803E0324;
            if (extraArgs != NULL)
            {
                vecRotateZXY(extraArgs, &cfg.velocityX);
            }
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7c1:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = (lbl_803E0374 + ((PartFxSpawnParams*)spawnParams)->unkC) * (((PartFxSpawnParams*)spawnParams)->
                unk8 * (lbl_803E03DC * (f32)(s32)
            randomGetRange(2, 0xd)
            )
            )
            ;
            cfg.lifetimeFrames = 0x11;
            cfg.behaviorFlags = 0x80114;
            cfg.renderFlags = 0x4000900;
            intVal = (int)(lbl_803E03D0 * ((PartFxSpawnParams*)spawnParams)->unkC);
            cfg.initialAlpha = intVal + 0x40;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7c2:
        if (spawnParams != NULL)
        {
            cfg.velocityY = lbl_803E0350 * (f32)(s32)
            randomGetRange(0, 100);
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * ((lbl_803E03E0 + cfg.velocityY) * (lbl_803E03E4 *
                (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * ((lbl_803E03E0 + cfg.velocityY) * (lbl_803E03E4 *
                (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            )
            ;
            cfg.velocityY = -cfg.velocityY * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B0 * (f32)(s32)
            randomGetRange(0x19, 0x32)
            )
            ;
            cfg.startPosY = lbl_803E03E8 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
            cfg.textureId = 0xc10;
            cfg.initialAlpha = '@';
            cfg.behaviorFlags = 0x80104;
            cfg.renderFlags = 0x4800808;
        }
        break;
    case 0x7c3:
        if (spawnParams != NULL)
        {
            intVal = randomGetRange(0, 0xffff);
            radius = lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + (f32)((PartFxSpawnParams*)spawnParams)->unk6;
            angle = (lbl_803E0344 * (f32)(s32)
            intVal
            )
            /
            lbl_803E0348;
            trigVal = mathSinf(angle);
            cfg.startPosX = radius * trigVal + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = lbl_803E0314 * (f32)(s32)
            randomGetRange(0, (s32)((PartFxSpawnParams*)spawnParams)->unk4) + ((PartFxSpawnParams*)spawnParams)->unk10;
            trigVal = mathCosf(angle);
            cfg.startPosZ = radius * trigVal + ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.lifetimeFrames = randomGetRange(10, 0x28);
            cfg.textureId = 0x156;
            cfg.behaviorFlags = 0x80480104;
            cfg.renderFlags = 0x4000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03EC * (f32)(s32)
            randomGetRange(0x31, 0x39)
            )
            ;
            cfg.initialAlpha = 0xff;
        }
        break;
    case 0x7c4:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = (lbl_803E0374 + ((PartFxSpawnParams*)spawnParams)->unkC) * (((PartFxSpawnParams*)spawnParams)->
                unk8 * (lbl_803E03CC * (f32)(s32)
            randomGetRange(10, 0xd)
            )
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 2) + 2;
            cfg.behaviorFlags = 0x80004;
            cfg.renderFlags = 0x4000820;
            cfg.initialAlpha = (int)(lbl_803E03D0 * ((PartFxSpawnParams*)spawnParams)->unkC) + 0x40;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.colorWord0 = 0xff87;
                cfg.colorWord1 = 0x4817;
                cfg.colorWord2 = 0x23;
                cfg.overrideColor0 = 0xf78f;
                cfg.overrideColor1 = 0xffa9;
                cfg.overrideColor2 = 0xb32b;
            }
            else
            {
                cfg.colorWord0 = 0x7fff;
                cfg.colorWord1 = 0x1806;
                cfg.colorWord2 = 0x4cb3;
                cfg.overrideColor0 = 0xf48c;
                cfg.overrideColor1 = 0x9882;
                cfg.overrideColor2 = 0xd97d;
            }
        }
        break;
    case 0x7c5:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = (lbl_803E0374 + ((PartFxSpawnParams*)spawnParams)->unkC) * (((PartFxSpawnParams*)spawnParams)->
                unk8 * (lbl_803E03DC * (f32)(s32)
            randomGetRange(2, 0xd)
            )
            )
            ;
            cfg.lifetimeFrames = 0x11;
            cfg.behaviorFlags = 0x80104;
            cfg.renderFlags = 0x4000900;
            intVal = (int)(lbl_803E03D0 * ((PartFxSpawnParams*)spawnParams)->unkC);
            cfg.initialAlpha = intVal + 0x40;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7c6:
        cfg.scale = lbl_803E03A8;
        cfg.lifetimeFrames = randomGetRange(0x27, 0x31);
        cfg.behaviorFlags = 0x180000;
        cfg.renderFlags = 0x408000;
        cfg.textureId = 0x5ff;
        break;
    case 0x7c7:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80200;
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7c8:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E034C * (f32)(s32)
            randomGetRange(0xfffffed4, 300);
            cfg.velocityY = lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E034C * (f32)(s32)
            randomGetRange(0xfffffed4, 300);
            cfg.startPosY = lbl_803E03F0;
            cfg.scale = lbl_803E03F4;
            cfg.lifetimeFrames = randomGetRange(0x19, 0x20);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80100;
            cfg.renderFlags = 0x40808;
        }
        break;
    case 0x7c9:
        cfg.velocityX = lbl_803E03F8 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E03FC * (f32)(s32)
        randomGetRange(0, 100);
        cfg.velocityZ = lbl_803E0400 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E0404 * (f32)(s32)
        randomGetRange(0xf, 0x14);
        cfg.lifetimeFrames = randomGetRange(300, 0x1c2);
        cfg.textureId = 0xc10;
        cfg.behaviorFlags = 0x8000100;
        cfg.renderFlags = 0x1000000;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x7ca:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E035C * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0408 * (f32)(s32)
            randomGetRange(0, 100);
            cfg.velocityZ = lbl_803E035C * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.scale = lbl_803E03E4 * (f32)(s32)
            randomGetRange(1, 0x14);
            cfg.lifetimeFrames = randomGetRange(100, 0x78);
            cfg.textureId = 0x605;
            if (((PartFxSpawnParams*)spawnParams)->unk2 == 1)
            {
                cfg.colorWord0 = 0x2234;
                cfg.colorWord1 = 0x8a54;
                cfg.colorWord2 = 0xfff6;
                cfg.overrideColor0 = 0x2234;
                cfg.overrideColor1 = 0x8a54;
                cfg.overrideColor2 = 0xfff6;
            }
            else if (((PartFxSpawnParams*)spawnParams)->unk2 == 2)
            {
                cfg.colorWord0 = 0xfff6;
                cfg.colorWord1 = 0x1524;
                cfg.colorWord2 = 0x1524;
                cfg.overrideColor0 = 0xfff6;
                cfg.overrideColor1 = 0x1524;
                cfg.overrideColor2 = 0x1524;
            }
            else
            {
                cfg.colorWord0 = 0xfff6;
                cfg.colorWord1 = 0x8a54;
                cfg.colorWord2 = 0x2234;
                cfg.overrideColor0 = 0xfff6;
                cfg.overrideColor1 = 0x8a54;
                cfg.overrideColor2 = 0x2234;
            }
            cfg.behaviorFlags = 0x80110;
            cfg.renderFlags = 0x8002828;
            cfg.initialAlpha = -0x40;
        }
        break;
    case 0x7cb:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E040C;
            cfg.lifetimeFrames = (int)
            (((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0x32, 0x3c)
            )
            ;
            cfg.textureId = 0x88;
            cfg.behaviorFlags = 0x480400;
            cfg.renderFlags = 0x80800;
        }
        break;
    case 0x7cc:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E031C * (f32)(s32)
            randomGetRange(5, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x2a, 0x32);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x580000;
            cfg.renderFlags = 0x800;
        }
        break;
    case 0x7cd:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0358 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x280201;
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7ce:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0358 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(5, 0xf);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x280201;
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 1999:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = lbl_803E0410 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0x7f;
            cfg.behaviorFlags = 0x280101;
            cfg.renderFlags = 0x822;
            cfg.colorWord0 = 0x75b;
            cfg.colorWord1 = 0x1642;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0x656a;
            cfg.overrideColor1 = 0x9f8;
            cfg.overrideColor2 = 0xffff;
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.behaviorFlags |= 0x20000000LL;
            }
        }
        break;
    case 2000:
        if (spawnParams != NULL)
        {
            if (extraArgs == NULL)
            {
                cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0370 * (f32)(s32)
                randomGetRange(100, 200)
                )
                ;
                cfg.velocityZ = lbl_803E0414 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0418 * (f32)(s32)
                randomGetRange(100, 200)
                )
                )
                ;
            }
            else
            {
                cfg.velocityY = lbl_803E0328 * (f32)(s32)
                randomGetRange(100, 200);
                cfg.velocityZ = lbl_803E041C * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0420 * (f32)(s32)
                randomGetRange(0x32, 100)
                )
                )
                ;
            }
            cfg.startPosX = lbl_803E03E0 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14) + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = lbl_803E0374 * (f32)(s32)
            randomGetRange(0xf, 0x14) + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0378 * (f32)(s32)
            randomGetRange(0x50, 0x8c)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0, 10) + 0xf;
            cfg.textureId = 0xc10;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x20080100;
            cfg.renderFlags = 0x4010020;
            cfg.colorWord0 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.colorWord1 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.colorWord2 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.overrideColor0 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.overrideColor1 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.overrideColor2 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7d1:
        if (spawnParams != NULL)
        {
            if (extraArgs == NULL)
            {
                cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0328 * (f32)(s32)
                randomGetRange(100, 200)
                )
                ;
                cfg.velocityZ = lbl_803E0424 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0418 * (f32)(s32)
                randomGetRange(100, 200)
                )
                )
                ;
            }
            else
            {
                cfg.velocityY = lbl_803E0328 * (f32)(s32)
                randomGetRange(100, 200);
                cfg.velocityZ = lbl_803E0424 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0370 * (f32)(s32)
                randomGetRange(100, 200)
                )
                )
                ;
            }
            cfg.startPosY = lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14) + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosX = lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14) + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x20080200;
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7d2:
        if (spawnParams != NULL)
        {
            if (*spawnParams != 0)
            {
                cfg.startPosY = lbl_803E0428;
                cfg.velocityX = lbl_803E0328 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.velocityY = lbl_803E03B0 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.velocityZ = lbl_803E0328 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
            }
            else
            {
                cfg.velocityX = lbl_803E0358 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.velocityY = lbl_803E036C * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.velocityZ = lbl_803E0358 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.startPosY = lbl_803E0314 * (f32)(s32)
                randomGetRange(100, 200);
            }
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(5, 10);
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk4;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80110;
            cfg.renderFlags = 0x20900;
        }
        break;
    case 0x7d3:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x480104;
            cfg.renderFlags = 0x8000080;
        }
        break;
    case 0x7d4:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x1480104;
            cfg.renderFlags = 0x8000080;
        }
        break;
    case 0x7d5:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x48010c;
            cfg.renderFlags = 0x8000080;
        }
        break;
    case 0x7d6:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x40480104;
            cfg.renderFlags = 0x8000080;
        }
        break;
    case 0x7d7:
        cfg.scale = lbl_803E03E4;
        cfg.lifetimeFrames = (uint)framesThisStep * 3;
        cfg.initialAlpha = 0x32;
        cfg.textureId = 0x605;
        cfg.behaviorFlags = 0x80200;
        cfg.renderFlags = 0x820;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x656a;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0xffff;
        break;
    case 0x7d8:
        cfg.startPosY = lbl_803E0434;
        cfg.startPosZ = lbl_803E0438;
        cfg.velocityZ = lbl_803E043C;
        cfg.scale = lbl_803E03B0 * (f32)(s32)
        randomGetRange(0x50, 0x58);
        cfg.lifetimeFrames = randomGetRange(0xd2, 0xe6);
        cfg.textureId = 0x7b;
        cfg.colorWord0 = 0xfaab;
        cfg.colorWord1 = 0xa9f;
        cfg.colorWord2 = 0x1d3;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0xff4b;
        cfg.initialAlpha = ',';
        cfg.behaviorFlags = 0x80004;
        cfg.renderFlags = 0x420820;
        if (spawnParams != NULL)
        {
            cfg.startPosX = lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + cfg.startPosX;
            cfg.startPosY = lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + cfg.startPosY;
            cfg.velocityZ = lbl_803E0440 * (f32)(s32)
            randomGetRange(0x5a, 0x6e);
            cfg.scale = lbl_803E035C;
            cfg.behaviorFlags |= 0x400000LL;
        }
        break;
    case 0x7d9:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 10;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = '@';
        cfg.behaviorFlags = 0x80104;
        cfg.renderFlags = 0x880;
        break;
    case 0x7da:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = 0x30;
        cfg.behaviorFlags = 0x80104;
        cfg.renderFlags = 0x880;
        break;
    case 0x7db:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = 0x30;
        cfg.behaviorFlags = 0x80104;
        cfg.renderFlags = 0x4000880;
        break;
    case 0x7dc:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = ((f32)((PartFxSpawnParams*)spawnParams)->unk4 / lbl_803E0444) * (lbl_803E033C * (f32)(s32)
            randomGetRange(5, 100)
            )
            ;
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.initialAlpha = *spawnParams + randomGetRange(0x20, 0x40);
            cfg.textureId = 0x605;
            cfg.behaviorFlags = 0x80104;
            cfg.renderFlags = 0x8a0;
            variant = ((PartFxSpawnParams*)spawnParams)->unk6;
            switch (variant)
            {
            case 0x160:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.overrideColor0 = 0x656a;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 5000;
                break;
            case 0xde:
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0x7fff;
                cfg.colorWord2 = 0;
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 5000;
                break;
            case 0x200:
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0;
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0x7fff;
                cfg.overrideColor2 = 5000;
                break;
            case 0xdd:
                cfg.colorWord0 = 40000;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0;
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0x7ffd;
                cfg.overrideColor2 = 0x4000;
                break;
            case 0xe0:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = 0x656a;
                cfg.overrideColor1 = 0;
                cfg.overrideColor2 = 0xffff;
                break;
            case 0xe4:
                cfg.colorWord0 = 40000;
                cfg.colorWord1 = 40000;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                break;
            case 0xdf:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = 12000;
                cfg.overrideColor1 = randomGetRange(0x4b0, 32000);
                cfg.overrideColor2 = 0xffff;
                break;
            case 0x7b:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0x7fff;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = randomGetRange(0x4b0, 32000);
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                break;
            default:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = 0x656a;
                cfg.overrideColor1 = 0;
                cfg.overrideColor2 = 0xffff;
                break;
            }
        }
        break;
    case 0x7dd:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
            randomGetRange(0, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = lbl_803E034C * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = randomGetRange(0x1e, 0x6e);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x3000000;
            cfg.renderFlags = 0x780880;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7de:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0340 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0340 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = lbl_803E0448 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = (int)
            (cfg.velocityY * (f32)(s32)
            randomGetRange(0x19, 100)
            )
            ;
            cfg.behaviorFlags = 0x1482000;
            cfg.renderFlags = 0x8400880;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7df:
        if (spawnParams != NULL)
        {
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8;
            vecRotateZXY(spawnParams, &cfg.velocityX);
            cfg.startPosX = cfg.startPosX + cfg.velocityX;
            cfg.startPosZ = cfg.startPosZ + cfg.velocityZ;
            cfg.velocityX = lbl_803E0324;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E044C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0310 * (f32)(s32)
            randomGetRange(0x4b, 100)
            )
            ;
            vecRotateZXY(spawnParams, &cfg.velocityX);
            cfg.scale = lbl_803E034C;
            cfg.lifetimeFrames = (int)
            (cfg.velocityY * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.initialAlpha = 0x7f;
            cfg.behaviorFlags = 0x3000000;
            cfg.renderFlags = 0x1600080;
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7e0:
        cfg.velocityX = lbl_803E0450 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityZ = lbl_803E0454 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E0408;
        cfg.lifetimeFrames = randomGetRange(0x28, 0x32);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = 0x5a;
        cfg.behaviorFlags = 0xa100000;
        cfg.renderFlags = 0x400000;
        break;
    case 0x7e1:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B0 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B0 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E042C;
            cfg.lifetimeFrames = (int)
            (cfg.velocityY * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.initialAlpha = 0x7f;
            cfg.behaviorFlags = 0x1080000;
            cfg.renderFlags = 0x5400080;
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7e2:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.velocityY = lbl_803E036C * (f32)(s32)
            randomGetRange(10, 0x50);
            cfg.velocityZ = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.scale = lbl_803E033C * (f32)(s32)
            randomGetRange(0xf, 0x1e);
            cfg.lifetimeFrames = randomGetRange(0x122, 0x15e);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x86000008;
            cfg.renderFlags = 0x1000000;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            if (((PartFxSpawnParams*)spawnParams)->unk2 == 1)
            {
                cfg.colorWord0 = (ushort)(randomGetRange(0x63bf, 0xffff) & 0xffff);
                cfg.overrideColor0 = cfg.colorWord0;
                cfg.colorWord1 = (ushort)(randomGetRange(0x3caf, 0xd8ef) & 0xffff);
                cfg.overrideColor1 = cfg.colorWord1;
                cfg.colorWord2 = (ushort)(randomGetRange(0x159f, 0x3caf) & 0xffff);
                cfg.overrideColor2 = cfg.colorWord2;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            else if (((PartFxSpawnParams*)spawnParams)->unk2 == 2)
            {
                cfg.colorWord0 = (ushort)(randomGetRange(0x3caf, 0x7fff) & 0xffff);
                cfg.overrideColor0 = cfg.colorWord0;
                cfg.colorWord1 = (ushort)(randomGetRange(0x7fff, 0xffff) & 0xffff);
                cfg.overrideColor1 = cfg.colorWord1;
                cfg.colorWord2 = (ushort)(randomGetRange(0x159f, 0x3caf) & 0xffff);
                cfg.overrideColor2 = cfg.colorWord2;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.behaviorFlags |= 0x800000LL;
                cfg.initialAlpha = 'A';
            }
            cfg.sourceVecX = randomGetRange(0, 0xffff);
            cfg.sourceVecY = randomGetRange(0, 0xffff);
            cfg.sourceVecX = randomGetRange(0, 0xffff);
            cfg.sourcePosY = (f32)(s32)
            randomGetRange(0xe6, 800);
            cfg.sourcePosZ = (f32)(s32)
            randomGetRange(0xe6, 800);
            cfg.sourcePosW = (f32)(s32)
            randomGetRange(0xe6, 800);
        }
        break;
    case 0x7e3:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.velocityY = lbl_803E0458 * (f32)(s32)
            randomGetRange(10, 0x50);
            cfg.velocityZ = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.scale = lbl_803E033C * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x122, 0x15e);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80008;
            cfg.renderFlags = 0x5000000;
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7e4:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.velocityY = lbl_803E036C * (f32)(s32)
            randomGetRange(10, 0x50);
            cfg.velocityZ = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.scale = lbl_803E045C * (f32)(s32)
            randomGetRange(5, 10);
            cfg.lifetimeFrames = randomGetRange(0x122, 0x15e);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80008;
            cfg.renderFlags = 0x5000100;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7e5:
        if (extraArgs != NULL)
        {
            cfg.velocityX = *extraArgs;
            cfg.velocityY = extraArgs[1];
            cfg.velocityZ = extraArgs[2];
        }
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x44, 100);
        cfg.lifetimeFrames = randomGetRange(100, 0x82);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = randomGetRange(0x28, 0x2c);
        cfg.behaviorFlags = 0x180100;
        cfg.renderFlags = 0x5080800;
        break;
    case 0x7e6:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.velocityX = *extraArgs;
                cfg.velocityY = extraArgs[1];
                cfg.velocityZ = extraArgs[2];
            }
            else
            {
                cfg.velocityX = lbl_803E0324;
                cfg.velocityY = lbl_803E0324;
                cfg.velocityZ = lbl_803E0324;
            }
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +cfg.velocityX;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E036C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            +cfg.velocityY;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +cfg.velocityZ;
            cfg.scale = (f32)(
                ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0460 * (f32)(s32)randomGetRange(0x44, 100))
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x2d, 0x5f);
            cfg.textureId = 0xc10;
            cfg.behaviorFlags = 0x180100;
            cfg.renderFlags = 0x5080000;
            if (*spawnParams == 3)
            {
                cfg.initialAlpha = randomGetRange(0x26, 0x2b);
                cfg.renderFlags = cfg.renderFlags | 0x800;
            }
            else
            {
                cfg.initialAlpha = randomGetRange(0x26, 0x2b);
            }
        }
        break;
    case 0x7e7:
        cfg.velocityX = lbl_803E03F8 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E03FC * (f32)(s32)
        randomGetRange(0, 100);
        cfg.velocityZ = lbl_803E0400 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E0404 * (f32)(s32)
        randomGetRange(0xf, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x96, 300);
        cfg.textureId = 0xc10;
        cfg.behaviorFlags = 0x8000100;
        cfg.renderFlags = 0x820;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0x4000;
        cfg.initialAlpha = '@';
        break;
    case 0x7e8:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 10;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = '@';
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x800;
        break;
    case 0x7e9:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = 0x0;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x800;
        break;
    case 0x7ea:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = 0x0;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x4000800;
        break;
    case 0x7eb:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            intVal = randomGetRange(0, 4);
            if (intVal != 0)
            {
                cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 * (
                    lbl_803E03C4 * (f32)(s32)
                randomGetRange(100, 0x6b)
                )
                )
                ;
                cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03C8 * (f32)(s32)
                randomGetRange(0x1c, 0x22)
                )
                ;
                cfg.initialAlpha = 0xff;
                cfg.behaviorFlags = 0x80080000;
                cfg.renderFlags = 0x8002820;
            }
            else
            {
                cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
                randomGetRange(0x1c, 0x22)
                )
                ;
                cfg.initialAlpha = 0xff;
                cfg.behaviorFlags = 0x80000;
                cfg.renderFlags = 0x8000820;
            }
            cfg.lifetimeFrames = randomGetRange(0x14, 0x1b);
            cfg.colorWord0 = 2000;
            cfg.colorWord1 = 2000;
            cfg.colorWord2 = 0x7fff;
            cfg.overrideColor0 = 7000;
            cfg.overrideColor1 = 0x7fff;
            cfg.overrideColor2 = 0xffff;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7ec:
        if (spawnParams != NULL)
        {
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E033C * (f32)(s32)
            randomGetRange(0x1e, 0x46)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x1e, 0x28);
            cfg.initialAlpha = randomGetRange(0x40, 0x7f);
            cfg.textureId = 0x605;
            cfg.behaviorFlags = (u32)randFn_80080100;
            cfg.renderFlags = 0x28a0;
            cfg.colorWord0 = 0;
            cfg.colorWord1 = 0x7fff;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = randomGetRange(40000, 0xffff);
            cfg.overrideColor1 = randomGetRange(0x4b0, 32000);
            cfg.overrideColor2 = 0xffff;
        }
        break;
    case 0x7ed:
        cfg.startPosY = lbl_803E0468;
        cfg.startPosZ = lbl_803E0324;
        cfg.velocityY = lbl_803E0424;
        cfg.scale = lbl_803E03B0 * (f32)(s32)
        randomGetRange(0x50, 0x58);
        cfg.lifetimeFrames = randomGetRange(0x50, 0x5a);
        cfg.textureId = 0x7b;
        cfg.colorWord0 = 0xfaab;
        cfg.colorWord1 = 0xa9f;
        cfg.colorWord2 = 0x1d3;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0xff4b;
        cfg.initialAlpha = ',';
        cfg.behaviorFlags = 0x200c0004;
        cfg.renderFlags = 0x420820;
        if (spawnParams != NULL)
        {
            cfg.startPosX = lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + cfg.startPosX;
            cfg.startPosY = lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + cfg.startPosY;
            cfg.velocityY = lbl_803E0358 * (f32)(s32)
            randomGetRange(0x5a, 0x6e);
            cfg.scale = lbl_803E035C;
            cfg.behaviorFlags |= 0x400000LL;
        }
        break;
    case 0x7ee:
        if (spawnParams != NULL)
        {
            cfg.scale = lbl_803E03B0 * (f32)(s32)
            randomGetRange(0x1e, 0x46);
            cfg.behaviorFlags = (u32)randFn_80080100;
            cfg.renderFlags = 0x8a0;
            cfg.colorWord0 = randomGetRange(40000, 0xffff);
            cfg.colorWord1 = randomGetRange(0x4b0, 32000);
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0;
            cfg.overrideColor1 = 0x7fff;
            cfg.overrideColor2 = 0xffff;
            cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 0x14;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityZ = lbl_803E0324;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8;
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.velocityX = lbl_803E0374;
            }
            else
            {
                cfg.velocityX = lbl_803E046C;
            }
            cfg.textureId = 0x605;
        }
        break;
    case 0x7ef:
    case 0x801:
    case 0x808:
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.velocityX = lbl_803E0470 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0474 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.velocityZ = lbl_803E0478 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E047C * (f32)(s32)
        randomGetRange(0x14, 100);
        if (effectId == 0x808)
        {
            cfg.scale = cfg.scale * lbl_803E0314;
        }
        cfg.lifetimeFrames = randomGetRange(0x14, 100);
        cfg.textureId = 0xc10;
        cfg.colorWord0 = 0xffe4;
        cfg.colorWord1 = 0x15;
        cfg.colorWord2 = 0xc67b;
        cfg.overrideColor0 = 0x1378;
        cfg.overrideColor1 = 0xfec0;
        cfg.overrideColor2 = 0x2d55;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080200;
        if ((effectId == 0x7ef) || (effectId == 0x808))
        {
            cfg.behaviorFlags |= 0x200001LL;
        }
        cfg.renderFlags = 0x4080820;
        break;
    case 0x7f0:
        cfg.velocityX = lbl_803E0480 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.velocityY = lbl_803E040C;
        cfg.scale = lbl_803E0484;
        cfg.lifetimeFrames = 0x73;
        cfg.textureId = 0x632;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x40180140;
        cfg.renderFlags = 0x820;
        break;
    case 0x7f1:
        cfg.velocityY = lbl_803E0380 * (f32)(s32)
        randomGetRange(8, 10);
        cfg.startPosY = lbl_803E0488;
        cfg.scale = lbl_803E0420 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x5a);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x5440820;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = '@';
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0xffff;
        break;
    case 0x7f2:
        cfg.startPosY = lbl_803E048C;
        cfg.velocityX = lbl_803E0340 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0368 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityZ = lbl_803E0340 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E0490;
        cfg.lifetimeFrames = randomGetRange(0xc, 0x3d);
        cfg.textureId = 0x605;
        cfg.colorWord0 = 0xffcc;
        cfg.colorWord1 = 0x23a8;
        cfg.colorWord2 = 0x325f;
        cfg.overrideColor0 = 0xfec1;
        cfg.overrideColor1 = 0x130c;
        cfg.overrideColor2 = 0xacf;
        cfg.initialAlpha = 0x80;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x80820;
        break;
    case 0x7f3:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = 0x37;
            cfg.textureId = 0xc86;
            cfg.initialAlpha = -0xd;
            cfg.behaviorFlags = 0x80100;
            cfg.renderFlags = 0x828;
            if (((PartFxSpawnParams*)spawnParams)->unk6 == 0)
            {
                cfg.scale = lbl_803E0368 * (f32)(s32)
                randomGetRange(10, 0x14);
                cfg.startPosY = lbl_803E048C;
                cfg.colorWord0 = 0xffcc;
                cfg.colorWord1 = 0x23a8;
                cfg.colorWord2 = 0x325f;
                cfg.overrideColor0 = 0xfec1;
                cfg.overrideColor1 = 0x130c;
                cfg.overrideColor2 = 0xacf;
            }
            if (((PartFxSpawnParams*)spawnParams)->unk6 == 1)
            {
                cfg.scale = lbl_803E040C * (f32)(s32)
                randomGetRange(10, 0x14);
                cfg.startPosY = lbl_803E0494;
                cfg.colorWord0 = 0x23a8;
                cfg.colorWord1 = 0xffcc;
                cfg.colorWord2 = 0x325f;
                cfg.overrideColor0 = 0x130c;
                cfg.overrideColor1 = 0xfec1;
                cfg.overrideColor2 = 0xacf;
            }
            if (((PartFxSpawnParams*)spawnParams)->unk6 == 2)
            {
                cfg.scale = lbl_803E0498 * (f32)(s32)
                randomGetRange(10, 0x14);
                cfg.startPosY = lbl_803E0494;
                cfg.colorWord0 = 0xffcc;
                cfg.colorWord1 = 0xffcc;
                cfg.colorWord2 = 0x325f;
                cfg.overrideColor0 = 0xfec1;
                cfg.overrideColor1 = 0xffcc;
                cfg.overrideColor2 = 0xacf;
            }
        }
        break;
    case 0x7f4:
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.velocityX = *extraArgs;
        cfg.velocityY = extraArgs[1];
        cfg.velocityZ = extraArgs[2];
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x50, 0x58);
        cfg.textureId = 0x7b;
        cfg.lifetimeFrames = 0x50;
        variant = ((PartFxSpawnParams*)spawnParams)->unk6;
        if ((variant == 0) || (variant == 3))
        {
            cfg.colorWord0 = 65000;
            cfg.colorWord1 = 10000;
            cfg.colorWord2 = 10000;
            cfg.lifetimeFrames = 0x55;
        }
        else if ((variant == 1) || (variant == 4))
        {
            cfg.colorWord0 = 0;
            cfg.colorWord1 = 65000;
            cfg.colorWord2 = 0;
        }
        else if ((variant == 2) || (variant == 5))
        {
            cfg.colorWord0 = 0;
            cfg.colorWord1 = 0;
            cfg.colorWord2 = 65000;
        }
        if (((PartFxSpawnParams*)spawnParams)->unk6 >= 3)
        {
            cfg.overrideColor0 = 65000;
            cfg.overrideColor1 = 65000;
            cfg.overrideColor2 = 0;
            cfg.lifetimeFrames = 0x5a;
        }
        else
        {
            cfg.overrideColor0 = (uint)cfg.colorWord0;
            cfg.overrideColor1 = (uint)cfg.colorWord1;
            cfg.overrideColor2 = (uint)cfg.colorWord2;
        }
        cfg.initialAlpha = ',';
        cfg.behaviorFlags = 0x80002;
        cfg.renderFlags = 0x420820;
        break;
    case 0x7f5:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E049C * (*(f32*)&lbl_803E031C * ((PartFxSpawnParams*)spawnParams)->unk8);
                cfg.behaviorFlags = 0x81080000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = 10;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0x81180000;
                cfg.renderFlags = 0x8400800;
                cfg.lifetimeFrames = randomGetRange(0x14, 0x1a) + 10;
            }
            cfg.velocityY = lbl_803E0314 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04A0 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0x5f5;
            cfg.initialAlpha = 0x80;
        }
        break;
    case 0x7f7:
        if (spawnParams != NULL)
        {
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(200, 300)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0x37, 0x41)
            )
            ;
            cfg.lifetimeFrames = (int)
            (((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0x1e, 0x28)
            )
            ;
            cfg.textureId = 0xc10;
            cfg.initialAlpha = 0x20;
            cfg.behaviorFlags = 0xc0080100;
            cfg.renderFlags = 0x4000800;
        }
        break;
    case 0x7f9:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03E4 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04A4 * (f32)(s32)
            randomGetRange(0, 100)
            )
            ;
            cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = randomGetRange(0x3c, 0x4b);
            cfg.textureId = 0xc73;
            cfg.colorWord0 = 5000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord1 = variant + 10000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord2 = variant + 20000;
            cfg.overrideColor0 = 0;
            cfg.overrideColor1 = randomGetRange(0, 10000);
            intVal = randomGetRange(0, 10000);
            cfg.overrideColor2 = intVal + 20000;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x1080004;
            cfg.renderFlags = 0x800a020;
        }
        break;
    case 0x7fa:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03E4 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04A8 * (f32)(s32)
            randomGetRange(0, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E040C * (f32)(s32)
            randomGetRange(10, 0x1e)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x32, 0x50);
            cfg.textureId = 0xc10;
            cfg.colorWord0 = 0xffcf;
            cfg.colorWord1 = 0xf987;
            cfg.colorWord2 = 0xfff8;
            cfg.overrideColor0 = 0x7a;
            cfg.overrideColor1 = 0x57d2;
            cfg.overrideColor2 = 0xffee;
            cfg.initialAlpha = randomGetRange(0x7b, 0xff);
            cfg.behaviorFlags = 0x40080204;
            cfg.renderFlags = 0x4080820;
        }
        break;
    case 0x7fb:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04AC * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04AC * (f32)(s32)
            randomGetRange(0x32, 0x96)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04AC * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = randomGetRange(0x28, 0x41);
            cfg.textureId = 0xc73;
            cfg.colorWord0 = 5000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord1 = variant + 10000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord2 = variant + 20000;
            cfg.overrideColor0 = 0;
            cfg.overrideColor1 = randomGetRange(0, 10000);
            intVal = randomGetRange(0, 10000);
            cfg.overrideColor2 = intVal + 20000;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x1080000;
            cfg.renderFlags = 0x800a020;
        }
        break;
    case 0x7fc:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03E4 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0310 * (f32)(s32)
            randomGetRange(10, 0x1e)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x32, 0x50);
            cfg.textureId = 0xc10;
            cfg.colorWord0 = 0xffcf;
            cfg.colorWord1 = 0xf987;
            cfg.colorWord2 = 0xfff8;
            cfg.overrideColor0 = 0x7a;
            cfg.overrideColor1 = 0x57d2;
            cfg.overrideColor2 = 0xffee;
            cfg.initialAlpha = randomGetRange(0x40, 0x7f);
            cfg.behaviorFlags = 0x40080200;
            cfg.renderFlags = 0x4000820;
        }
        break;
    case 0x7fd:
        cfg.startPosX = lbl_803E03E8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosY = lbl_803E03E8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosZ = lbl_803E03E8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.scale = lbl_803E04AC;
        cfg.lifetimeFrames = randomGetRange(8, 0xe);
        cfg.behaviorFlags = 0x110100;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = 0xdf;
        break;
    case 0x7fe:
        cfg.scale = lbl_803E04B0 * (f32)(s32)
        randomGetRange(100, 200);
        cfg.lifetimeFrames = randomGetRange(0x43, 100);
        cfg.textureId = 0xc10;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = 0x65a7;
        cfg.overrideColor1 = 0x433a;
        cfg.overrideColor2 = 0x1855;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x5000020;
        break;
    case 0x7ff:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0330 * (f32)(s32)
            randomGetRange(0, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E04B4 * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0x19, 100);
            cfg.lifetimeFrames = randomGetRange(0x28, 0xa5);
            cfg.textureId = 0xc73;
            cfg.colorWord0 = 15000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord1 = variant + 20000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord2 = variant + 30000;
            cfg.overrideColor0 = 10000;
            cfg.overrideColor1 = randomGetRange(10000, 20000);
            intVal = randomGetRange(0, 10000);
            cfg.overrideColor2 = intVal + 30000;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x1080000;
            cfg.renderFlags = 0x800a020;
        }
        break;
    case 0x800:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03E4 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04B8 * (f32)(s32)
            randomGetRange(10, 0x1e)
            )
            ;
            intVal = randomGetRange(0, 1) * 100;
            cfg.lifetimeFrames = randomGetRange(0x32, 0xb4) + intVal;
            cfg.textureId = 0xc10;
            cfg.colorWord0 = 0xffcf;
            cfg.colorWord1 = 0xf987;
            cfg.colorWord2 = 0xfff8;
            cfg.overrideColor0 = 0x7a;
            cfg.overrideColor1 = 0x57d2;
            cfg.overrideColor2 = 0xffee;
            cfg.initialAlpha = randomGetRange(0x40, 0x7f);
            cfg.behaviorFlags = 0x40080200;
            cfg.renderFlags = 0x4000820;
        }
        break;
    case 0x802:
        cfg.velocityX = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0350 * (f32)(s32)
        randomGetRange(0x28, 100);
        cfg.velocityZ = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E04B8 * (f32)(s32)
        randomGetRange(4, 10);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x23);
        cfg.textureId = 0xc10;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 50000;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 54000;
        cfg.overrideColor2 = 0x7fff;
        cfg.initialAlpha = randomGetRange(0x54, 0x7a);
        cfg.behaviorFlags = 0x1080200;
        cfg.renderFlags = 0x5000020;
        break;
    case 0x803:
        cfg.velocityX = lbl_803E04BC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E04BC * (f32)(s32)
        randomGetRange(0xffffffb5, 100);
        cfg.scale = lbl_803E036C;
        cfg.lifetimeFrames = 0x32;
        cfg.colorWord0 = 2000;
        cfg.colorWord1 = 2000;
        variant = randomGetRange(0xffffec78, 5000);
        cfg.colorWord2 = variant + 10000;
        cfg.overrideColor0 = 8000;
        cfg.overrideColor1 = 8000;
        intVal = randomGetRange(0xffffec78, 5000);
        cfg.overrideColor2 = intVal + 12000;
        cfg.textureId = 0x639;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1080004;
        cfg.renderFlags = 0x408028;
        break;
    case 0x804:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = 0xdf;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x480100;
            cfg.renderFlags = 0x8000000;
        }
        break;
    case 0x805:
        cfg.startPosY = lbl_803E0324;
        cfg.startPosZ = lbl_803E0324;
        cfg.scale = lbl_803E04B4 * (f32)(s32)
        randomGetRange(0x50, 0x58);
        cfg.lifetimeFrames = randomGetRange(100, 0x6e);
        cfg.textureId = 0x7b;
        if (((PartFxSpawnParams*)spawnParams)->unk2 == 0)
        {
            cfg.colorWord0 = 20000;
            cfg.colorWord1 = 20000;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 20000;
            cfg.overrideColor1 = 10000;
            cfg.overrideColor2 = 0xffff;
        }
        else
        {
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = 50000;
            cfg.colorWord2 = 0;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 50000;
            cfg.overrideColor2 = 0;
        }
        cfg.initialAlpha = ',';
        cfg.behaviorFlags = 0x80004;
        cfg.renderFlags = 0x420820;
        cfg.velocityX = *extraArgs;
        cfg.velocityY = extraArgs[1];
        cfg.velocityZ = extraArgs[2];
        break;
    case 0x806:
        cfg.startPosZ = lbl_803E0488;
        vecRotateZXY(sourceObj, &cfg.startPosX);
        cfg.velocityY = lbl_803E04C0;
        cfg.scale = lbl_803E0328 * (f32)(s32)
        randomGetRange(0x50, 0x5f);
        cfg.lifetimeFrames = 0xfa;
        cfg.textureId = 0x7b;
        cfg.colorWord0 = 0xfaab;
        cfg.colorWord1 = 0xa9f;
        cfg.colorWord2 = 0x1d3;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0xff4b;
        cfg.initialAlpha = randomGetRange(0x32, 0x36);
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x4000820;
        break;
    case 0x807:
        cfg.startPosZ = lbl_803E0488;
        vecRotateZXY(sourceObj, &cfg.startPosX);
        cfg.velocityY = lbl_803E04C4;
        cfg.scale = lbl_803E0328 * (f32)(s32)
        randomGetRange(0x50, 0x5f);
        cfg.lifetimeFrames = 0xfa;
        cfg.textureId = 0x7b;
        cfg.colorWord0 = 2000;
        cfg.colorWord1 = 2000;
        cfg.colorWord2 = 0xfaab;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0xff4b;
        cfg.initialAlpha = randomGetRange(0x32, 0x36);
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x4000820;
        break;
    case 0x809:
        cfg.velocityX = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0330 * (f32)(s32)
        randomGetRange(0x28, 100);
        cfg.velocityZ = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E036C * (f32)(s32)
        randomGetRange(4, 10);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x23);
        cfg.textureId = 0xc10;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 50000;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 58000;
        cfg.overrideColor2 = 38000;
        cfg.initialAlpha = randomGetRange(0xb8, 0xde);
        cfg.behaviorFlags = 0x1080200;
        cfg.renderFlags = 0x5000020;
        break;
    case 0x80a:
        cfg.velocityX = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E04AC * (f32)(s32)
        randomGetRange(0x28, 100);
        cfg.velocityZ = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E036C * (f32)(s32)
        randomGetRange(4, 10);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x23);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = randomGetRange(0x40, 0x7f);
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 0x4400800;
        break;
    case 0x80b:
        cfg.velocityX = lbl_803E0330 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0330 * (f32)(s32)
        randomGetRange(0x28, 100);
        cfg.velocityZ = lbl_803E0330 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E03B0 * (f32)(s32)
        randomGetRange(4, 10);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x23);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x600820;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = (u16)randomGetRange(0x7fff, 0xffff);
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        break;
    case 0x80c:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffff0, 0x10);
        cfg.startPosY = lbl_803E04C8;
        cfg.scale = lbl_803E0310 * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = randomGetRange(0xf, 0x14);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = randomGetRange(0x20, 0x40);
        cfg.behaviorFlags = 0x1080010;
        cfg.renderFlags = 0x4400800;
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
    ret = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, ret);
    return ret;
}


void Effect20_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB888 + (step = lbl_803E0310 * timeDelta);
    lbl_803DB888 = sum;
    if (sum > 1.0f) lbl_803DB888 = lbl_803E0314;
    sum = lbl_803DB88C + step;
    lbl_803DB88C = sum;
    if (sum > 1.0f) lbl_803DB88C = lbl_803E0320;
    lbl_803DD400 = lbl_803DD400 + (s32)framesThisStep * 0x64;
    if (lbl_803DD400 > 0x7fff) lbl_803DD400 = 0;
    lbl_803DD40C = mathSinf(lbl_803E0344 * (f32)(s16)lbl_803DD400 / lbl_803E0348);
    lbl_803DD404 = lbl_803DD404 + (s32)framesThisStep * 0x32;
    if (lbl_803DD404 > 0x7fff) lbl_803DD404 = 0;
    lbl_803DD408 = mathSinf(lbl_803E0344 * (f32)(s16)lbl_803DD404 / lbl_803E0348);
}

/* Trivial 4b 0-arg blr leaves. */
void Effect16_func03_nop(void);




















void Effect20_func03_nop(void)
{
}

void Effect20_release(void)
{
}

void Effect20_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int Checkpoint_func09_ret_1(void);


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
