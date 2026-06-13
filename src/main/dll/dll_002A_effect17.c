#include "main/audio/sfx_ids.h"
#include "main/dll/partfxspawn_struct.h"
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
            local_80 = ((PartFxSpawnParams*)param_3)->posX;
            local_7c = ((PartFxSpawnParams*)param_3)->posY;
            local_78 = ((PartFxSpawnParams*)param_3)->posZ;
            local_84 = *(undefined4*)&((PartFxSpawnParams*)param_3)->scale;
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
                local_64 = ((PartFxSpawnParams*)param_3)->posY;
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

extern s16 lbl_803DD414;
extern s16 lbl_803DD416;

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 mathSinf(f32 x);

extern f32 lbl_803DB858;
extern f32 lbl_803DB85C;
extern f32 lbl_803E01B8;
extern f32 lbl_803E01BC;
extern f32 lbl_803E01C8;
extern s32 lbl_803DD3D0;
extern s32 lbl_803DD3D4;
extern f32 lbl_803DD3D8;
extern f32 lbl_803DD3DC;
extern f32 lbl_803E0218;
extern f32 lbl_803E021C;

extern f32 lbl_803DB850;
extern f32 lbl_803DB854;
extern f32 lbl_803E01C4;
extern f32 lbl_803E01CC;
extern f32 lbl_803E01D0;
extern f32 lbl_803E01D4;
extern f32 lbl_803E01D8;
extern f32 lbl_803E01DC;
extern f32 lbl_803E01E0;
extern f32 lbl_803E01E4;
extern f32 lbl_803E01E8;
extern f32 lbl_803E01EC;
extern f32 lbl_803E01F0;
extern f32 lbl_803E01F4;
extern f32 lbl_803E01F8;
extern f32 lbl_803E01FC;
extern f32 lbl_803E0200;
extern f32 lbl_803E0204;
extern f32 lbl_803E0208;
extern f32 lbl_803E020C;

#pragma dont_inline on

#pragma dont_inline off

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

/* Append v to array pointed to by lbl_803DD41C, capped at 10 entries.
 * NOTE: stuck at ~78% ? instruction scheduling differs. */

void Effect17_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB858 + (step = lbl_803E01B8 * timeDelta);
    lbl_803DB858 = sum;
    if (sum > 1.0f) lbl_803DB858 = lbl_803E01BC;
    sum = lbl_803DB85C + step;
    lbl_803DB85C = sum;
    if (sum > 1.0f) lbl_803DB85C = lbl_803E01C8;
    lbl_803DD3D0 = lbl_803DD3D0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3D0 > 0x7fff) lbl_803DD3D0 = 0;
    lbl_803DD3DC = mathSinf(lbl_803E0218 * (f32)(s16)lbl_803DD3D0 / lbl_803E021C);
    lbl_803DD3D4 = lbl_803DD3D4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3D4 > 0x7fff) lbl_803DD3D4 = 0;
    lbl_803DD3D8 = mathSinf(lbl_803E0218 * (f32)(s16)lbl_803DD3D4 / lbl_803E021C);
}

void Effect18_func05(void);

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

int Effect17_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                    u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    lbl_803DB850 = lbl_803DB850 + lbl_803E01B8;
    if (lbl_803DB850 > 1.0f) lbl_803DB850 = lbl_803E01BC;
    lbl_803DB854 = lbl_803DB854 + lbl_803E01C4;
    if (lbl_803DB854 > 1.0f) lbl_803DB854 = lbl_803E01C8;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = spawnParams->posX;
        cfg.sourcePosZ = spawnParams->posY;
        cfg.sourcePosW = spawnParams->posZ;
        cfg.sourcePosX = spawnParams->scale;
        cfg.sourceVecZ = spawnParams->rotZ;
        cfg.sourceVecY = spawnParams->rotY;
        cfg.sourceVecX = spawnParams->rotX;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803E01CC;
    cfg.startPosY = lbl_803E01CC;
    cfg.startPosZ = lbl_803E01CC;
    cfg.velocityX = lbl_803E01CC;
    cfg.velocityY = lbl_803E01CC;
    cfg.velocityZ = lbl_803E01CC;
    cfg.scale = lbl_803E01CC;
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
    cfg.textureSetupFlags = 0;
    switch (effectId)
    {
    case 0x73a:
        cfg.velocityY = lbl_803E01D0 * (f32)(s32)
        randomGetRange(8, 0xa);
        if ((int)randomGetRange(0, 0x28) != 0)
        {
            cfg.scale = lbl_803E01B8 * (f32)(s32)
            randomGetRange(8, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x5a, 0x78);
        }
        else
        {
            cfg.scale = lbl_803E01B8 * (f32)(s32)
            randomGetRange(0x15, 0x29);
            cfg.lifetimeFrames = 0x1cc;
        }
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x1000020;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x7f;
        cfg.colorWord2 = 0x3fff;
        cfg.colorWord1 = 0x3fff;
        cfg.colorWord0 = 0x3fff;
        cfg.overrideColor2 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.startPosY = lbl_803E01D4;
        break;
    case 0x73b:
        cfg.velocityX = lbl_803E01D0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E01D0 * (f32)(s32)
        randomGetRange(8, 0x14);
        cfg.velocityZ = lbl_803E01D0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E01D8;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x3000200;
        cfg.renderFlags = 0x200020;
        cfg.textureId = 0x33;
        cfg.initialAlpha = 0xff;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor2 = randomGetRange(0, 0x8000);
        cfg.overrideColor1 = cfg.overrideColor2;
        cfg.startPosY = lbl_803E01DC;
        break;
    case 0x73d:
        cfg.startPosX = lbl_803E01BC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803E01D0 * (f32)(s32)
        randomGetRange(-0xa, 0x64);
        cfg.startPosZ = lbl_803E01BC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803E01E0 * (lbl_803E01E4 * (f32)(s32)
        randomGetRange(7, 9)
        )
        ;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x73e:
        cfg.startPosX = lbl_803E01BC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803E01D0 * (f32)(s32)
        randomGetRange(-0xa, 0x64);
        cfg.startPosZ = lbl_803E01BC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803E01E0 * (lbl_803E01E4 * (f32)(s32)
        randomGetRange(7, 9)
        )
        ;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdf;
        break;
    case 0x73f:
        if (extraArgs != 0)
        {
            cfg.startPosX = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa) + lbl_803E01E8;
            cfg.startPosY = lbl_803E01D0 * (f32)(s32)
            randomGetRange(-0xa, 0x64) + lbl_803E01EC;
            cfg.startPosZ = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa) + lbl_803E01F0;
        }
        else
        {
            cfg.startPosX = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.startPosY = lbl_803E01D0 * (f32)(s32)
            randomGetRange(-0xa, 0x64);
            cfg.startPosZ = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.scale = lbl_803E01F4 * (lbl_803E01E4 * (f32)(s32)
        randomGetRange(7, 9)
        )
        ;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x740:
        if (extraArgs != 0)
        {
            cfg.startPosX = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa) + lbl_803E01E8;
            cfg.startPosY = lbl_803E01D0 * (f32)(s32)
            randomGetRange(-0xa, 0x64) + lbl_803E01EC;
            cfg.startPosZ = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa) + lbl_803E01F0;
        }
        else
        {
            cfg.startPosX = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.startPosY = lbl_803E01D0 * (f32)(s32)
            randomGetRange(-0xa, 0x64);
            cfg.startPosZ = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.scale = lbl_803E01F4 * (lbl_803E01E4 * (f32)(s32)
        randomGetRange(7, 9)
        )
        ;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdf;
        break;
    case 0x741:
        if (spawnParams != 0) cfg.startPosY = spawnParams->posY;
        cfg.scale = lbl_803E01F8;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x50;
        cfg.initialAlpha = 0x60;
        cfg.behaviorFlags = 0x80110;
        cfg.textureId = 0x7b;
        cfg.linkGroup = 0x20;
        break;
    case 0x742:
        cfg.velocityZ = lbl_803E01FC;
        cfg.velocityX = lbl_803E0200 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0200 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E0204;
        cfg.lifetimeFrames = randomGetRange(0x46, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x82000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x3f4;
        break;
    case 0x743:
        cfg.velocityZ = lbl_803E01FC;
        cfg.velocityX = lbl_803E0200 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0200 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E0204;
        cfg.lifetimeFrames = randomGetRange(0x46, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x82000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x500;
        break;
    case 0x744:
        if ((int)randomGetRange(0, 4) == 4)
        {
            cfg.scale = lbl_803E0208;
            cfg.initialAlpha = 0x9b;
            cfg.behaviorFlags = 0x480000;
            cfg.lifetimeFrames = randomGetRange(0x1e, 0x28);
        }
        else
        {
            cfg.scale = lbl_803E020C;
            cfg.initialAlpha = 0x7d;
            cfg.behaviorFlags = 0x180000;
            cfg.lifetimeFrames = 0x50;
        }
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x88;
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

int Effect16_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);

void Effect17_func03_nop(void)
{
}

void Effect17_release(void)
{
}

void Effect17_initialise(void)
{
}

void Effect18_func03_nop(void);

#pragma dont_inline reset
#pragma dont_inline reset

#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
