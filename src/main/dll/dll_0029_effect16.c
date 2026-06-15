#include "main/dll/waterfxcfg_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"

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
FUN_800c8110(int sourceObj, undefined4 effectId, undefined2* spawnParams, uint spawnFlags, u8 modelId,
             int useWorldOffset)
{
    undefined4 result;
    uint rngRoll;
    int cfg[3];
    undefined2 srcRotX;
    undefined2 srcRotY;
    undefined2 srcRotZ;
    undefined4 srcScale;
    float srcPosX;
    float srcPosY;
    float srcPosZ;
    float velX;
    float velY;
    float velZ;
    float startPosX;
    float startPosY;
    float startPosZ;
    float scale;
    undefined2 linkGroup;
    undefined2 textureId;
    uint behaviorFlags;
    undefined4 renderFlags;
    undefined4 overrideColor0;
    uint overrideColor1;
    uint overrideColor2;
    undefined2 colorWord0;
    undefined2 colorWord1;
    undefined2 colorWord2;
    u8 effectIdByte;
    u8 initialAlpha;
    u8 textureSetupFlags;
    u8 modelIdByte;
    undefined4 local_30;
    uint rngTmp0;
    undefined4 local_28;
    uint rngTmp1;
    undefined4 local_20;
    uint rngTmp2;
    undefined4 local_18;
    uint rngTmp3;

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
    if (sourceObj == 0)
    {
        result = 0xffffffff;
    }
    else
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            if (spawnParams == (undefined2*)0x0)
            {
                return 0xffffffff;
            }
            srcPosX = ((PartFxSpawnParams*)spawnParams)->posX;
            srcPosY = ((PartFxSpawnParams*)spawnParams)->posY;
            srcPosZ = ((PartFxSpawnParams*)spawnParams)->posZ;
            srcScale = *(undefined4*)&((PartFxSpawnParams*)spawnParams)->scale;
            srcRotZ = ((PartFxSpawnParams*)spawnParams)->unk4;
            srcRotY = ((PartFxSpawnParams*)spawnParams)->unk2;
            srcRotX = *spawnParams;
            modelIdByte = modelId;
        }
        behaviorFlags = 0;
        renderFlags = 0;
        effectIdByte = (undefined)effectId;
        startPosX = lbl_803E0E4C;
        startPosY = lbl_803E0E4C;
        startPosZ = lbl_803E0E4C;
        velX = lbl_803E0E4C;
        velY = lbl_803E0E4C;
        velZ = lbl_803E0E4C;
        scale = lbl_803E0E4C;
        cfg[2] = 0;
        cfg[1] = 0xffffffff;
        initialAlpha = 0xff;
        textureSetupFlags = 0;
        textureId = 0;
        colorWord0 = 0xffff;
        colorWord1 = 0xffff;
        colorWord2 = 0xffff;
        overrideColor0 = 0xffff;
        overrideColor1 = 0xffff;
        overrideColor2 = 0xffff;
        linkGroup = 0;
        cfg[0] = sourceObj;
        switch (effectId)
        {
        case 0x73a:
            rngTmp0 = randomGetRange(8, 10);
            velY = lbl_803E0E50 * (f32)(s32)
            rngTmp0;
            rngRoll = randomGetRange(0, 0x28);
            if (rngRoll == 0)
            {
                rngTmp0 = randomGetRange(0x15, 0x29);
                scale = lbl_803E0E38 *
                    (f32)(s32)
                rngTmp0;
                cfg[2] = 0x1cc;
            }
            else
            {
                rngTmp0 = randomGetRange(8, 0x14);
                scale = lbl_803E0E38 *
                    (f32)(s32)
                rngTmp0;
                cfg[2] = randomGetRange(0x5a, 0x78);
            }
            behaviorFlags = 0x80180200;
            renderFlags = 0x1000020;
            textureId = 0xc0b;
            initialAlpha = 0x7f;
            colorWord2 = 0x3fff;
            colorWord1 = 0x3fff;
            colorWord0 = 0x3fff;
            overrideColor2 = 0xffff;
            overrideColor1 = 0xffff;
            overrideColor0 = 0xffff;
            startPosY = lbl_803E0E54;
            break;
        case 0x73b:
            rngTmp0 = randomGetRange(0xffffffec, 0x14);
            velX = lbl_803E0E50 * (f32)(s32)
            rngTmp0;
            rngTmp1 = randomGetRange(8, 0x14);
            velY = lbl_803E0E50 * (f32)(s32)
            rngTmp1;
            rngTmp2 = randomGetRange(0xffffffec, 0x14);
            velZ = lbl_803E0E50 * (f32)(s32)
            rngTmp2;
            scale = lbl_803E0E58;
            cfg[2] = 0x32;
            behaviorFlags = 0x3000200;
            renderFlags = 0x200020;
            textureId = 0x33;
            initialAlpha = 0xff;
            colorWord0 = 0xffff;
            colorWord1 = 0xffff;
            colorWord2 = 0xffff;
            overrideColor0 = 0xffff;
            overrideColor1 = randomGetRange(0, 0x8000);
            startPosY = lbl_803E0E5C;
            overrideColor2 = overrideColor1;
            break;
        default:
            return 0xffffffff;
        case 0x73d:
            rngTmp2 = randomGetRange(0xfffffff6, 10);
            startPosX = lbl_803E0E3C * (f32)(s32)
            rngTmp2;
            rngTmp1 = randomGetRange(0xfffffff6, 100);
            startPosY = lbl_803E0E50 * (f32)(s32)
            rngTmp1;
            rngTmp0 = randomGetRange(0xfffffff6, 10);
            startPosZ = lbl_803E0E3C * (f32)(s32)
            rngTmp0;
            rngTmp3 = randomGetRange(7, 9);
            scale = lbl_803E0E60 *
                lbl_803E0E64 * (f32)(s32)
            rngTmp3;
            cfg[2] = 0x3c;
            behaviorFlags = 0x80100;
            textureSetupFlags = 0x10;
            textureId = 0xde;
            break;
        case 0x73e:
            rngTmp3 = randomGetRange(0xfffffff6, 10);
            startPosX = lbl_803E0E3C * (f32)(s32)
            rngTmp3;
            rngTmp2 = randomGetRange(0xfffffff6, 100);
            startPosY = lbl_803E0E50 * (f32)(s32)
            rngTmp2;
            rngTmp1 = randomGetRange(0xfffffff6, 10);
            startPosZ = lbl_803E0E3C * (f32)(s32)
            rngTmp1;
            rngTmp0 = randomGetRange(7, 9);
            scale = lbl_803E0E60 *
                lbl_803E0E64 * (f32)(s32)
            rngTmp0;
            cfg[2] = 0x3c;
            behaviorFlags = 0x80100;
            textureSetupFlags = 0x10;
            textureId = 0xdf;
            break;
        case 0x73f:
            if (useWorldOffset == 0)
            {
                rngTmp3 = randomGetRange(0xfffffff6, 10);
                startPosX = lbl_803E0E3C *
                    (f32)(s32)
                rngTmp3;
                rngTmp2 = randomGetRange(0xfffffff6, 100);
                startPosY = lbl_803E0E50 *
                    (f32)(s32)
                rngTmp2;
                rngTmp1 = randomGetRange(0xfffffff6, 10);
                rngTmp1 = rngTmp1 ^ 0x80000000;
                startPosZ = lbl_803E0E3C *
                    (f32)(s32)
                rngTmp1;
            }
            else
            {
                rngTmp3 = randomGetRange(0xfffffff6, 10);
                startPosX = lbl_803E0E3C *
                    (f32)(s32)
                rngTmp3 +
                    lbl_803E0E68;
                rngTmp2 = randomGetRange(0xfffffff6, 100);
                startPosY = lbl_803E0E50 *
                    (f32)(s32)
                rngTmp2 +
                    lbl_803E0E6C;
                rngTmp1 = randomGetRange(0xfffffff6, 10);
                rngTmp1 = rngTmp1 ^ 0x80000000;
                startPosZ = lbl_803E0E3C *
                    (f32)(s32)
                rngTmp1 +
                    lbl_803E0E70;
            }
            local_28 = 0x43300000;
            rngTmp3 = randomGetRange(7, 9);
            scale = lbl_803E0E74 *
                lbl_803E0E64 * (f32)(s32)
            rngTmp3;
            cfg[2] = 0x3c;
            behaviorFlags = 0x80100;
            textureSetupFlags = 0x10;
            textureId = 0xde;
            break;
        case 0x740:
            if (useWorldOffset == 0)
            {
                rngTmp3 = randomGetRange(0xfffffff6, 10);
                startPosX = lbl_803E0E3C *
                    (f32)(s32)
                rngTmp3;
                rngTmp2 = randomGetRange(0xfffffff6, 100);
                startPosY = lbl_803E0E50 *
                    (f32)(s32)
                rngTmp2;
                rngTmp1 = randomGetRange(0xfffffff6, 10);
                rngTmp1 = rngTmp1 ^ 0x80000000;
                startPosZ = lbl_803E0E3C *
                    (f32)(s32)
                rngTmp1;
            }
            else
            {
                rngTmp3 = randomGetRange(0xfffffff6, 10);
                startPosX = lbl_803E0E3C *
                    (f32)(s32)
                rngTmp3 +
                    lbl_803E0E68;
                rngTmp2 = randomGetRange(0xfffffff6, 100);
                startPosY = lbl_803E0E50 *
                    (f32)(s32)
                rngTmp2 +
                    lbl_803E0E6C;
                rngTmp1 = randomGetRange(0xfffffff6, 10);
                rngTmp1 = rngTmp1 ^ 0x80000000;
                startPosZ = lbl_803E0E3C *
                    (f32)(s32)
                rngTmp1 +
                    lbl_803E0E70;
            }
            local_28 = 0x43300000;
            rngTmp3 = randomGetRange(7, 9);
            scale = lbl_803E0E74 *
                lbl_803E0E64 * (f32)(s32)
            rngTmp3;
            cfg[2] = 0x3c;
            behaviorFlags = 0x80100;
            textureSetupFlags = 0x10;
            textureId = 0xdf;
            break;
        case 0x741:
            if (spawnParams != (undefined2*)0x0)
            {
                startPosY = ((PartFxSpawnParams*)spawnParams)->posY;
            }
            scale = lbl_803E0E78;
            cfg[2] = randomGetRange(0, 0x1e);
            cfg[2] = cfg[2] + 0x50;
            initialAlpha = 0x60;
            behaviorFlags = 0x80110;
            textureId = 0x7b;
            textureSetupFlags = 0x20;
            break;
        case 0x742:
            velZ = lbl_803E0E7C;
            rngTmp3 = randomGetRange(0xffffffec, 0x14);
            velX = lbl_803E0E80 * (f32)(s32)
            rngTmp3;
            rngTmp2 = randomGetRange(0xffffffec, 0x14);
            velY = lbl_803E0E80 * (f32)(s32)
            rngTmp2;
            scale = lbl_803E0E84;
            cfg[2] = randomGetRange(0x46, 0x50);
            initialAlpha = 0xff;
            behaviorFlags = 0x82000104;
            renderFlags = 0x400;
            textureId = 0x3f4;
            break;
        case 0x743:
            velZ = lbl_803E0E7C;
            rngTmp3 = randomGetRange(0xffffffec, 0x14);
            velX = lbl_803E0E80 * (f32)(s32)
            rngTmp3;
            rngTmp2 = randomGetRange(0xffffffec, 0x14);
            velY = lbl_803E0E80 * (f32)(s32)
            rngTmp2;
            scale = lbl_803E0E84;
            cfg[2] = randomGetRange(0x46, 0x50);
            initialAlpha = 0xff;
            behaviorFlags = 0x82000104;
            renderFlags = 0x400;
            textureId = 0x500;
            break;
        case 0x744:
            rngRoll = randomGetRange(0, 4);
            if (rngRoll == 4)
            {
                scale = lbl_803E0E88;
                initialAlpha = 0x9b;
                behaviorFlags = 0x480000;
                cfg[2] = randomGetRange(0x1e, 0x28);
            }
            else
            {
                scale = lbl_803E0E8C;
                initialAlpha = 0x7d;
                behaviorFlags = 0x180000;
                cfg[2] = 0x50;
            }
            renderFlags = 0x2000000;
            textureId = 0x88;
        }
        behaviorFlags = behaviorFlags | spawnFlags;
        if (((behaviorFlags & 1) != 0) && ((behaviorFlags & 2) != 0))
        {
            behaviorFlags = behaviorFlags ^ 2;
        }
        if ((behaviorFlags & 1) != 0)
        {
            if ((spawnFlags & 0x200000) == 0)
            {
                if (cfg[0] != 0)
                {
                    startPosX = startPosX + *(float*)(cfg[0] + 0x18);
                    startPosY = startPosY + *(float*)(cfg[0] + 0x1c);
                    startPosZ = startPosZ + *(float*)(cfg[0] + 0x20);
                }
            }
            else
            {
                startPosX = startPosX + srcPosX;
                startPosY = startPosY + srcPosY;
                startPosZ = startPosZ + srcPosZ;
            }
        }
        result = (*gExpgfxInterface)->spawnEffect(cfg, 0xffffffff, effectId, 0);
    }
    return result;
}

undefined4 FUN_800c9030(uint key, int* outIndex)
{
    int hi;
    int lo;
    int mid;

    *outIndex = -1;
    if ((int)key < 0)
    {
        return 0;
    }
    hi = DAT_803de090 + -1;
    lo = 0;
    while (true)
    {
        while (true)
        {
            if (hi < lo)
            {
                *outIndex = -1;
                return 0;
            }
            mid = hi + lo >> 1;
            if (key <= (uint)(&DAT_8039d0b8)[mid * 2]) break;
            lo = mid + 1;
        }
        if ((uint)(&DAT_8039d0b8)[mid * 2] <= key) break;
        hi = mid + -1;
    }
    *outIndex = mid;
    return (&DAT_8039d0bc)[mid * 2];
}

extern s16 lbl_803DD414;
extern s16 lbl_803DD416;

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 mathSinf(f32 x);

extern f32 lbl_803DB848;
extern f32 lbl_803DB84C;
extern f32 lbl_803E00A8;
extern f32 lbl_803E00AC;
extern f32 lbl_803E00B0;
extern f32 lbl_803E00B8;
extern s32 lbl_803DD3C0;
extern s32 lbl_803DD3C4;
extern f32 lbl_803DD3C8;
extern f32 lbl_803DD3CC;
extern f32 lbl_803E0108;
extern f32 lbl_803E010C;

extern f32 lbl_803DB840;
extern f32 lbl_803DB844;
extern f32 lbl_803E00B4;
extern f32 lbl_803E00BC;
extern f32 lbl_803E00C0;
extern f32 lbl_803E00C4;
extern f32 lbl_803E00C8;
extern f32 lbl_803E00CC;
extern f32 lbl_803E00D0;
extern f32 lbl_803E00D4;
extern f32 lbl_803E00D8;
extern f32 lbl_803E00DC;
extern f32 lbl_803E00E0;
extern f32 lbl_803E00E4;
extern f32 lbl_803E00E8;
extern f32 lbl_803E00EC;
extern f32 lbl_803E00F0;
extern f32 lbl_803E00F4;
extern f32 lbl_803E00F8;
extern WaterfxCfg lbl_8039C410;

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

void Effect16_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB848 + (step = lbl_803E00A8 * timeDelta);
    lbl_803DB848 = sum;
    if (sum > 1.0f) lbl_803DB848 = lbl_803E00AC;
    sum = lbl_803DB84C + step;
    lbl_803DB84C = sum;
    if (sum > 1.0f) lbl_803DB84C = lbl_803E00B8;
    lbl_803DD3C0 = lbl_803DD3C0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3C0 > 0x7fff) lbl_803DD3C0 = 0;
    lbl_803DD3CC = mathSinf(lbl_803E0108 * (f32)(s16)lbl_803DD3C0 / lbl_803E010C);
    lbl_803DD3C4 = lbl_803DD3C4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3C4 > 0x7fff) lbl_803DD3C4 = 0;
    lbl_803DD3C8 = mathSinf(lbl_803E0108 * (f32)(s16)lbl_803DD3C4 / lbl_803E010C);
}

void Effect17_func05(void);

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

int Effect16_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                    u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    lbl_803DB840 = lbl_803DB840 + lbl_803E00A8;
    if (lbl_803DB840 > 1.0f) lbl_803DB840 = lbl_803E00AC;
    lbl_803DB844 = lbl_803DB844 + lbl_803E00B4;
    if (lbl_803DB844 > 1.0f) lbl_803DB844 = lbl_803E00B8;
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
    cfg.startPosX = lbl_803E00BC;
    cfg.startPosY = lbl_803E00BC;
    cfg.startPosZ = lbl_803E00BC;
    cfg.velocityX = lbl_803E00BC;
    cfg.velocityY = lbl_803E00BC;
    cfg.velocityZ = lbl_803E00BC;
    cfg.scale = lbl_803E00BC;
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
    case 0x6d7:
        if (spawnParams == 0)
        {
            lbl_8039C410.posX = lbl_803E00BC;
            lbl_8039C410.posY = lbl_803E00BC;
            lbl_8039C410.posZ = lbl_803E00BC;
            lbl_8039C410.scale = lbl_803E00B0;
            lbl_8039C410.rotX = 0;
            lbl_8039C410.rotY = 0;
            lbl_8039C410.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C410;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803E00A8 * (f32)(s32)
        randomGetRange(0xa, 0x1e);
        cfg.lifetimeFrames = randomGetRange(0x118, 0x12c);
        cfg.behaviorFlags = 0x80180214;
        cfg.textureId = 0x5c;
        break;
    case 0x6d8:
        if (spawnParams == 0)
        {
            lbl_8039C410.posX = lbl_803E00BC;
            lbl_8039C410.posY = lbl_803E00BC;
            lbl_8039C410.posZ = lbl_803E00BC;
            lbl_8039C410.scale = lbl_803E00B0;
            lbl_8039C410.rotX = 0;
            lbl_8039C410.rotY = 0;
            lbl_8039C410.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C410;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803E00A8 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x118, 0x12c);
        cfg.behaviorFlags = 0x80180214;
        cfg.textureId = 0xc79;
        break;
    case 0x6d9:
        cfg.velocityX = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.scale = lbl_803E00C4 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80114;
        cfg.renderFlags = 0x10008;
        cfg.textureId = 0x157;
        break;
    case 0x6da:
        cfg.scale = lbl_803E00C8;
        cfg.lifetimeFrames = 0x14;
        cfg.behaviorFlags = 0x80480210;
        cfg.textureId = 0xc79;
        cfg.initialAlpha = 0x9d;
        break;
    case 0x6db:
        if (extraArgs != 0)
        {
            cfg.velocityX = lbl_803E00CC * (f32)(s32)
            randomGetRange(-0x96, 0x96);
            cfg.velocityZ = lbl_803E00CC * (f32)(s32)
            randomGetRange(-0x96, 0x96);
            cfg.velocityY = lbl_803E00CC * (f32)(s32)
            randomGetRange(0x64, 0x190);
            cfg.scale = lbl_803E00D0 * (f32)(s32)
            randomGetRange(0xf, 0x14);
            cfg.lifetimeFrames = 0x32;
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = 0xffff;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0;
            cfg.overrideColor2 = 0;
            cfg.behaviorFlags = 0x3000200;
            cfg.renderFlags = 0x200022;
        }
        else
        {
            cfg.scale = lbl_803E00D4 * (f32)(s32)
            randomGetRange(0xf, 0x14);
            cfg.lifetimeFrames = 1;
            cfg.behaviorFlags = 0x80000;
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc79;
        break;
    case 0x6dc:
        cfg.velocityY = lbl_803E00D8 * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E00A8 * (f32)(s32)
        randomGetRange(0x12, 0x1c);
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.behaviorFlags = 0x80180200;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0xff;
        break;
    case 0x6dd:
        cfg.scale = lbl_803E00AC;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xc3;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x580110;
        cfg.textureId = 0xc79;
        break;
    case 0x6de:
        cfg.velocityX = lbl_803E00DC * lbl_803DB840 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityZ = lbl_803E00DC * lbl_803DB840 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803E00DC * lbl_803DB840 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.initialAlpha = 0x7d;
        cfg.scale = lbl_803E00E0 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x300000;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = 0xc79;
        break;
    case 0x6df:
        cfg.velocityX = lbl_803E00CC * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityZ = lbl_803E00CC * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803E00CC * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803E00E4 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.behaviorFlags = 0x80200;
        cfg.renderFlags = 0x100000;
        cfg.lifetimeFrames = 0x64;
        cfg.textureId = 0x125;
        break;
    case 0x6e0:
        cfg.velocityX = lbl_803E00E8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityZ = lbl_803E00E8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803E00E8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803E00E0 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.behaviorFlags = 0x2000200;
        cfg.renderFlags = 0x300000;
        cfg.lifetimeFrames = 0x1e;
        cfg.textureId = 0x33;
        break;
    case 0x6e1:
        cfg.lifetimeFrames = 0x46;
        cfg.scale = lbl_803E00EC;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = 0xff00;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0xff00;
        cfg.behaviorFlags = 0x100100;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = 0x7f;
        cfg.textureId = 0x72;
        break;
    case 0x6f2:
        if (spawnParams == 0)
        {
            lbl_8039C410.posX = lbl_803E00BC;
            lbl_8039C410.posY = lbl_803E00BC;
            lbl_8039C410.posZ = lbl_803E00BC;
            lbl_8039C410.scale = lbl_803E00B0;
            lbl_8039C410.rotX = 0;
            lbl_8039C410.rotY = 0;
            lbl_8039C410.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C410;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-7, 3);
        cfg.velocityY = lbl_803E00C0 * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.velocityZ = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-7, 3);
        cfg.scale = lbl_803E00F0 * (f32)(s32)
        randomGetRange(0x32, 0x3c);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x5a);
        cfg.behaviorFlags = 0x580004;
        cfg.renderFlags = 0x400000;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0d;
        break;
    case 0x6f3:
        if (spawnParams == 0)
        {
            lbl_8039C410.posX = lbl_803E00BC;
            lbl_8039C410.posY = lbl_803E00BC;
            lbl_8039C410.posZ = lbl_803E00BC;
            lbl_8039C410.scale = lbl_803E00B0;
            lbl_8039C410.rotX = 0;
            lbl_8039C410.rotY = 0;
            lbl_8039C410.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C410;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803E00F4 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x58f;
        break;
    case 0x6f4:
        if (spawnParams == 0)
        {
            lbl_8039C410.posX = lbl_803E00BC;
            lbl_8039C410.posY = lbl_803E00BC;
            lbl_8039C410.posZ = lbl_803E00BC;
            lbl_8039C410.scale = lbl_803E00B0;
            lbl_8039C410.rotX = 0;
            lbl_8039C410.rotY = 0;
            lbl_8039C410.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C410;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803E00F8 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x4800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x590;
        break;
    case 0x6f5:
        if (spawnParams == 0)
        {
            lbl_8039C410.posX = lbl_803E00BC;
            lbl_8039C410.posY = lbl_803E00BC;
            lbl_8039C410.posZ = lbl_803E00BC;
            lbl_8039C410.scale = lbl_803E00B0;
            lbl_8039C410.rotX = 0;
            lbl_8039C410.rotY = 0;
            lbl_8039C410.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C410;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803E00F4 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x403;
        break;
    case 0x6f6:
        if (spawnParams == 0)
        {
            lbl_8039C410.posX = lbl_803E00BC;
            lbl_8039C410.posY = lbl_803E00BC;
            lbl_8039C410.posZ = lbl_803E00BC;
            lbl_8039C410.scale = lbl_803E00B0;
            lbl_8039C410.rotX = 0;
            lbl_8039C410.rotY = 0;
            lbl_8039C410.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C410;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803E00F8 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x4800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x404;
        break;
    case 0x6f7:
        if (spawnParams == 0)
        {
            lbl_8039C410.posX = lbl_803E00BC;
            lbl_8039C410.posY = lbl_803E00BC;
            lbl_8039C410.posZ = lbl_803E00BC;
            lbl_8039C410.scale = lbl_803E00B0;
            lbl_8039C410.rotX = 0;
            lbl_8039C410.rotY = 0;
            lbl_8039C410.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C410;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803E00F4 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x405;
        break;
    case 0x6f8:
        if (spawnParams == 0)
        {
            lbl_8039C410.posX = lbl_803E00BC;
            lbl_8039C410.posY = lbl_803E00BC;
            lbl_8039C410.posZ = lbl_803E00BC;
            lbl_8039C410.scale = lbl_803E00B0;
            lbl_8039C410.rotX = 0;
            lbl_8039C410.rotY = 0;
            lbl_8039C410.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C410;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803E00F8 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x406;
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

int Effect15_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId, f32* extraArgs);

void Effect16_func03_nop(void)
{
}

void Effect16_release(void)
{
}

void Effect16_initialise(void)
{
}

void Effect15_func05_nop(void);

#pragma dont_inline reset
#pragma dont_inline reset

