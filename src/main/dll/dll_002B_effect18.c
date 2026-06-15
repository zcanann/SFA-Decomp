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

extern f32 lbl_803DB868;
extern f32 lbl_803DB86C;
extern f32 lbl_803E0220;
extern f32 lbl_803E0224;
extern f32 lbl_803E0228;
extern f32 lbl_803E0230;
extern s32 lbl_803DD3E0;
extern s32 lbl_803DD3E4;
extern f32 lbl_803DD3E8;
extern f32 lbl_803DD3EC;
extern f32 lbl_803E02D0;
extern f32 lbl_803E02D4;

extern f32 lbl_803DB860;
extern f32 lbl_803DB864;
extern f32 lbl_803E022C;
extern f32 lbl_803E0234;
extern f32 lbl_803E0238;
extern f32 lbl_803E023C;
extern f32 lbl_803E0240;
extern f32 lbl_803E0244;
extern f32 lbl_803E0248;
extern f32 lbl_803E024C;
extern f32 lbl_803E0250;
extern f32 lbl_803E0254;
extern f32 lbl_803E0258;
extern f32 lbl_803E025C;
extern f32 lbl_803E0260;
extern f32 lbl_803E0264;
extern f32 lbl_803E0268;
extern f32 lbl_803E026C;
extern f32 lbl_803E0270;
extern f32 lbl_803E0274;
extern f32 lbl_803E0278;
extern f32 lbl_803E027C;
extern f32 lbl_803E0280;
extern f32 lbl_803E0284;
extern f32 lbl_803E0288;
extern f32 lbl_803E028C;
extern f32 lbl_803E0290;
extern f32 lbl_803E0294;
extern f32 lbl_803E0298;
extern f32 lbl_803E029C;
extern f32 lbl_803E02A0;
extern f32 lbl_803E02A4;
extern f32 lbl_803E02A8;
extern f32 lbl_803E02AC;
extern f32 lbl_803E02B0;
extern f32 lbl_803E02B4;
extern f32 lbl_803E02B8;
extern f32 sqrtf(f32);

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

void Effect18_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB868 + (step = lbl_803E0220 * timeDelta);
    lbl_803DB868 = sum;
    if (sum > 1.0f) lbl_803DB868 = lbl_803E0224;
    sum = lbl_803DB86C + step;
    lbl_803DB86C = sum;
    if (sum > 1.0f) lbl_803DB86C = lbl_803E0230;
    lbl_803DD3E0 = lbl_803DD3E0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3E0 > 0x7fff) lbl_803DD3E0 = 0;
    lbl_803DD3EC = mathSinf(lbl_803E02D0 * (f32)(s16)lbl_803DD3E0 / lbl_803E02D4);
    lbl_803DD3E4 = lbl_803DD3E4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3E4 > 0x7fff) lbl_803DD3E4 = 0;
    lbl_803DD3E8 = mathSinf(lbl_803E02D0 * (f32)(s16)lbl_803DD3E4 / lbl_803E02D4);
}

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

int Effect18_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                    u8 modelId, void* extraArgs)
{
    int spawnResult;
    f32 thr;
    PartFxSpawn cfg;

    lbl_803DB860 = lbl_803DB860 + lbl_803E0220;
    if (lbl_803DB860 > 1.0f) lbl_803DB860 = lbl_803E0224;
    lbl_803DB864 = lbl_803DB864 + lbl_803E022C;
    if (lbl_803DB864 > 1.0f) lbl_803DB864 = lbl_803E0230;
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
    cfg.startPosX = lbl_803E0234;
    cfg.startPosY = lbl_803E0234;
    cfg.startPosZ = lbl_803E0234;
    cfg.velocityX = lbl_803E0234;
    cfg.velocityY = lbl_803E0234;
    cfg.velocityZ = lbl_803E0234;
    cfg.scale = lbl_803E0234;
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
    case 0x708:
        cfg.velocityX = lbl_803E0238 * (f32)(s32)
        randomGetRange(0xa, 0x19);
        cfg.scale = lbl_803E0224;
        cfg.lifetimeFrames = randomGetRange(0x15e, 0x190);
        cfg.behaviorFlags = 0xa100100;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x62;
        break;
    case 0x709:
        cfg.velocityY = lbl_803E023C * (f32)(s32)
        randomGetRange(0xa, 0x14);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityY = -cfg.velocityY;
        cfg.scale = lbl_803E0220;
        cfg.lifetimeFrames = 0x78;
        cfg.initialAlpha = (u8)randomGetRange(0x7f, 0xff);
        cfg.behaviorFlags = 0x80480000;
        cfg.renderFlags = 0x440000;
        cfg.textureId = (s16)randomGetRange(0x525, 0x528);
        break;
    case 0x70a:
        cfg.velocityX = lbl_803E0240 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0240 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803E0240 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E0244;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = (s16)randomGetRange(0x525, 0x528);
        break;
    case 0x70b:
        cfg.lifetimeFrames = 0x64;
        cfg.scale = lbl_803E0248;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x208;
        cfg.renderFlags = 0x5000000;
        break;
    case 0x70c:
        cfg.lifetimeFrames = randomGetRange(0x19, 0x4b);
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803E024C * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803E0250 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.behaviorFlags = 0x1082000;
        cfg.textureId = (s16)randomGetRange(0x208, 0x20a);
        cfg.renderFlags = 0x1400000;
        break;
    case 0x70f:
        cfg.lifetimeFrames = randomGetRange(0xf, 0x2d);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-5, 5);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-5, 5);
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803E024C * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803E0254 * (f32)(s32)
        randomGetRange(0x32, 0x46);
        cfg.initialAlpha = 0xa0;
        cfg.behaviorFlags = 0x1082000;
        cfg.renderFlags = 0x5400000;
        cfg.textureId = (s16)randomGetRange(0x208, 0x20a);
        break;
    case 0x710:
        if (extraArgs != 0) thr = *(f32*)extraArgs;
        else thr = lbl_803E0228;
        cfg.lifetimeFrames = randomGetRange(0xf, 0x4b);
        cfg.startPosY = lbl_803E0258 * thr;
        cfg.startPosZ = lbl_803E025C * thr;
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803E024C * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E0260 * (f32)(s32)
        randomGetRange(0x14, 0x46);
        cfg.scale = lbl_803E0264 * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.initialAlpha = (u8)randomGetRange(0x3c, 0xa0);
        cfg.behaviorFlags = 0x81080200;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0xc0f;
        break;
    case 0x711:
        if (extraArgs != 0) thr = *(f32*)extraArgs;
        else thr = lbl_803E0228;
        cfg.lifetimeFrames = randomGetRange(0x23, 0x4b);
        cfg.startPosY = lbl_803E0268 * thr;
        cfg.startPosZ = lbl_803E025C * thr;
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E026C * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E0260 * (f32)(s32)
        randomGetRange(0x14, 0x3c);
        cfg.scale = lbl_803E0264 * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.initialAlpha = (u8)randomGetRange(0x64, 0xc8);
        cfg.behaviorFlags = 0x81080200;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0xc0f;
        break;
    case 0x712:
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0270 * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E0274;
        if ((int)randomGetRange(0, 2) != 0) cfg.behaviorFlags = 0xa100008;
        else cfg.behaviorFlags = 0x180008;
        cfg.renderFlags = 0x1400000;
        cfg.textureId = 0x5f;
        break;
    case 0x713:
        break;
    case 0x714:
        cfg.initialAlpha = (u8)randomGetRange(0x1e, 0x28);
        if (extraArgs != 0)
        {
            cfg.initialAlpha = (f32)(u32)
            cfg.initialAlpha *
                ((f32)(s32) * (int*)extraArgs / lbl_803E0278);
        }
        cfg.velocityZ = lbl_803E027C * (f32)(s32)
        randomGetRange(0x12, 0x14);
        cfg.scale = lbl_803E0280 * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.lifetimeFrames = randomGetRange(8, 0x14);
        cfg.behaviorFlags = 0x80204;
        cfg.renderFlags = 0x4002800;
        cfg.textureId = 0xc0f;
        break;
    case 0x715:
        if (extraArgs != 0)
        {
            cfg.velocityX = lbl_803E0284 * (f32)(s32)
            randomGetRange(-0x19, 0x19);
            cfg.velocityY = lbl_803E0284 * (f32)(s32)
            randomGetRange(5, 0x32);
            cfg.velocityZ = lbl_803E0284 * (f32)(s32)
            randomGetRange(-0x19, 0x19);
            cfg.scale = lbl_803E0288;
            cfg.lifetimeFrames = randomGetRange(0x28, 0x78);
            cfg.behaviorFlags = 0x80480000;
            cfg.renderFlags = 0x400800;
        }
        else
        {
            cfg.scale = lbl_803E028C * (f32)(s32)
            randomGetRange(0x32, 0x64);
            cfg.lifetimeFrames = 0x78;
            cfg.behaviorFlags = 0x80580200;
            cfg.renderFlags = 0x800;
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0f;
        break;
    case 0x716:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0238 * (f32)(s32)
        randomGetRange(0x5a, 0x64);
        cfg.linkGroup = 0xf;
        cfg.scale = lbl_803E0220 * (f32)(s32)
        randomGetRange(0x5a, 0x64);
        cfg.behaviorFlags = 0x800c0100;
        cfg.renderFlags = 0x4000800;
        cfg.initialAlpha = (u8)randomGetRange(0x96, 0xc8);
        cfg.lifetimeFrames = randomGetRange(0x32, 0x46);
        cfg.textureId = 0x185;
        break;
    case 0x717:
        if (extraArgs != 0) thr = *(f32*)extraArgs;
        else thr = lbl_803E0228;
        cfg.startPosX = thr * (lbl_803E0224 * (f32)(s32)
        randomGetRange(-0x96, 0x96)
        )
        ;
        cfg.startPosY = thr * (lbl_803E0224 * (f32)(s32)
        randomGetRange(0x64, 0x12c)
        )
        ;
        cfg.startPosZ = thr * (lbl_803E0224 * (f32)(s32)
        randomGetRange(-0x96, -0x32)
        )
        ;
        cfg.scale = lbl_803E0244;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x96);
        cfg.behaviorFlags = 0x80480100;
        cfg.textureId = (s16)randomGetRange(0x527, 0x528);
        break;
    case 0x718:
        {
            f32 v = lbl_803E027C * (f32)(s32)randomGetRange(8, 0xa);
            cfg.velocityY = v;
            if (extraArgs != 0)
            {
                cfg.velocityY = v * (lbl_803E0228 + *(f32*)extraArgs / lbl_803E0290);
            }
            cfg.scale = lbl_803E0240 * (f32)(s32)
            randomGetRange(6, 0xc);
            cfg.lifetimeFrames = randomGetRange(0x3c, 0x64);
            cfg.behaviorFlags = 0x80180000;
            cfg.renderFlags = 0x5440800;
            cfg.textureId = 0xc0b;
            cfg.initialAlpha = 0x40;
            break;
        }
    case 0x71a:
        cfg.startPosZ = lbl_803E0294;
        cfg.scale = lbl_803E0298 * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.lifetimeFrames = 1;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0xc7e;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x71b:
        cfg.scale = lbl_803E029C;
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0x180000;
        cfg.renderFlags = 0x400800;
        cfg.textureId = 0x73;
        cfg.initialAlpha = 0xff;
        break;
    case 0x71c:
        cfg.lifetimeFrames = randomGetRange(0x28, 0x78);
        cfg.velocityX = lbl_803E027C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E02A0 * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E027C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803E0284;
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x600820;
        cfg.textureId = 0x20d;
        cfg.initialAlpha = 0xff;
        cfg.colorWord2 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0 = 0xffff;
        cfg.overrideColor2 = 0;
        cfg.overrideColor1 = 0;
        break;
    case 0x71d:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.linkGroup = 0xf;
        cfg.scale = lbl_803E0220 * (f32)(s32)
        randomGetRange(0x78, 0xc8);
        cfg.behaviorFlags = 0x80180100;
        cfg.renderFlags = 0x4000800;
        cfg.initialAlpha = (u8)randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = randomGetRange(0x64, 0x8c);
        cfg.textureId = 0x185;
        break;
    case 0x71e:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x23, 0x23);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x1e);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x23, 0x23);
        cfg.velocityY = lbl_803E027C * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E0240 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x64, 0x96);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x1440000;
        cfg.textureId = 0x564;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x71f:
        cfg.velocityY = lbl_803E027C * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E0288 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x50);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x5440800;
        cfg.textureId = 0x564;
        cfg.initialAlpha = 0x40;
        break;
    case 0x720:
        cfg.velocityY = lbl_803E02A4 * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E0288 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x50);
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x5000800;
        cfg.textureId = 0x564;
        cfg.initialAlpha = 0x40;
        break;
    case 0x721:
        cfg.scale = lbl_803E02A8 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0xfa, 0x15e);
        cfg.behaviorFlags = 0x80480008;
        cfg.renderFlags = 0x400000;
        cfg.textureId = 0xc0d;
        break;
    case 0x722:
        cfg.startPosY = lbl_803E02AC;
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x3c);
        cfg.velocityX = lbl_803E02A4 * (f32)(s32)
        randomGetRange(-0x3c, 0x3c);
        cfg.velocityY = lbl_803E02B0 * sqrtf(cfg.velocityX * cfg.velocityX + cfg.velocityZ * cfg.velocityZ);
        cfg.velocityZ = lbl_803E02A4 * (f32)(s32)
        randomGetRange(-0x3c, 0x3c);
        cfg.scale = lbl_803E02A4;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x5400800;
        cfg.textureId = 0x564;
        cfg.initialAlpha = (u8)((int)randomGetRange(0x46, 0xbe) >> 1);
        break;
    case 0x723:
        {
            int base, span;
            cfg.lifetimeFrames = randomGetRange(0x23, 0x2d);
            if (extraArgs != 0) base = *(int*)extraArgs + 5;
            else base = 5;
            cfg.velocityY = (f32)(s32)
            base / lbl_803E02B4 *
                (lbl_803E02B8 * (f32)(s32)
            randomGetRange(8, 0xc)
            )
            ;
            span = 0x41 - base;
            cfg.velocityX = lbl_803E024C * (f32)(s32)
            randomGetRange(-span, span);
            cfg.velocityZ = lbl_803E024C * (f32)(s32)
            randomGetRange(-span, span);
            cfg.scale = lbl_803E0240 * (f32)(s32)
            randomGetRange(6, 0xc);
            cfg.initialAlpha = (u8)((int)randomGetRange(0x40, 0x7f) >> 1);
            cfg.behaviorFlags = 0x80080000;
            cfg.renderFlags = 0x5400800;
            cfg.textureId = 0x564;
            break;
        }
    case 0x724:
        cfg.velocityY = lbl_803E027C * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E0240 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x3c);
        cfg.behaviorFlags = 0x80080000;
        cfg.renderFlags = 0x5440800;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x40;
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

void Effect19_func05(void);

void Effect18_func03_nop(void)
{
}

void Effect18_release(void)
{
}

void Effect18_initialise(void)
{
}

void Effect19_func03_nop(void);

#pragma dont_inline reset
#pragma dont_inline reset


extern f32 sqrtf(f32 x);
