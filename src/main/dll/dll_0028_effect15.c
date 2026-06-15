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

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

int Effect15_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                    u8 modelId, f32* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

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
            lbl_8039C428.posX = lbl_803E0110;
            lbl_8039C428.posY = lbl_803E0110;
            lbl_8039C428.posZ = lbl_803E0110;
            lbl_8039C428.scale = lbl_803E011C;
            lbl_8039C428.rotX = 0;
            lbl_8039C428.rotY = 0;
            lbl_8039C428.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C428;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
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
            lbl_8039C428.posX = lbl_803E0110;
            lbl_8039C428.posY = lbl_803E0110;
            lbl_8039C428.posZ = lbl_803E0110;
            lbl_8039C428.scale = lbl_803E011C;
            lbl_8039C428.rotX = 0;
            lbl_8039C428.rotY = 0;
            lbl_8039C428.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C428;
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
        cfg.scale = spawnParams->scale *
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
            lbl_8039C428.posX = lbl_803E0110;
            lbl_8039C428.posY = lbl_803E0110;
            lbl_8039C428.posZ = lbl_803E0110;
            lbl_8039C428.scale = lbl_803E011C;
            lbl_8039C428.rotX = 0;
            lbl_8039C428.rotY = 0;
            lbl_8039C428.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&lbl_8039C428;
        }
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
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
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
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
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
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
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
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
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.scale = spawnParams->scale;
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
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.scale = spawnParams->scale;
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

int Effect18_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId, void* extraArgs);

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

#pragma dont_inline reset
#pragma dont_inline reset

