#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/waterfxcfg_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
#include "main/audio/sfx.h"

#if 0
u32
FUN_800c8110(int sourceObj, u32 effectId, u16* spawnParams, u32 spawnFlags, u8 modelId,
             int useWorldOffset)
{
    u32 result;
    u32 rngRoll;
    int cfg[3];
    u16 srcRotX;
    u16 srcRotY;
    u16 srcRotZ;
    u32 srcScale;
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
    u16 linkGroup;
    u16 textureId;
    u32 behaviorFlags;
    u32 renderFlags;
    u32 overrideColor0;
    u32 overrideColor1;
    u32 overrideColor2;
    u16 colorWord0;
    u16 colorWord1;
    u16 colorWord2;
    u8 effectIdByte;
    u8 initialAlpha;
    u8 textureSetupFlags;
    u8 modelIdByte;
    u32 convBias0;
    u32 rngTmp0;
    u32 convBias1;
    u32 rngTmp1;
    u32 convBias2;
    u32 rngTmp2;
    u32 convBias3;
    u32 rngTmp3;

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
            if (spawnParams == 0x0)
            {
                return 0xffffffff;
            }
            srcPosX = ((PartFxSpawnParams*)spawnParams)->posX;
            srcPosY = ((PartFxSpawnParams*)spawnParams)->posY;
            srcPosZ = ((PartFxSpawnParams*)spawnParams)->posZ;
            srcScale = *(u32*)&((PartFxSpawnParams*)spawnParams)->scale;
            srcRotZ = ((PartFxSpawnParams*)spawnParams)->unk4;
            srcRotY = ((PartFxSpawnParams*)spawnParams)->unk2;
            srcRotX = *spawnParams;
            modelIdByte = modelId;
        }
        behaviorFlags = 0;
        renderFlags = 0;
        effectIdByte = effectId;
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
            convBias1 = 0x43300000;
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
            convBias1 = 0x43300000;
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
            if (spawnParams != 0x0)
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

u32 FUN_800c9030(u32 key, int* outIndex)
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
            if (key <= (u32)(&DAT_8039d0b8)[mid * 2]) break;
            lo = mid + 1;
        }
        if ((u32)(&DAT_8039d0b8)[mid * 2] <= key) break;
        hi = mid + -1;
    }
    *outIndex = mid;
    return (&DAT_8039d0bc)[mid * 2];
}
#endif

extern s16 lbl_803DD414;
extern s16 lbl_803DD416;
extern f32 lbl_803E0180;
extern f32 lbl_803E0184;
extern f32 lbl_803E0188;
extern f32 lbl_803E018C;
extern f32 lbl_803E0190;
extern f32 lbl_803E0194;
extern f32 lbl_803E0198;
extern f32 lbl_803E019C;
extern f32 lbl_803E01A0;
extern f32 lbl_803E01A4;
extern f32 lbl_803E01A8;
extern f32 lbl_803E01AC;

extern WaterfxCfg gEffect13DefaultSplashParams;

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

int Effect13_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId)
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
    cfg.effectIdByte = effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803E0180;
    cfg.startPosY = lbl_803E0180;
    cfg.startPosZ = lbl_803E0180;
    cfg.velocityX = lbl_803E0180;
    cfg.velocityY = lbl_803E0180;
    cfg.velocityZ = lbl_803E0180;
    cfg.scale = lbl_803E0180;
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
    case 0x44c:
        cfg.velocityX = lbl_803E0184 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803E0188 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803E0184 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803E018C;
        cfg.lifetimeFrames = 0x6e;
        cfg.behaviorFlags = 0x8a100208;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x400;
        cfg.overrideColor1 = 0xea60;
        cfg.overrideColor2 = 0x1000;
        break;
    case 0x44d:
        cfg.velocityX = lbl_803E018C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803E018C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803E0190;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x0a100100;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0x400;
        cfg.colorWord1 = 0xea60;
        cfg.colorWord2 = 0x1000;
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = 0xc350;
        cfg.overrideColor2 = 0;
        break;
    case 0x44e:
        cfg.startPosY = lbl_803E0194;
        cfg.scale = lbl_803E0198;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11000004;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x44f;
        break;
    case 0x44f:
        if (spawnParams == 0)
        {
            gEffect13DefaultSplashParams.posX = lbl_803E0180;
            gEffect13DefaultSplashParams.posY = lbl_803E0180;
            gEffect13DefaultSplashParams.posZ = lbl_803E0180;
            gEffect13DefaultSplashParams.scale = lbl_803E019C;
            gEffect13DefaultSplashParams.rotX = 0;
            gEffect13DefaultSplashParams.rotY = 0;
            gEffect13DefaultSplashParams.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect13DefaultSplashParams;
        }
        (*gWaterfxInterface)->spawnSplashBurst(NULL, spawnParams->posX,
                                               spawnParams->posY,
                                               spawnParams->posZ, lbl_803E01A0);
        Sfx_PlayFromObject((int)sourceObj, SFXsc_snort02);
        cfg.lifetimeFrames = 1;
        cfg.scale = lbl_803E01A4;
        cfg.behaviorFlags = 0x0a000001;
        cfg.textureId = 0x56;
        break;
    case 0x450:
        cfg.startPosY = lbl_803E01A8;
        cfg.scale = lbl_803E0198;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11000004;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x451;
        break;
    case 0x451:
        Sfx_PlayFromObject((int)sourceObj, SFXsc_snort02);
        cfg.lifetimeFrames = 0x64;
        cfg.scale = lbl_803E01AC * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.behaviorFlags = 0x0a100201;
        cfg.textureId = 0x56;
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
                cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

int Effect17_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);

void Effect13_func05_nop(void)
{
}

void Effect13_func03_nop(void)
{
}

void Effect13_release(void)
{
}

void Effect13_initialise(void)
{
}

void Effect17_func03_nop(void);

#pragma dont_inline reset
#pragma dont_inline reset
