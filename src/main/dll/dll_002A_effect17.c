#include "main/game_object.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
extern u32 DAT_8039d0b8;
extern u32 DAT_8039d0bc;
extern u32 DAT_803de090;
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

extern s16 lbl_803DD414;
extern s16 lbl_803DD416;
extern f32 timeDelta;
extern u8 framesThisStep;
extern float mathSinf(float x);
extern f32 gEffect17AnimProgressC;
extern f32 gEffect17AnimProgressD;
extern f32 lbl_803E01B8;
extern f32 lbl_803E01BC;
extern f32 lbl_803E01C8;
extern s32 gEffect17SinPhaseA;
extern s32 gEffect17SinPhaseB;
extern f32 gEffect17SinValueB;
extern f32 gEffect17SinValueA;
extern f32 gEffect17Pi;
extern f32 gEffect17AngleScale;
extern f32 gEffect17AnimProgressA;
extern f32 gEffect17AnimProgressB;
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
    sum = gEffect17AnimProgressC + (step = lbl_803E01B8 * timeDelta);
    gEffect17AnimProgressC = sum;
    if (sum > 1.0f) gEffect17AnimProgressC = lbl_803E01BC;
    sum = gEffect17AnimProgressD + step;
    gEffect17AnimProgressD = sum;
    if (sum > 1.0f) gEffect17AnimProgressD = lbl_803E01C8;
    gEffect17SinPhaseA = gEffect17SinPhaseA + framesThisStep * 0x64;
    if (gEffect17SinPhaseA > 0x7fff) gEffect17SinPhaseA = 0;
    gEffect17SinValueA = mathSinf(gEffect17Pi * (f32)(s16)gEffect17SinPhaseA / gEffect17AngleScale);
    gEffect17SinPhaseB = gEffect17SinPhaseB + framesThisStep * 0x32;
    if (gEffect17SinPhaseB > 0x7fff) gEffect17SinPhaseB = 0;
    gEffect17SinValueB = mathSinf(gEffect17Pi * (f32)(s16)gEffect17SinPhaseB / gEffect17AngleScale);
}

void Effect18_func05(void);

int Effect17_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                    u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    gEffect17AnimProgressA = gEffect17AnimProgressA + lbl_803E01B8;
    if (gEffect17AnimProgressA > 1.0f) gEffect17AnimProgressA = lbl_803E01BC;
    gEffect17AnimProgressB = gEffect17AnimProgressB + lbl_803E01C4;
    if (gEffect17AnimProgressB > 1.0f) gEffect17AnimProgressB = lbl_803E01C8;
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
                cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
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
