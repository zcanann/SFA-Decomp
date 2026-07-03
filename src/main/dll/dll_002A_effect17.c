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

void Effect17_func03_nop(void)
{
}

void Effect17_release(void)
{
}

void Effect17_initialise(void)
{
}

#pragma dont_inline reset
#pragma dont_inline reset
