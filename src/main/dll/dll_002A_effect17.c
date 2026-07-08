#include "main/game_object.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
#include "main/frame_timing.h"
#include "main/dll/dll_002A_effect17.h"

extern f32 gEffect17AnimProgressC;
extern f32 gEffect17AnimProgressD;
extern s32 gEffect17SinPhaseA;
extern s32 gEffect17SinPhaseB;
extern f32 gEffect17SinValueB;
extern f32 gEffect17SinValueA;
extern f32 gEffect17AnimProgressA;
extern f32 gEffect17AnimProgressB;
extern float mathSinf(float x);

int Effect17_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                    s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    gEffect17AnimProgressA += 0.001f;
    if (gEffect17AnimProgressA > 1.0f)
        gEffect17AnimProgressA = 0.1f;
    gEffect17AnimProgressB += 0.0003f;
    if (gEffect17AnimProgressB > 1.0f)
        gEffect17AnimProgressB = 0.3f;
    if (sourceObj == 0)
        return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0)
            return -1;
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
    cfg.startPosX = 0.0f;
    cfg.startPosY = 0.0f;
    cfg.startPosZ = 0.0f;
    cfg.velocityX = 0.0f;
    cfg.velocityY = 0.0f;
    cfg.velocityZ = 0.0f;
    cfg.scale = 0.0f;
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
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(8, 0xa);
        if ((int)randomGetRange(0, 0x28) != 0)
        {
            cfg.scale = 0.001f * (f32)(s32)randomGetRange(8, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x5a, 0x78);
        }
        else
        {
            cfg.scale = 0.001f * (f32)(s32)randomGetRange(0x15, 0x29);
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
        cfg.startPosY = 65.0f;
        break;
    case 0x73b:
        cfg.velocityX = 0.05f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(8, 0x14);
        cfg.velocityZ = 0.05f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.003f;
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
        cfg.startPosY = 20.0f;
        break;
    case 0x73d:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosY = 0.05f * (f32)(s32)randomGetRange(-0xa, 0x64);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.5f * (0.0009f * (f32)(s32)randomGetRange(7, 9));
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x73e:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosY = 0.05f * (f32)(s32)randomGetRange(-0xa, 0x64);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.5f * (0.0009f * (f32)(s32)randomGetRange(7, 9));
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdf;
        break;
    case 0x73f:
        if (extraArgs != 0)
        {
            cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa) + 2.0f;
            cfg.startPosY = 0.05f * (f32)(s32)randomGetRange(-0xa, 0x64) + 104.0f;
            cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa) + 5.5f;
        }
        else
        {
            cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.startPosY = 0.05f * (f32)(s32)randomGetRange(-0xa, 0x64);
            cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.scale = 0.25f * (0.0009f * (f32)(s32)randomGetRange(7, 9));
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x740:
        if (extraArgs != 0)
        {
            cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa) + 2.0f;
            cfg.startPosY = 0.05f * (f32)(s32)randomGetRange(-0xa, 0x64) + 104.0f;
            cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa) + 5.5f;
        }
        else
        {
            cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.startPosY = 0.05f * (f32)(s32)randomGetRange(-0xa, 0x64);
            cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.scale = 0.25f * (0.0009f * (f32)(s32)randomGetRange(7, 9));
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdf;
        break;
    case 0x741:
        if (spawnParams != 0)
            cfg.startPosY = spawnParams->posY;
        cfg.scale = 0.03f;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x50;
        cfg.initialAlpha = 0x60;
        cfg.behaviorFlags = 0x80110;
        cfg.textureId = 0x7b;
        cfg.linkGroup = 0x20;
        break;
    case 0x742:
        cfg.velocityZ = -0.5f;
        cfg.velocityX = 0.009f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.009f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.0047f;
        cfg.lifetimeFrames = randomGetRange(0x46, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x82000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x3f4;
        break;
    case 0x743:
        cfg.velocityZ = -0.5f;
        cfg.velocityX = 0.009f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.009f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.0047f;
        cfg.lifetimeFrames = randomGetRange(0x46, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x82000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x500;
        break;
    case 0x744:
        if ((int)randomGetRange(0, 4) == 4)
        {
            cfg.scale = 0.0147f;
            cfg.initialAlpha = 0x9b;
            cfg.behaviorFlags = 0x480000;
            cfg.lifetimeFrames = randomGetRange(0x1e, 0x28);
        }
        else
        {
            cfg.scale = 0.0347f;
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
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0))
        cfg.behaviorFlags ^= 2LL;
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

void Effect17_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect17AnimProgressC + (step = 0.001f * timeDelta);
    gEffect17AnimProgressC = sum;
    if (sum > 1.0f)
        gEffect17AnimProgressC = 0.1f;
    sum = gEffect17AnimProgressD + step;
    gEffect17AnimProgressD = sum;
    if (sum > 1.0f)
        gEffect17AnimProgressD = 0.3f;
    gEffect17SinPhaseA = gEffect17SinPhaseA + framesThisStep * 0x64;
    if (gEffect17SinPhaseA > 0x7fff)
        gEffect17SinPhaseA = 0;
    gEffect17SinValueA = mathSinf(3.1415927f * (f32)(s16)gEffect17SinPhaseA / 32768.0f);
    gEffect17SinPhaseB = gEffect17SinPhaseB + framesThisStep * 0x32;
    if (gEffect17SinPhaseB > 0x7fff)
        gEffect17SinPhaseB = 0;
    gEffect17SinValueB = mathSinf(3.1415927f * (f32)(s16)gEffect17SinPhaseB / 32768.0f);
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
