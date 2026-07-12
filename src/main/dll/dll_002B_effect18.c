/* DLL 0x2B (Effect18): particle-effect spawner for effect IDs 0x708-0x724,
 * building PartFxSpawn requests dispatched through gExpgfxInterface->spawnEffect. */
#include "main/dll/partfxspawn_struct.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
#include "main/frame_timing.h"
#include "main/dll/dll_002B_effect18.h"

extern f32 gEffect18Progress2;
extern f32 gEffect18Progress3;
extern s32 gEffect18SinePhaseA;
extern s32 gEffect18SinePhaseB;
extern f32 gEffect18SineValueB;
extern f32 gEffect18SineValueA;
extern f32 gEffect18Progress0;
extern f32 gEffect18Progress1;
extern float mathSinf(float x);

int Effect18_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                    void* extraArgs)
{
    int spawnResult;
    f32 thr;
    PartFxSpawn cfg;

    gEffect18Progress0 += 0.001f;
    if (gEffect18Progress0 > 1.0f)
        gEffect18Progress0 = 0.1f;
    gEffect18Progress1 += 0.0003f;
    if (gEffect18Progress1 > 1.0f)
        gEffect18Progress1 = 0.3f;
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
    switch (effectId)
    {
    case 0x708:
        cfg.velocityX = 0.03f * (f32)(s32)randomGetRange(0xa, 0x19);
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = randomGetRange(0x15e, 0x190);
        cfg.behaviorFlags = 0xa100100;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x62;
        break;
    case 0x709:
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0xa, 0x14);
        if ((int)randomGetRange(0, 1) != 0)
            cfg.velocityY = -cfg.velocityY;
        cfg.scale = 0.001f;
        cfg.lifetimeFrames = 0x78;
        cfg.initialAlpha = randomGetRange(0x7f, 0xff);
        cfg.behaviorFlags = 0x80480000;
        cfg.renderFlags = 0x440000;
        cfg.textureId = randomGetRange(0x525, 0x528);
        break;
    case 0x70a:
        cfg.velocityX = 0.002f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = 0.002f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.0012f;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = randomGetRange(0x525, 0x528);
        break;
    case 0x70b:
        cfg.lifetimeFrames = 0x64;
        cfg.scale = 0.08f;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x208;
        cfg.renderFlags = 0x5000000;
        break;
    case 0x70c:
        cfg.lifetimeFrames = randomGetRange(0x19, 0x4b);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.015f * (f32)(s32)cfg.lifetimeFrames;
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = 3e-05f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.behaviorFlags = 0x1082000;
        cfg.textureId = randomGetRange(0x208, 0x20a);
        cfg.renderFlags = 0x1400000;
        break;
    case 0x70f:
        cfg.lifetimeFrames = randomGetRange(0xf, 0x2d);
        cfg.startPosX = (f32)(s32)randomGetRange(-5, 5);
        cfg.startPosZ = (f32)(s32)randomGetRange(-5, 5);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.015f * (f32)(s32)cfg.lifetimeFrames;
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = 2e-05f * (f32)(s32)randomGetRange(0x32, 0x46);
        cfg.initialAlpha = 0xa0;
        cfg.behaviorFlags = 0x1082000;
        cfg.renderFlags = 0x5400000;
        cfg.textureId = randomGetRange(0x208, 0x20a);
        break;
    case 0x710:
        if (extraArgs != 0)
            thr = *(f32*)extraArgs;
        else
            thr = 1.0f;
        cfg.lifetimeFrames = randomGetRange(0xf, 0x4b);
        cfg.startPosY = 20.0f * thr;
        cfg.startPosZ = -5.0f * thr;
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = 0.015f * (f32)(s32)cfg.lifetimeFrames;
        cfg.velocityZ = -0.01f * (f32)(s32)randomGetRange(0x14, 0x46);
        cfg.scale = 4e-05f * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.initialAlpha = randomGetRange(0x3c, 0xa0);
        cfg.behaviorFlags = 0x81080200;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0xc0f;
        break;
    case 0x711:
        if (extraArgs != 0)
            thr = *(f32*)extraArgs;
        else
            thr = 1.0f;
        cfg.lifetimeFrames = randomGetRange(0x23, 0x4b);
        cfg.startPosY = 15.0f * thr;
        cfg.startPosZ = -5.0f * thr;
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.velocityY = 0.013f * (f32)(s32)cfg.lifetimeFrames;
        cfg.velocityZ = -0.01f * (f32)(s32)randomGetRange(0x14, 0x3c);
        cfg.scale = 4e-05f * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.initialAlpha = randomGetRange(0x64, 0xc8);
        cfg.behaviorFlags = 0x81080200;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0xc0f;
        break;
    case 0x712:
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.0018f * (f32)(s32)cfg.lifetimeFrames;
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.007f;
        if ((int)randomGetRange(0, 2) != 0)
            cfg.behaviorFlags = 0xa100008;
        else
            cfg.behaviorFlags = 0x180008;
        cfg.renderFlags = 0x1400000;
        cfg.textureId = 0x5f;
        break;
    case 0x713:
        break;
    case 0x714:
        cfg.initialAlpha = randomGetRange(0x1e, 0x28);
        if (extraArgs != 0)
        {
            cfg.initialAlpha = (f32)(u32)cfg.initialAlpha * ((f32)(s32) * (int*)extraArgs / 255.0f);
        }
        cfg.velocityZ = 0.05f * (f32)(s32)randomGetRange(0x12, 0x14);
        cfg.scale = 9e-05f * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.lifetimeFrames = randomGetRange(8, 0x14);
        cfg.behaviorFlags = 0x80204;
        cfg.renderFlags = 0x4002800;
        cfg.textureId = 0xc0f;
        break;
    case 0x715:
        if (extraArgs != 0)
        {
            cfg.velocityX = 0.005f * (f32)(s32)randomGetRange(-0x19, 0x19);
            cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(5, 0x32);
            cfg.velocityZ = 0.005f * (f32)(s32)randomGetRange(-0x19, 0x19);
            cfg.scale = 0.0015f;
            cfg.lifetimeFrames = randomGetRange(0x28, 0x78);
            cfg.behaviorFlags = 0x80480000;
            cfg.renderFlags = 0x400800;
        }
        else
        {
            cfg.scale = 5e-05f * (f32)(s32)randomGetRange(0x32, 0x64);
            cfg.lifetimeFrames = 0x78;
            cfg.behaviorFlags = 0x80580200;
            cfg.renderFlags = 0x800;
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0f;
        break;
    case 0x716:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.03f * (f32)(s32)randomGetRange(0x5a, 0x64);
        cfg.linkGroup = 0xf;
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0x5a, 0x64);
        cfg.behaviorFlags = 0x800c0100;
        cfg.renderFlags = 0x4000800;
        cfg.initialAlpha = randomGetRange(0x96, 0xc8);
        cfg.lifetimeFrames = randomGetRange(0x32, 0x46);
        cfg.textureId = 0x185;
        break;
    case 0x717:
        if (extraArgs != 0)
            thr = *(f32*)extraArgs;
        else
            thr = 1.0f;
        cfg.startPosX = thr * (0.1f * (f32)(s32)randomGetRange(-0x96, 0x96));
        cfg.startPosY = thr * (0.1f * (f32)(s32)randomGetRange(0x64, 0x12c));
        cfg.startPosZ = thr * (0.1f * (f32)(s32)randomGetRange(-0x96, -0x32));
        cfg.scale = 0.0012f;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x96);
        cfg.behaviorFlags = 0x80480100;
        cfg.textureId = randomGetRange(0x527, 0x528);
        break;
    case 0x718:
    {
        f32 v = 0.05f * (f32)(s32)randomGetRange(8, 0xa);
        cfg.velocityY = v;
        if (extraArgs != 0)
        {
            cfg.velocityY = v * (1.0f + *(f32*)extraArgs / 70.0f);
        }
        cfg.scale = 0.002f * (f32)(s32)randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x64);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x5440800;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x40;
        break;
    }
    case 0x71a:
        cfg.startPosZ = 8.0f;
        cfg.scale = 0.0021f * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.lifetimeFrames = 1;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0xc7e;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x71b:
        cfg.scale = 0.5f;
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0x180000;
        cfg.renderFlags = 0x400800;
        cfg.textureId = 0x73;
        cfg.initialAlpha = 0xff;
        break;
    case 0x71c:
        cfg.lifetimeFrames = randomGetRange(0x28, 0x78);
        cfg.velocityX = 0.05f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.velocityY = 0.035f * (f32)(s32)cfg.lifetimeFrames;
        cfg.velocityZ = 0.05f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.scale = 0.005f;
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
        cfg.startPosX = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.linkGroup = 0xf;
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0x78, 0xc8);
        cfg.behaviorFlags = 0x80180100;
        cfg.renderFlags = 0x4000800;
        cfg.initialAlpha = randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = randomGetRange(0x64, 0x8c);
        cfg.textureId = 0x185;
        break;
    case 0x71e:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x23, 0x23);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x1e);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x23, 0x23);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(8, 0xa);
        cfg.scale = 0.002f * (f32)(s32)randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x64, 0x96);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x1440000;
        cfg.textureId = 0x564;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x71f:
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(8, 0xa);
        cfg.scale = 0.0015f * (f32)(s32)randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x50);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x5440800;
        cfg.textureId = 0x564;
        cfg.initialAlpha = 0x40;
        break;
    case 0x720:
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(8, 0xa);
        cfg.scale = 0.0015f * (f32)(s32)randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x50);
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x5000800;
        cfg.textureId = 0x564;
        cfg.initialAlpha = 0x40;
        break;
    case 0x721:
        cfg.scale = 0.0005f * (f32)(s32)randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0xfa, 0x15e);
        cfg.behaviorFlags = 0x80480008;
        cfg.renderFlags = 0x400000;
        cfg.textureId = 0xc0d;
        break;
    case 0x722:
        cfg.startPosY = -45.0f;
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x3c);
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(-0x3c, 0x3c);
        cfg.velocityY = 0.25f * sqrtf(cfg.velocityX * cfg.velocityX + cfg.velocityZ * cfg.velocityZ);
        cfg.velocityZ = 0.02f * (f32)(s32)randomGetRange(-0x3c, 0x3c);
        cfg.scale = 0.02f;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x5400800;
        cfg.textureId = 0x564;
        cfg.initialAlpha = (u8)((int)randomGetRange(0x46, 0xbe) >> 1);
        break;
    case 0x723:
    {
        int base;
        cfg.lifetimeFrames = randomGetRange(0x23, 0x2d);
        if (extraArgs != 0)
            base = *(int*)extraArgs + 5;
        else
            base = 5;
        cfg.velocityY = (f32)(s32)base / 50.0f * (0.2f * (f32)(s32)randomGetRange(8, 0xc));
        base = 0x41 - base;
        cfg.velocityX = 0.015f * (f32)(s32)randomGetRange(-base, base);
        cfg.velocityZ = 0.015f * (f32)(s32)randomGetRange(-base, base);
        cfg.scale = 0.002f * (f32)(s32)randomGetRange(6, 0xc);
        cfg.initialAlpha = (u8)((int)randomGetRange(0x40, 0x7f) >> 1);
        cfg.behaviorFlags = 0x80080000;
        cfg.renderFlags = 0x5400800;
        cfg.textureId = 0x564;
        break;
    }
    case 0x724:
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(8, 0xa);
        cfg.scale = 0.002f * (f32)(s32)randomGetRange(6, 0xc);
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

void Effect18_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect18Progress2 + (step = 0.001f * timeDelta);
    gEffect18Progress2 = sum;
    if (sum > 1.0f)
        gEffect18Progress2 = 0.1f;
    sum = gEffect18Progress3 + step;
    gEffect18Progress3 = sum;
    if (sum > 1.0f)
        gEffect18Progress3 = 0.3f;
    gEffect18SinePhaseA = gEffect18SinePhaseA + framesThisStep * 0x64;
    if (gEffect18SinePhaseA > 0x7fff)
        gEffect18SinePhaseA = 0;
    gEffect18SineValueA = mathSinf(3.1415927f * (f32)(s16)gEffect18SinePhaseA / 32768.0f);
    gEffect18SinePhaseB = gEffect18SinePhaseB + framesThisStep * 0x32;
    if (gEffect18SinePhaseB > 0x7fff)
        gEffect18SinePhaseB = 0;
    gEffect18SineValueB = mathSinf(3.1415927f * (f32)(s16)gEffect18SinePhaseB / 32768.0f);
}

void Effect18_func03_nop(void)
{
}

void Effect18_release(void)
{
}

void Effect18_initialise(void)
{
}
