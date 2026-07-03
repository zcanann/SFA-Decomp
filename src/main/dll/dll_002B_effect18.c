/* DLL 0x2B (Effect18): particle-effect spawner for effect IDs 0x708-0x724,
 * building PartFxSpawn requests dispatched through gExpgfxInterface->spawnEffect. */
#include "main/dll/partfxspawn_struct.h"
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
extern s16 lbl_803DD414;
extern s16 lbl_803DD416;
extern f32 timeDelta;
extern u8 framesThisStep;
extern float mathSinf(float x);
extern f32 gEffect18Progress2;
extern f32 gEffect18Progress3;
extern f32 lbl_803E0220;
extern f32 lbl_803E0224;
extern f32 lbl_803E0228;
extern f32 lbl_803E0230;
extern s32 gEffect18SinePhaseA;
extern s32 gEffect18SinePhaseB;
extern f32 gEffect18SineValueB;
extern f32 gEffect18SineValueA;
extern f32 gEffect18Pi;
extern f32 gEffect18S16Range;
extern f32 gEffect18Progress0;
extern f32 gEffect18Progress1;
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
extern f32 gEffect18AlphaMax;
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

void Effect18_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect18Progress2 + (step = lbl_803E0220 * timeDelta);
    gEffect18Progress2 = sum;
    if (sum > 1.0f) gEffect18Progress2 = lbl_803E0224;
    sum = gEffect18Progress3 + step;
    gEffect18Progress3 = sum;
    if (sum > 1.0f) gEffect18Progress3 = lbl_803E0230;
    gEffect18SinePhaseA = gEffect18SinePhaseA + framesThisStep * 0x64;
    if (gEffect18SinePhaseA > 0x7fff) gEffect18SinePhaseA = 0;
    gEffect18SineValueA = mathSinf(gEffect18Pi * (f32)(s16)gEffect18SinePhaseA / gEffect18S16Range);
    gEffect18SinePhaseB = gEffect18SinePhaseB + framesThisStep * 0x32;
    if (gEffect18SinePhaseB > 0x7fff) gEffect18SinePhaseB = 0;
    gEffect18SineValueB = mathSinf(gEffect18Pi * (f32)(s16)gEffect18SinePhaseB / gEffect18S16Range);
}

int Effect18_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                    u8 modelId, void* extraArgs)
{
    int spawnResult;
    f32 thr;
    PartFxSpawn cfg;

    gEffect18Progress0 = gEffect18Progress0 + lbl_803E0220;
    if (gEffect18Progress0 > 1.0f) gEffect18Progress0 = lbl_803E0224;
    gEffect18Progress1 = gEffect18Progress1 + lbl_803E022C;
    if (gEffect18Progress1 > 1.0f) gEffect18Progress1 = lbl_803E0230;
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
        cfg.initialAlpha = randomGetRange(0x7f, 0xff);
        cfg.behaviorFlags = 0x80480000;
        cfg.renderFlags = 0x440000;
        cfg.textureId = randomGetRange(0x525, 0x528);
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
        cfg.textureId = randomGetRange(0x525, 0x528);
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
        cfg.textureId = randomGetRange(0x208, 0x20a);
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
        cfg.textureId = randomGetRange(0x208, 0x20a);
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
        cfg.initialAlpha = randomGetRange(0x3c, 0xa0);
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
        cfg.initialAlpha = randomGetRange(0x64, 0xc8);
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
        cfg.initialAlpha = randomGetRange(0x1e, 0x28);
        if (extraArgs != 0)
        {
            cfg.initialAlpha = (f32)(u32)
            cfg.initialAlpha *
                ((f32)(s32) * (int*)extraArgs / gEffect18AlphaMax);
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
        cfg.initialAlpha = randomGetRange(0x96, 0xc8);
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
        cfg.textureId = randomGetRange(0x527, 0x528);
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
        cfg.initialAlpha = randomGetRange(0x32, 0x64);
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
            int base;
            cfg.lifetimeFrames = randomGetRange(0x23, 0x2d);
            if (extraArgs != 0) base = *(int*)extraArgs + 5;
            else base = 5;
            cfg.velocityY = (f32)(s32)
            base / lbl_803E02B4 *
                (lbl_803E02B8 * (f32)(s32)
            randomGetRange(8, 0xc)
            )
            ;
            base = 0x41 - base;
            cfg.velocityX = lbl_803E024C * (f32)(s32)
            randomGetRange(-base, base);
            cfg.velocityZ = lbl_803E024C * (f32)(s32)
            randomGetRange(-base, base);
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
                cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
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

#pragma dont_inline reset
