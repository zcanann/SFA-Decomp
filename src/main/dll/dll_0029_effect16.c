/*
 * effect16 (DLL 0x29) - one of the particle-effect spawner DLLs
 * (siblings effect13..effect20 share the same skeleton).
 *
 * Effect16_func04 is the per-effect spawn dispatcher: given an effect
 * id (handled ranges 0x6d7..0x6e1 and 0x6f2..0x6f8; ids 0x6e2..0x6f1
 * are unhandled and fall to default: return -1), it fills an
 * EffectSpawnConfig (velocity, scale,
 * lifetime, colour, texture, behaviour/render flags) - randomised via
 * randomGetRange - and hands it to gExpgfxInterface->spawnEffect. When
 * spawnFlags has 0x200000 set the source transform is read from the
 * caller's PartFxSpawnParams; behaviour bit 0 offsets the start
 * position by the attached source object's world position (+0x18/1c/20).
 *
 * Effect16_func05 advances this DLL's shared animation phases each tick
 * (two looping 0..1 scroll accumulators and two sin-driven values
 * stepped by framesThisStep). The remaining entry points are no-ops.
 */
#include "main/dll/waterfxcfg_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
extern float mathSinf(float x);
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 gEffect16ScrollPhaseA;
extern f32 gEffect16ScrollPhaseB;
extern f32 gEffect16TimedScrollPhaseA;
extern f32 gEffect16TimedScrollPhaseB;
extern s32 gEffect16SinPhaseCounterA;
extern s32 gEffect16SinPhaseCounterB;
extern f32 gEffect16SinValueB;
extern f32 gEffect16SinValueA;
extern f32 lbl_803E00A8;
extern f32 lbl_803E00AC;
extern f32 lbl_803E00B0;
extern f32 lbl_803E00B4;
extern f32 lbl_803E00B8;
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
extern f32 gEffect16Pi;
extern f32 gEffect16SinPhaseScale;
extern WaterfxCfg gEffect16DefaultSpawnSource;

void Effect16_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect16TimedScrollPhaseA + (step = lbl_803E00A8 * timeDelta);
    gEffect16TimedScrollPhaseA = sum;
    if (sum > 1.0f) gEffect16TimedScrollPhaseA = lbl_803E00AC;
    sum = gEffect16TimedScrollPhaseB + step;
    gEffect16TimedScrollPhaseB = sum;
    if (sum > 1.0f) gEffect16TimedScrollPhaseB = lbl_803E00B8;
    gEffect16SinPhaseCounterA = gEffect16SinPhaseCounterA + framesThisStep * 0x64;
    if (gEffect16SinPhaseCounterA > 0x7fff) gEffect16SinPhaseCounterA = 0;
    gEffect16SinValueA = mathSinf(gEffect16Pi * (f32)(s16)gEffect16SinPhaseCounterA / gEffect16SinPhaseScale);
    gEffect16SinPhaseCounterB = gEffect16SinPhaseCounterB + framesThisStep * 0x32;
    if (gEffect16SinPhaseCounterB > 0x7fff) gEffect16SinPhaseCounterB = 0;
    gEffect16SinValueB = mathSinf(gEffect16Pi * (f32)(s16)gEffect16SinPhaseCounterB / gEffect16SinPhaseScale);
}

int Effect16_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                    u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    gEffect16ScrollPhaseA = gEffect16ScrollPhaseA + lbl_803E00A8;
    if (gEffect16ScrollPhaseA > 1.0f) gEffect16ScrollPhaseA = lbl_803E00AC;
    gEffect16ScrollPhaseB = gEffect16ScrollPhaseB + lbl_803E00B4;
    if (gEffect16ScrollPhaseB > 1.0f) gEffect16ScrollPhaseB = lbl_803E00B8;
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
            gEffect16DefaultSpawnSource.posX = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posY = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posZ = lbl_803E00BC;
            gEffect16DefaultSpawnSource.scale = lbl_803E00B0;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
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
            gEffect16DefaultSpawnSource.posX = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posY = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posZ = lbl_803E00BC;
            gEffect16DefaultSpawnSource.scale = lbl_803E00B0;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
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
        cfg.velocityX = lbl_803E00DC * gEffect16ScrollPhaseA * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityZ = lbl_803E00DC * gEffect16ScrollPhaseA * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803E00DC * gEffect16ScrollPhaseA * (f32)(s32)
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
            gEffect16DefaultSpawnSource.posX = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posY = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posZ = lbl_803E00BC;
            gEffect16DefaultSpawnSource.scale = lbl_803E00B0;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
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
            gEffect16DefaultSpawnSource.posX = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posY = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posZ = lbl_803E00BC;
            gEffect16DefaultSpawnSource.scale = lbl_803E00B0;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
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
            gEffect16DefaultSpawnSource.posX = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posY = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posZ = lbl_803E00BC;
            gEffect16DefaultSpawnSource.scale = lbl_803E00B0;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
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
            gEffect16DefaultSpawnSource.posX = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posY = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posZ = lbl_803E00BC;
            gEffect16DefaultSpawnSource.scale = lbl_803E00B0;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
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
            gEffect16DefaultSpawnSource.posX = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posY = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posZ = lbl_803E00BC;
            gEffect16DefaultSpawnSource.scale = lbl_803E00B0;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
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
            gEffect16DefaultSpawnSource.posX = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posY = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posZ = lbl_803E00BC;
            gEffect16DefaultSpawnSource.scale = lbl_803E00B0;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
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
            gEffect16DefaultSpawnSource.posX = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posY = lbl_803E00BC;
            gEffect16DefaultSpawnSource.posZ = lbl_803E00BC;
            gEffect16DefaultSpawnSource.scale = lbl_803E00B0;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
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
                cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

void Effect16_func03_nop(void)
{
}

void Effect16_release(void)
{
}

void Effect16_initialise(void)
{
}
