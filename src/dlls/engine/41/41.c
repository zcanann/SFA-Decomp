#include "main/dll/waterfxcfg_struct.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/dll/partfxspawn_struct.h"
#include "game/objects/object.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0029_effect16.h"
#include "main/vecmath.h"

f32 gEffect16SinValueA;
f32 gEffect16SinValueB;
s32 gEffect16SinPhaseCounterB;
s32 gEffect16SinPhaseCounterA;

f32 gEffect16ScrollPhaseA = 0.1f;
f32 gEffect16ScrollPhaseB = 0.3f;
f32 gEffect16TimedScrollPhaseA = 0.1f;
f32 gEffect16TimedScrollPhaseB = 0.3f;

WaterfxCfg gEffect16DefaultSpawnSource;

ObjectDescriptor6 Effect16_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect16_initialise,
    (ObjectDescriptorCallback)Effect16_release,
    0,
    (ObjectDescriptorCallback)Effect16_func03_nop,
    (ObjectDescriptorCallback)Effect16_spawnObject,
    (ObjectDescriptorCallback)Effect16_updateFrameState,
};

int Effect16_spawnObject(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                         s16* extraArgs) {
    int spawnResult;
    PartFxSpawn cfg;

    gEffect16ScrollPhaseA += 0.001f;
    if (gEffect16ScrollPhaseA > 1.0f) {
        gEffect16ScrollPhaseA = 0.1f;
    }
    gEffect16ScrollPhaseB += 0.0003f;
    if (gEffect16ScrollPhaseB > 1.0f) {
        gEffect16ScrollPhaseB = 0.3f;
    }
    if (sourceObj == 0) {
        return -1;
    }
    if ((spawnFlags & 0x200000) != 0) {
        if (spawnParams == 0) {
            return -1;
        }
        cfg.sourcePosX = spawnParams->posX;
        cfg.sourcePosY = spawnParams->posY;
        cfg.sourcePosZ = spawnParams->posZ;
        cfg.sourceScale = spawnParams->scale;
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
    switch (effectId) {
    case 0x6d7:
        if (spawnParams == 0) {
            gEffect16DefaultSpawnSource.posX = 0.0f;
            gEffect16DefaultSpawnSource.posY = 0.0f;
            gEffect16DefaultSpawnSource.posZ = 0.0f;
            gEffect16DefaultSpawnSource.scale = 1.0f;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0xa, 0x1e);
        cfg.lifetimeFrames = randomGetRange(0x118, 0x12c);
        cfg.behaviorFlags = 0x80180214;
        cfg.textureId = 0x5c;
        break;
    case 0x6d8:
        if (spawnParams == 0) {
            gEffect16DefaultSpawnSource.posX = 0.0f;
            gEffect16DefaultSpawnSource.posY = 0.0f;
            gEffect16DefaultSpawnSource.posZ = 0.0f;
            gEffect16DefaultSpawnSource.scale = 1.0f;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x118, 0x12c);
        cfg.behaviorFlags = 0x80180214;
        cfg.textureId = 0xc79;
        break;
    case 0x6d9:
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = 0.02f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.scale = 0.00035f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80114;
        cfg.renderFlags = 0x10008;
        cfg.textureId = 0x157;
        break;
    case 0x6da:
        cfg.scale = 0.035f;
        cfg.lifetimeFrames = 0x14;
        cfg.behaviorFlags = 0x80480210;
        cfg.textureId = 0xc79;
        cfg.initialAlpha = 0x9d;
        break;
    case 0x6db:
        if (extraArgs != 0) {
            cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x96, 0x96);
            cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x96, 0x96);
            cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0x64, 0x190);
            cfg.scale = 0.0005f * (f32)(s32)randomGetRange(0xf, 0x14);
            cfg.lifetimeFrames = 0x32;
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = 0xffff;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0;
            cfg.overrideColor2 = 0;
            cfg.behaviorFlags = 0x3000200;
            cfg.renderFlags = 0x200022;
        } else {
            cfg.scale = 0.002f * (f32)(s32)randomGetRange(0xf, 0x14);
            cfg.lifetimeFrames = 1;
            cfg.behaviorFlags = 0x80000;
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc79;
        break;
    case 0x6dc:
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(8, 0xa);
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0x12, 0x1c);
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.behaviorFlags = 0x80180200;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0xff;
        break;
    case 0x6dd:
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xc3;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x580110;
        cfg.textureId = 0xc79;
        break;
    case 0x6de:
        cfg.velocityX = 0.185f * gEffect16ScrollPhaseA * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.velocityZ = 0.185f * gEffect16ScrollPhaseA * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.velocityY = 0.185f * gEffect16ScrollPhaseA * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.initialAlpha = 0x7d;
        cfg.scale = 0.000288f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x300000;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = 0xc79;
        break;
    case 0x6df:
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.behaviorFlags = 0x80200;
        cfg.renderFlags = 0x100000;
        cfg.lifetimeFrames = 0x64;
        cfg.textureId = 0x125;
        break;
    case 0x6e0:
        cfg.velocityX = 0.5f * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.velocityZ = 0.5f * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.velocityY = 0.5f * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.000288f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.behaviorFlags = 0x2000200;
        cfg.renderFlags = 0x300000;
        cfg.lifetimeFrames = 0x1e;
        cfg.textureId = 0x33;
        break;
    case 0x6e1:
        cfg.lifetimeFrames = 0x46;
        cfg.scale = 0.2f;
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
        if (spawnParams == 0) {
            gEffect16DefaultSpawnSource.posX = 0.0f;
            gEffect16DefaultSpawnSource.posY = 0.0f;
            gEffect16DefaultSpawnSource.posZ = 0.0f;
            gEffect16DefaultSpawnSource.scale = 1.0f;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(-7, 3);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(5, 0xf);
        cfg.velocityZ = 0.02f * (f32)(s32)randomGetRange(-7, 3);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x32, 0x3c);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x5a);
        cfg.behaviorFlags = 0x580004;
        cfg.renderFlags = 0x400000;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0d;
        break;
    case 0x6f3:
        if (spawnParams == 0) {
            gEffect16DefaultSpawnSource.posX = 0.0f;
            gEffect16DefaultSpawnSource.posY = 0.0f;
            gEffect16DefaultSpawnSource.posZ = 0.0f;
            gEffect16DefaultSpawnSource.scale = 1.0f;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.00002f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x58f;
        break;
    case 0x6f4:
        if (spawnParams == 0) {
            gEffect16DefaultSpawnSource.posX = 0.0f;
            gEffect16DefaultSpawnSource.posY = 0.0f;
            gEffect16DefaultSpawnSource.posZ = 0.0f;
            gEffect16DefaultSpawnSource.scale = 1.0f;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.00001f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x4800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x590;
        break;
    case 0x6f5:
        if (spawnParams == 0) {
            gEffect16DefaultSpawnSource.posX = 0.0f;
            gEffect16DefaultSpawnSource.posY = 0.0f;
            gEffect16DefaultSpawnSource.posZ = 0.0f;
            gEffect16DefaultSpawnSource.scale = 1.0f;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.00002f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x403;
        break;
    case 0x6f6:
        if (spawnParams == 0) {
            gEffect16DefaultSpawnSource.posX = 0.0f;
            gEffect16DefaultSpawnSource.posY = 0.0f;
            gEffect16DefaultSpawnSource.posZ = 0.0f;
            gEffect16DefaultSpawnSource.scale = 1.0f;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.00001f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x4800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x404;
        break;
    case 0x6f7:
        if (spawnParams == 0) {
            gEffect16DefaultSpawnSource.posX = 0.0f;
            gEffect16DefaultSpawnSource.posY = 0.0f;
            gEffect16DefaultSpawnSource.posZ = 0.0f;
            gEffect16DefaultSpawnSource.scale = 1.0f;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.00002f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x405;
        break;
    case 0x6f8:
        if (spawnParams == 0) {
            gEffect16DefaultSpawnSource.posX = 0.0f;
            gEffect16DefaultSpawnSource.posY = 0.0f;
            gEffect16DefaultSpawnSource.posZ = 0.0f;
            gEffect16DefaultSpawnSource.scale = 1.0f;
            gEffect16DefaultSpawnSource.rotX = 0;
            gEffect16DefaultSpawnSource.rotY = 0;
            gEffect16DefaultSpawnSource.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect16DefaultSpawnSource;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.00001f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x406;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags |= spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) {
        cfg.behaviorFlags ^= 2;
    }
    if ((cfg.behaviorFlags & 1) != 0) {
        if ((spawnFlags & 0x200000) != 0) {
            cfg.startPosX += cfg.sourcePosX;
            cfg.startPosY += cfg.sourcePosY;
            cfg.startPosZ += cfg.sourcePosZ;
        } else {
            if (cfg.attachedSource != 0) {
                cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

void Effect16_updateFrameState(void) {
    f32 sum;
    f32 step;
    sum = gEffect16TimedScrollPhaseA + (step = 0.001f * timeDelta);
    gEffect16TimedScrollPhaseA = sum;
    if (sum > 1.0f) {
        gEffect16TimedScrollPhaseA = 0.1f;
    }
    sum = gEffect16TimedScrollPhaseB + step;
    gEffect16TimedScrollPhaseB = sum;
    if (sum > 1.0f) {
        gEffect16TimedScrollPhaseB = 0.3f;
    }
    gEffect16SinPhaseCounterA = gEffect16SinPhaseCounterA + framesThisStep * 0x64;
    if (gEffect16SinPhaseCounterA > 0x7fff) {
        gEffect16SinPhaseCounterA = 0;
    }
    gEffect16SinValueA = mathSinf(3.1415927f * (f32)(s16)gEffect16SinPhaseCounterA / 32768.0f);
    gEffect16SinPhaseCounterB = gEffect16SinPhaseCounterB + framesThisStep * 0x32;
    if (gEffect16SinPhaseCounterB > 0x7fff) {
        gEffect16SinPhaseCounterB = 0;
    }
    gEffect16SinValueB = mathSinf(3.1415927f * (f32)(s16)gEffect16SinPhaseCounterB / 32768.0f);
}

void Effect16_func03_nop(void) {
}

void Effect16_release(void) {
}

void Effect16_initialise(void) {
}
