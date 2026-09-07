#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/vecmath.h"
#include "game/objects/object.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/modgfx.h"
#include "main/frame_timing.h"
#include "main/dll/dll_001E_effect5.h"

f32 gEffect5SinValueA;
f32 gEffect5SinValueB;
int gEffect5SinPhaseB;
int gEffect5SinPhaseA;

f32 gEffect5AnimProgressA = 0.1f;
f32 gEffect5AnimProgressB = 0.3f;
f32 gEffect5AnimProgressC = 0.1f;
f32 gEffect5AnimProgressD = 0.3f;

ObjectDescriptor6 Effect5_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect5_initialise,
    (ObjectDescriptorCallback)Effect5_release,
    0,
    (ObjectDescriptorCallback)Effect5_func03_nop,
    (ObjectDescriptorCallback)Effect5_spawnObject,
    (ObjectDescriptorCallback)Effect5_updateFrameState,
};

int Effect5_spawnObject(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                        s16* extraArgs) {
    int spawnResult;
    MatrixTransform es;
    PartFxSpawn cfg;

    gEffect5AnimProgressA += 0.001f;
    if (gEffect5AnimProgressA > 1.0f) {
        gEffect5AnimProgressA = 0.1f;
    }
    gEffect5AnimProgressB += 0.0003f;
    if (gEffect5AnimProgressB > 1.0f) {
        gEffect5AnimProgressB = 0.3f;
    }
    if (sourceObj == 0) {
        return -1;
    }
    if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0) {
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
    cfg.impactEffectId = -1;
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
    switch (effectId) {
    case 0xc8:
        cfg.startPosX = (f32)(s32)randomGetRange(-6, 6);
        cfg.startPosY = (f32)(s32)randomGetRange(-6, 6);
        cfg.startPosZ = (f32)(s32)randomGetRange(-6, 6);
        cfg.scale = 0.009f * (f32)(s32)randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x24;
        cfg.initialAlpha = 0x41;
        cfg.behaviorFlags = 0x100111;
        cfg.textureId = 0xc10;
        break;
    case PARTFX_DIG_DEBRIS:
        if (spawnParams == 0) {
            return 0;
        }
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.02f * (f32)(s32)randomGetRange(0x14, 0x1e);
        es.x = 0.0f;
        es.y = 0.0f;
        es.z = 0.0f;
        es.scale = 1.0f;
        es.rotZ = 0;
        es.rotY = 0;
        es.rotX = spawnParams->dig.yaw;
        vecRotateZXY(&es.rotX, &cfg.velocityX);
        cfg.scale = 0.002f * (f32)(s32)randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x180108;
        cfg.renderFlags = 0x5000000;
        if (spawnParams->dig.variant == 0) {
            cfg.textureId = 0x2b;
        } else if (spawnParams->dig.variant == 1) {
            cfg.textureId = 0x1a1;
        } else if (spawnParams->dig.variant == 2) {
            cfg.textureId = 0xc10;
            cfg.renderFlags |= 0x800;
        } else {
            cfg.textureId = 0x2b;
        }
        break;
    case PARTFX_DIG_DUST:
        if (spawnParams == 0) {
            return 0;
        }
        cfg.velocityX = 0.025f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.045f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(0x14, 0x1e);
        es.x = 0.0f;
        es.y = 0.0f;
        es.z = 0.0f;
        es.scale = 1.0f;
        es.rotZ = 0;
        es.rotY = 0;
        es.rotX = spawnParams->dig.yaw;
        vecRotateZXY(&es.rotX, &cfg.velocityX);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x1080100;
        cfg.renderFlags = 0x5000000;
        if (spawnParams->dig.variant == 0) {
            cfg.textureId = 0x2b;
        } else if (spawnParams->dig.variant == 1) {
            cfg.textureId = 0x1a1;
        } else if (spawnParams->dig.variant == 2) {
            cfg.textureId = 0xc10;
            cfg.renderFlags |= 0x800;
        } else {
            cfg.textureId = 0x2b;
        }
        break;
    case 0xcc:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.startPosY = 180.0f * (f32)(s32)randomGetRange(1, 2);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityX = 0.04f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.04f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.0004f * (f32)(s32)randomGetRange(4, 8);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80108;
        cfg.textureId = 0x5c;
        break;
    case 0xcd:
        cfg.startPosX = (f32)(s32)randomGetRange(0, 0xfa);
        {
            f32 rnd = (f32)(s32)randomGetRange(-5, 5);
            f32 baseY = 20.0f + cfg.startPosX / 20.0f;
            cfg.startPosY = baseY + rnd;
        }
        cfg.startPosZ = 0.7f * cfg.startPosX;
        cfg.scale = 0.00004f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x80080118;
        cfg.textureId = 0x5c;
        break;
    case 0xce:
        cfg.startPosX = 290.0f + (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosY = 40.0f + (f32)(s32)randomGetRange(-8, 8);
        cfg.startPosZ = 175.0f + (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.03f * (f32)(s32)randomGetRange(0, 0xa);
        cfg.scale = 0.0003f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(80.0f + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xcf:
        cfg.startPosX = -(f32)(s32)randomGetRange(0, 0xfa);
        {
            f32 rnd = (f32)(s32)randomGetRange(-5, 5);
            f32 baseY = 20.0f + cfg.startPosX / 20.0f;
            cfg.startPosY = baseY + rnd;
        }
        cfg.startPosZ = -cfg.startPosX;
        cfg.scale = 0.00004f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x80080118;
        cfg.textureId = 0x5c;
        break;
    case 0xd0:
        cfg.startPosX = -305.0f + (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosY = 40.0f + (f32)(s32)randomGetRange(-8, 8);
        cfg.startPosZ = 300.0f + (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.03f * (f32)(s32)randomGetRange(0, 0xa);
        cfg.scale = 0.0003f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(80.0f + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xd1:
        cfg.scale = 0.0003f * (f32)(s32)randomGetRange(0x46, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0xf) + 0x14;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x180210;
        cfg.textureId = 0x159;
        break;
    case 0xd2:
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x400000;
        cfg.textureId = 0x159;
        break;
    case 0xd3:
        cfg.startPosX = -(f32)(s32)randomGetRange(0, 0xfa);
        cfg.startPosY = 10.0f + (f32)(s32)randomGetRange(-5, 5);
        cfg.startPosZ = (f32)(s32)randomGetRange(-5, 5);
        cfg.velocityZ = 0.1f * (f32)(s32)randomGetRange(-5, 5);
        cfg.scale = 0.00006f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xa0;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x180108;
        cfg.textureId = 0x5c;
        break;
    case 0xd4:
        cfg.startPosX = (f32)(s32)randomGetRange(-0xa, 0x14);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x1c);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(0, 0xa);
        cfg.scale = 0.0013f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(110.0f + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xd5:
        cfg.scale = 0.004f;
        cfg.impactEffectId = 0xd6;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80000;
        cfg.textureId = 0x159;
        break;
    case 0xd6:
        cfg.scale = 0.004f;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x159;
        break;
    case 0xd7:
        cfg.startPosX = 0.08f * (f32)(s32)randomGetRange(-0x8c, 0x8c);
        cfg.startPosY = 0.08f * (f32)(s32)randomGetRange(-0x32, 0xa);
        cfg.startPosZ = 0.08f * (f32)(s32)randomGetRange(-0x8c, 0x8c);
        cfg.velocityY = 0.0035f * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.scale = 0.0015f * (f32)(s32)randomGetRange(1, 0xa);
        cfg.lifetimeFrames = 0x8c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80180100;
        cfg.textureId = 0x5f;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags |= spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) {
        cfg.behaviorFlags ^= 2;
    }
    if ((cfg.behaviorFlags & 1) != 0) {
        if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0) {
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

void Effect5_updateFrameState(void) {
    f32 sum;
    f32 step;
    sum = gEffect5AnimProgressC + (step = 0.001f * timeDelta);
    gEffect5AnimProgressC = sum;
    if (sum > 1.0f) {
        gEffect5AnimProgressC = 0.1f;
    }
    sum = gEffect5AnimProgressD + step;
    gEffect5AnimProgressD = sum;
    if (sum > 1.0f) {
        gEffect5AnimProgressD = 0.3f;
    }
    gEffect5SinPhaseA = gEffect5SinPhaseA + framesThisStep * 0x64;
    if (gEffect5SinPhaseA > 0x7fff) {
        gEffect5SinPhaseA = 0;
    }
    gEffect5SinValueA = mathSinf(3.14159274f * (f32)(s16)gEffect5SinPhaseA / 32768.0f);
    gEffect5SinPhaseB = gEffect5SinPhaseB + framesThisStep * 0x32;
    if (gEffect5SinPhaseB > 0x7fff) {
        gEffect5SinPhaseB = 0;
    }
    gEffect5SinValueB = mathSinf(3.14159274f * (f32)(s16)gEffect5SinPhaseB / 32768.0f);
}

void Effect5_func03_nop(void) {
}

void Effect5_release(void) {
}

void Effect5_initialise(void) {
}
