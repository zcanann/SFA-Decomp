#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "game/objects/object.h"
#include "main/frame_timing.h"
#include "main/maketex_random_api.h"
#include "main/dll/dll_0021_effect8.h"
#include "main/vecmath.h"

f32 gModgfxSineWaveA;
f32 gModgfxSineWaveB;
int gModgfxSinePhaseB;
int gModgfxSinePhaseA;

f32 gEffect8SpawnPhaseA = 0.1f;
f32 gEffect8SpawnPhaseB = 0.3f;
f32 gEffect8FramePhaseA = 0.1f;
f32 gEffect8FramePhaseB = 0.3f;

PartFxSpawnParams gEffect8DefaultSpawnParams;

ObjectDescriptor6 Effect8_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)Effect8_initialise,
    (ObjectDescriptorCallback)Effect8_release,
    0,
    (ObjectDescriptorCallback)Effect8_func03_nop,
    (ObjectDescriptorCallback)Effect8_spawnObject,
    (ObjectDescriptorCallback)Effect8_updateFrameState,
};

#define FILL8()                                                                                                        \
    do {                                                                                                               \
        gEffect8DefaultSpawnParams.posX = 0.0f;                                                                        \
        gEffect8DefaultSpawnParams.posY = 0.0f;                                                                        \
        gEffect8DefaultSpawnParams.posZ = 0.0f;                                                                        \
        gEffect8DefaultSpawnParams.scale = 1.0f;                                                                       \
        gEffect8DefaultSpawnParams.unk0 = 0;                                                                           \
        gEffect8DefaultSpawnParams.unk2 = 0;                                                                           \
        gEffect8DefaultSpawnParams.unk4 = 0;                                                                           \
        spawnParams = &gEffect8DefaultSpawnParams;                                                                     \
    } while (0)

int Effect8_spawnObject(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                        s16* extraArgs) {
    int spawnResult;
    PartFxSpawn cfg;

    gEffect8SpawnPhaseA += 0.001f;
    if (gEffect8SpawnPhaseA > 1.0f) {
        gEffect8SpawnPhaseA = 0.1f;
    }
    gEffect8SpawnPhaseB += 0.0003f;
    if (gEffect8SpawnPhaseB > 1.0f) {
        gEffect8SpawnPhaseB = 0.3f;
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
    case 0x361:
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosX = (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0xc8;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x62;
        break;
    case 0x362:
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosX = (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0xc8;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x62;
        break;
    case 0x35f:
        cfg.startPosX = 0.2f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosZ = 0.2f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosY = 0.2f * (f32)(s32)randomGetRange(-0xa, 0x78);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(2, 0x64);
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180201;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0x9b00;
        cfg.overrideColor0 = 0x9600;
        cfg.overrideColor1 = 0x1400;
        cfg.overrideColor2 = 0x1400;
        cfg.renderFlags = 0x20;
        break;
    case 0x360:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.startPosY = 70.0f + (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.velocityX = 0.006f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityZ = 0.006f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0, 0x64);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x81008000;
        cfg.textureId = 0x208;
        break;
    case 0x357:
        if (spawnParams == 0) {
            FILL8();
        }
        if (spawnParams == 0) {
            return -1;
        }
        cfg.colorWord0 = (u16)((u8)spawnParams->unk4 << 8);
        cfg.colorWord1 = (u16)((u8)spawnParams->unk2 << 8);
        cfg.colorWord2 = (u16)((u8)spawnParams->unk0 << 8);
        cfg.overrideColor0 = 0xfe00;
        cfg.overrideColor1 = 0xfe00;
        cfg.overrideColor2 = 0xfe00;
        cfg.scale = 0.009f;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0x78;
        cfg.behaviorFlags = 0x8000201;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x71;
        break;
    case 0x359:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.startPosY = 70.0f + (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.velocityX = 0.006f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.006f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0, 0x64);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x81008000;
        cfg.impactEffectId = 0x284;
        cfg.textureId = 0x208;
        break;
    case 0x352:
        cfg.scale = 0.6f;
        cfg.lifetimeFrames = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0xa100208;
        cfg.textureId = 0x91;
        break;
    case 0x353:
        cfg.startPosX = (f32)(s32)randomGetRange(-2, 2);
        cfg.startPosZ = (f32)(s32)randomGetRange(-2, 2);
        cfg.velocityX = 0.0025f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = 0.0025f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0, 0x50);
        cfg.scale = 0.00003f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x17c) + 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80400109;
        cfg.textureId = 0x47;
        break;
    case 0x354:
        cfg.startPosX = (f32)(s32)randomGetRange(-4, 4);
        cfg.startPosZ = (f32)(s32)randomGetRange(-4, 4);
        cfg.startPosY = (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityX = 0.006f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.006f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0, 0x64);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x1000001;
        cfg.impactEffectId = 0x284;
        cfg.textureId = 0x208;
        break;
    case 0x355:
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x580101;
        cfg.textureId = 0x17c;
        break;
    case 0x356:
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.velocityY = -0.0001f * (f32)(s32)randomGetRange(0, 0x14);
        cfg.behaviorFlags = 0x80201;
        cfg.textureId = 0x62;
        break;
    case 0x35a:
        if (spawnParams == 0) {
            FILL8();
        }
        if (spawnParams == 0) {
            return -1;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.01f * (0.007f * (f32)(s32)spawnParams->unk4);
        cfg.lifetimeFrames = 0x3c;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = spawnParams->unk4 << 8;
        cfg.overrideColor1 = spawnParams->unk4 << 8;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x60;
        cfg.initialAlpha = spawnParams->unk4;
        cfg.behaviorFlags = 0x201;
        cfg.textureId = 0x76;
        break;
    case 0x35b:
        if (spawnParams == 0) {
            FILL8();
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x580101;
        cfg.textureId = 0xc22;
        break;
    case 0x35c:
        if (spawnParams == 0) {
            FILL8();
        }
        if (spawnParams == 0) {
            return -1;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.003f * (0.006f * (255.0f + (f32)(s32)spawnParams->unk0));
        cfg.lifetimeFrames = 0xa;
        cfg.colorWord0 = (u16)(spawnParams->unk0 << 8);
        cfg.colorWord1 = (u16)(spawnParams->unk0 << 8);
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = spawnParams->unk0 << 8;
        cfg.overrideColor1 = spawnParams->unk0 << 8;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = spawnParams->unk4;
        cfg.textureId = 0xc9d;
        break;
    case 0x35d:
        if (spawnParams == 0) {
            FILL8();
        }
        if (spawnParams == 0) {
            return -1;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.003f * (0.006f * (255.0f + (f32)(s32)spawnParams->unk0));
        cfg.lifetimeFrames = 0xa;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = (u16)(spawnParams->unk0 << 8);
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = 0xff00;
        cfg.overrideColor1 = spawnParams->unk0 << 8;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = spawnParams->unk4;
        cfg.textureId = 0xc9d;
        break;
    case 0x35e:
        if (spawnParams == 0) {
            FILL8();
        }
        cfg.scale = 0.06f;
        cfg.startPosY = 7.0f;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = spawnParams != 0 ? spawnParams->unk4 : 0xff;
        cfg.linkGroup = 0;
        cfg.startPosX = spawnParams != 0 ? spawnParams->posX : 0.0f;
        cfg.startPosY = spawnParams != 0 ? spawnParams->posY : 0.0f;
        cfg.startPosZ = spawnParams != 0 ? spawnParams->posZ : 0.0f;
        cfg.behaviorFlags = 0xa100200;
        cfg.textureId = 0x7d;
        break;
    case 0x367:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.startPosY = 0.9f;
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.velocityX = 0.004f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.006f * (f32)(s32)randomGetRange(0x64, 0xc8);
        cfg.velocityZ = 0.004f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(5, 0x19);
        cfg.lifetimeFrames = 0x7d0;
        cfg.initialAlpha = 0xe6;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosX = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.sourcePosY = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.renderFlags = 0x10000000;
        cfg.behaviorFlags = 0x8f000000;
        cfg.textureId = 0x56e;
        break;
    case 0x369:
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x580101;
        cfg.textureId = 0x17c;
        break;
    case 0x366:
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0x1f4, 0x3e8);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x12c, 0x12c);
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x12c, 0x12c);
        cfg.startPosY = 50.0f;
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x400000;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x62;
        cfg.initialAlpha = 0x50;
        break;
    case 0x365:
        cfg.velocityY = 0.008f * (f32)(s32)randomGetRange(0x6e, 0xc8);
        cfg.startPosZ = 0.05f * (f32)(s32)randomGetRange(-0x12c, 0x12c);
        cfg.startPosX = 0.05f * (f32)(s32)randomGetRange(-0x12c, 0x12c);
        cfg.scale = 0.00015f * (f32)(s32)randomGetRange(1, 0x14) + 0.001f;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosX = (f32)(s32)randomGetRange(0, 0x258);
        cfg.sourcePosY = (f32)(s32)randomGetRange(0, 0x258);
        cfg.sourcePosZ = (f32)(s32)randomGetRange(0, 0x258);
        {
            u16 r2;
            cfg.colorWord0 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
            r2 = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
            cfg.colorWord1 = r2;
            cfg.colorWord2 = 0x3caf;
            cfg.overrideColor0 = cfg.colorWord0;
            cfg.overrideColor1 = r2;
            cfg.overrideColor2 = 0x3caf;
        }
        cfg.renderFlags = 0x20;
        cfg.lifetimeFrames = randomGetRange(0, 0x3c) + 0x15e;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x86000008;
        cfg.textureId = 0x3a2;
        break;
    case 0x364:
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(5, 0x64);
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x50;
        {
            u16 r2;
            cfg.colorWord0 = (u16)(randomGetRange(0, 0x2710) + 0x63bf);
            r2 = (u16)(randomGetRange(0, 0x2710) + 0x3caf);
            cfg.colorWord1 = r2;
            cfg.colorWord2 = 0x3caf;
            cfg.overrideColor0 = cfg.colorWord0;
            cfg.overrideColor1 = r2;
            cfg.overrideColor2 = 0x3caf;
        }
        cfg.renderFlags = 0x20;
        cfg.behaviorFlags = (u32)randomChanceOneIn;
        cfg.textureId = 0x62;
        cfg.initialAlpha = 0xa0;
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
#undef FILL8

void Effect8_updateFrameState(void) {
    f32 sum;
    f32 step;
    sum = gEffect8FramePhaseA + (step = 0.001f * timeDelta);
    gEffect8FramePhaseA = sum;
    if (sum > 1.0f) {
        gEffect8FramePhaseA = 0.1f;
    }
    sum = gEffect8FramePhaseB + step;
    gEffect8FramePhaseB = sum;
    if (sum > 1.0f) {
        gEffect8FramePhaseB = 0.3f;
    }
    gModgfxSinePhaseA = gModgfxSinePhaseA + framesThisStep * 0x64;
    if (gModgfxSinePhaseA > 0x7fff) {
        gModgfxSinePhaseA = 0;
    }
    gModgfxSineWaveA = mathSinf(3.1415927f * (f32)(s16)gModgfxSinePhaseA / 32768.0f);
    gModgfxSinePhaseB = gModgfxSinePhaseB + framesThisStep * 0x32;
    if (gModgfxSinePhaseB > 0x7fff) {
        gModgfxSinePhaseB = 0;
    }
    gModgfxSineWaveB = mathSinf(3.1415927f * (f32)(s16)gModgfxSinePhaseB / 32768.0f);
}

void Effect8_func03_nop(void) {
}

void Effect8_release(void) {
}

void Effect8_initialise(void) {
}
