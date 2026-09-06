#include "main/dll/partfxspawn_struct.h"
#include "main/vecmath.h"
#include "main/dll_000A_expgfx.h"
#include "game/objects/object.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/dll/dll_001A_effect1.h"

f32 gEffect1SineWaveA;
f32 gEffect1SineWaveB;
int gEffect1SineWaveBPhase;
int gEffect1SineWaveAPhase;

f32 gEffect1AnimRampC = 0.1f;
f32 gEffect1AnimRampD = 0.3f;
f32 gEffect1AnimRampA = 0.1f;
f32 gEffect1AnimRampB = 0.3f;

PartFxSpawnParams gEffect1DefaultSpawnParams;

#define FILL320()                                                                                                      \
    do {                                                                                                               \
        gEffect1DefaultSpawnParams.posX = 0.0f;                                                                        \
        gEffect1DefaultSpawnParams.posY = 0.0f;                                                                        \
        gEffect1DefaultSpawnParams.posZ = 0.0f;                                                                        \
        gEffect1DefaultSpawnParams.scale = 1.0f;                                                                       \
        gEffect1DefaultSpawnParams.unk0 = 0;                                                                           \
        gEffect1DefaultSpawnParams.unk2 = 0;                                                                           \
        gEffect1DefaultSpawnParams.unk4 = 0;                                                                           \
        spawnParams = &gEffect1DefaultSpawnParams;                                                                     \
    } while (0)

int Effect1_spawnObject(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                        s16* extraArgs) {
    int spawnResult;
    MatrixTransform es;
    PartFxSpawn cfg;

    gEffect1AnimRampC += 0.001f;
    if (gEffect1AnimRampC > 1.0f) {
        gEffect1AnimRampC = 0.1f;
    }
    gEffect1AnimRampD += 0.0003f;
    if (gEffect1AnimRampD > 1.0f) {
        gEffect1AnimRampD = 0.3f;
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
    cfg.textureSetupFlags = 0;
    switch (effectId) {
    case 0x5fc:
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x5c;
        break;
    case 0x5fb:
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xe7;
        break;
    case 0x5fa:
        cfg.startPosX = 0.06f * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.startPosZ = 0.06f * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0x320, 0x4b0);
        cfg.scale = 0.00246f;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x26c;
        break;
    case 0x5f9:
        cfg.startPosX = 0.05f * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.startPosZ = 0.05f * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.velocityY = 0.00035f * (f32)(s32)randomGetRange(0x320, 0x4b0);
        cfg.scale = 0.0016f;
        cfg.lifetimeFrames = 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480100;
        cfg.renderFlags = 0x2000000;
        cfg.quadVertex3Pad06 = 0x5e9;
        cfg.textureId = 0x26c;
        break;
    case 0x5e9:
        cfg.scale = 0.0016f;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x26c;
        break;
    case 0x3a7:
        cfg.scale = 0.026f;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1c0100;
        cfg.textureId = 0x73;
        break;
    case 0x3a5:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams != 0) {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        } else {
            cfg.startPosZ = 15.0f;
            cfg.startPosY = 1e+01f;
        }
        cfg.velocityZ = 0.012f * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(-0x4, 0x4);
        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(0xa, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x8e;
        cfg.behaviorFlags = 0x40180100;
        break;
    case 0x3a6:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams != 0) {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        } else {
            cfg.startPosZ = 15.0f;
            cfg.startPosY = 1e+01f;
        }
        cfg.velocityZ = 0.018f * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(-0x4, 0x4);
        cfg.scale = 2e-05f * (f32)(s32)randomGetRange(0x28, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0x3c) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0a;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x42000100;
        break;
    case 0x3a3:
        cfg.scale = 0.06f;
        cfg.lifetimeFrames = 0x4;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0x64;
        cfg.initialAlpha = 0x9b;
        break;
    case 0x3a4:
        cfg.velocityX = 1.9e-05f * (f32)(s32)randomGetRange(0x19, 0x64);
        cfg.velocityY = 0.000282f * (f32)(s32)randomGetRange(0x42, 0x64);
        cfg.velocityZ = 2.8e-05f * (f32)(s32)randomGetRange(0x11, 0x64);
        cfg.startPosX = 0.031527f * (f32)(s32)randomGetRange(-0x64, 0x64);
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.036577f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = 0.000415f * (f32)(s32)randomGetRange(0x27, 0x50);
        cfg.lifetimeFrames = randomGetRange(0x14, 0x20) + 0xdb;
        cfg.textureId = 0x20c;
        cfg.colorWord0 = 0x10000 - 0x1d0b;
        cfg.colorWord1 = 0x5308;
        cfg.colorWord2 = 0x42d9;
        cfg.overrideColor0 = 0x10000 - 0x7502;
        cfg.overrideColor1 = 0x5866;
        cfg.overrideColor2 = 0x40c3;
        cfg.initialAlpha = randomGetRange(0xd, 0x53);
        cfg.behaviorFlags = 0x480208;
        cfg.renderFlags = 0x8002820;
        break;
    case 0x3a8:
    case 0x3a2:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams == 0) {
            return -1;
        }
        cfg.velocityX = spawnParams->scale * (0.003604f * (f32)(s32)randomGetRange(-0x64, 0x64));
        cfg.velocityY = spawnParams->scale * (0.013278f * (f32)(s32)randomGetRange(0x50, 0x8c));
        cfg.velocityZ = spawnParams->scale * (0.00414f * (f32)(s32)randomGetRange(-0x64, 0x64));
        cfg.startPosX = 0.03698f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosY = 1e+01f;
        cfg.startPosZ = 0.048008f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = spawnParams->scale * (0.00055949995f * (f32)(s32)randomGetRange(0x16, 0x46));
        cfg.lifetimeFrames = randomGetRange(0xe, 0x30) + 0x29;
        cfg.textureId = 0x60;
        cfg.colorWord0 = 0x10000 - 0x108b;
        cfg.colorWord1 = 0x10000 - 0x3d92;
        cfg.colorWord2 = 0x4aab;
        cfg.overrideColor0 = 0x10000 - 0x161;
        cfg.overrideColor1 = 0x796c;
        cfg.overrideColor2 = 0x57a0;
        cfg.initialAlpha = randomGetRange(0x29, 0x64);
        cfg.behaviorFlags = 0x80080108;
        if (effectId == 0x3a2) {
            cfg.behaviorFlags |= 0x20000000;
        }
        cfg.renderFlags = 0x8400820;
        break;
    case 0x3a1:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams == 0) {
            return -1;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = 2e+01f + spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityZ = 0.1f * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(-0x14, 0x14);
        es.x = 0.0f;
        es.y = 0.0f;
        es.z = 0.0f;
        es.scale = 1.0f;
        es.rotZ = ((s16*)sourceObj)[2];
        es.rotY = ((s16*)sourceObj)[1];
        es.rotX = *(s16*)sourceObj;
        vecRotateZXY(&es.rotX, &cfg.velocityX);
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x167;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x2000110;
        break;
    case 0x3a0:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams == 0) {
            return -1;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = 2e+01f + spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityZ = 0.04f * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.velocityX = 0.012f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.015f * (f32)(s32)randomGetRange(2, 6);
        es.x = 0.0f;
        es.y = 0.0f;
        es.z = 0.0f;
        es.scale = 1.0f;
        es.rotZ = ((s16*)sourceObj)[2];
        es.rotY = ((s16*)sourceObj)[1];
        es.rotX = *(s16*)sourceObj;
        vecRotateZXY(&es.rotX, &cfg.velocityX);
        cfg.scale = 0.002f * (f32)(s32)randomGetRange(8, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x78);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x1400020;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x7f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x3caf;
        cfg.overrideColor1 = 0x3caf;
        cfg.overrideColor2 = 0x3caf;
        break;
    case 0x39f:
        cfg.velocityY = 0.042f * (f32)(s32)randomGetRange(0xa, 0xe);
        cfg.scale = 0.007f;
        cfg.lifetimeFrames = 0x1;
        cfg.initialAlpha = 0x23;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x64;
        break;
    case 0x39a:
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.00125f;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x17c;
        break;
    case 0x39b:
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x17c;
        break;
    case 0x39c:
        cfg.initialAlpha = 0x37;
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x17c;
        break;
    case 0x39d:
        cfg.initialAlpha = 0x87;
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2000;
        cfg.textureId = 0x17c;
        break;
    case 0x39e:
        cfg.velocityZ = 0.002f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityX = 0.002f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.initialAlpha = 0x87;
        cfg.scale = 5e-06f * (f32)(s32)randomGetRange(0x320, 0x4b0);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0x1480200;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0x17c;
        break;
    case 0x399:
        if (spawnParams == 0) {
            FILL320();
        }
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosX = 0.0f;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourceScale = 1.0f;
        if (spawnParams != 0) {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = 12.0f + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.sourceVecX = spawnParams->rotX;
            cfg.sourceVecZ = spawnParams->rotZ;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.033f;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x6100100;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x64;
        break;
    case 0x397:
        cfg.startPosX = 0.01f * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.startPosZ = 0.01f * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.velocityY = 0.00015f * (f32)(s32)randomGetRange(0x320, 0x4b0);
        cfg.scale = 0.0006f;
        cfg.lifetimeFrames = 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080110;
        cfg.quadVertex3Pad06 = 0x398;
        cfg.textureId = 0xc0d;
        break;
    case 0x398:
        cfg.scale = 0.0006f;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0xc0d;
        break;
    case 0x5f7:
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.55f;
        cfg.lifetimeFrames = 0x73;
        cfg.behaviorFlags = 0x8100110;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x77;
        break;
    case 0x5f6:
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.000725f;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x202;
        cfg.textureId = 0x26c;
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.003f;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x528;
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.initialAlpha = 0x37;
        cfg.scale = 0.015f;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x528;
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.initialAlpha = 0x87;
        cfg.scale = 0.003f;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2002;
        cfg.textureId = 0x528;
        break;
    case 0x5f5:
        cfg.velocityX = 0.00025f * (f32)(s32)randomGetRange(-0x384, 0x384);
        cfg.velocityZ = 0.00025f * (f32)(s32)randomGetRange(-0x384, 0x384);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.0055f;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x110;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0xe4;
        break;
    case 0x5f4:
        cfg.startPosX = 0.005f * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = 0.005f * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.velocityZ = 0.00025f * (f32)(s32)randomGetRange(0x12c, 0x190);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.00025f;
        cfg.lifetimeFrames = 0x8c;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x528;
        break;
    case 0x5f0:
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.00125f;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x26c;
        break;
    case 0x5f1:
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x528;
        break;
    case 0x5f2:
        cfg.initialAlpha = 0x37;
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x528;
        break;
    case 0x5f3:
        cfg.initialAlpha = 0x87;
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2000;
        cfg.textureId = 0x528;
        break;
    case 0x5ef:
        cfg.startPosX = 0.001f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.startPosZ = 0.001f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.velocityY = 3.0f;
        cfg.initialAlpha = 0x9b;
        cfg.scale = 0.0025f;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x3f2;
        break;
    case 0x5ee:
        cfg.velocityZ = -0.002f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = -0.002f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.0015f;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x2000100;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x33;
        break;
    case 0x5f8:
        cfg.velocityX = -0.002f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = -0.002f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.0015f;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x2000100;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x33;
        break;
    case 0x5ed:
        if (spawnParams == 0) {
            FILL320();
        }
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosX = 0.0f;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourceScale = 1.0f;
        if (spawnParams != 0) {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = 12.0f + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.sourceVecX = spawnParams->rotX;
            cfg.sourceVecZ = spawnParams->rotZ;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.033f;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x6100100;
        cfg.textureId = 0x5fe;
        break;
    case 0x5fd:
        if (spawnParams == 0) {
            FILL320();
        }
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosX = 0.0f;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourceScale = 1.0f;
        if (spawnParams != 0) {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = 12.0f + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.sourceVecX = spawnParams->rotX;
            cfg.sourceVecZ = spawnParams->rotZ;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.033f * (f32)(s32)randomGetRange(1, 3);
        cfg.lifetimeFrames = randomGetRange(0, 0x64) + 0x78;
        cfg.behaviorFlags = 0x6100000;
        cfg.renderFlags = 0x10000 - 0x8000;
        cfg.textureId = 0x5ff;
        break;
    case 0x5eb:
        cfg.velocityZ = -0.0025f * (f32)(s32)randomGetRange(0xb4, 0xc8);
        cfg.velocityX = -0.002f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0, 0x28);
        cfg.initialAlpha = 0x9b;
        cfg.scale = 0.04f;
        cfg.lifetimeFrames = randomGetRange(0x8c, 0xa5);
        cfg.behaviorFlags = 0x81100000;
        cfg.renderFlags = (u32)(0x410000 - 0x7fe0);
        cfg.colorWord0 = 0x7d0;
        cfg.colorWord1 = 0x7d0;
        cfg.colorWord2 = randomGetRange(-0x1388, 0x1388) + 0x2710;
        cfg.overrideColor0 = 0x1f40;
        cfg.overrideColor1 = 0x1f40;
        cfg.overrideColor2 = randomGetRange(-0x1388, 0x1388) + 0x2ee0;
        cfg.textureId = 0x639;
        break;
    case 0x5ea:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x19, 0x19);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x19, 0x19);
        cfg.initialAlpha = 0x9b;
        cfg.scale = 0.015f;
        cfg.lifetimeFrames = randomGetRange(0x46, 0x64);
        cfg.behaviorFlags = 0x81100000;
        cfg.renderFlags = (u32)(0x410000 - 0x7fe0);
        cfg.colorWord0 = 0x7d0;
        cfg.colorWord1 = 0x7d0;
        cfg.colorWord2 = randomGetRange(-0x1388, 0x1388) + 0x4e20;
        cfg.overrideColor0 = 0x1f40;
        cfg.overrideColor1 = 0x1f40;
        cfg.overrideColor2 = randomGetRange(-0x1388, 0x1388) + 0x7d00;
        cfg.textureId = 0x639;
        break;
    case 0x5e3:
        cfg.scale = 9.8e-05f * (f32)(s32)randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0xf0;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x156;
        break;
    case 0x5e4:
        cfg.scale = 9.8e-05f * (f32)(s32)randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0xf0;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x156;
        break;
    case 0x5e5:
        cfg.scale = 0.0198f;
        cfg.lifetimeFrames = 0xf0;
        cfg.initialAlpha = 0xb9;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x156;
        break;
    case 0x5e6:
        cfg.scale = 9.8e-05f * (f32)(s32)randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0x12c;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x156;
        break;
    case 0x5e7:
        cfg.scale = 9.8e-05f * (f32)(s32)randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0x6;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x156;
        break;
    case 0x5e8:
        cfg.scale = 0.0198f;
        cfg.lifetimeFrames = 0x6;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x156;
        break;
    case 0x5dd:
        cfg.startPosZ = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.startPosY = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.velocityX = 0.08f * (f32)(s32)randomGetRange(5, 0xf);
        cfg.velocityY = cfg.startPosY / 1e+02f;
        cfg.velocityZ = cfg.startPosZ / 1e+02f;
        cfg.scale = 0.00018f * (f32)(s32)randomGetRange(5, 0xf);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0xc79;
        break;
    case 0x5de:
        cfg.startPosZ = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.startPosY = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.velocityX = 0.08f * (f32)(s32)randomGetRange(5, 0xf);
        cfg.velocityY = cfg.startPosY / 1e+02f;
        cfg.velocityZ = cfg.startPosZ / 1e+02f;
        cfg.scale = 0.00018f * (f32)(s32)randomGetRange(5, 0xf);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x166;
        break;
    case 0x5df:
        cfg.startPosZ = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.startPosY = (f32)(s32)randomGetRange(-0xc, 0xc);
        cfg.velocityX = 0.08f * (f32)(s32)randomGetRange(5, 0xf);
        cfg.velocityY = cfg.startPosY / 1e+02f;
        cfg.velocityZ = cfg.startPosZ / 1e+02f;
        cfg.scale = 0.00018f * (f32)(s32)randomGetRange(5, 0xf);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x528;
        break;
    case 0x5e0:
        cfg.velocityX = -0.000174f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.scale = 0.043483f;
        cfg.lifetimeFrames = 0x39;
        cfg.textureId = 0xc76;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0x7fff;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80500100;
        cfg.renderFlags = 0x8000800;
        break;
    case 0x5e1:
        cfg.velocityX = -0.000174f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.scale = 0.043483f;
        cfg.lifetimeFrames = 0x39;
        cfg.textureId = 0xc74;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0x7fff;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80500100;
        cfg.renderFlags = 0x8000800;
        break;
    case 0x5e2:
        cfg.velocityX = -0.000174f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.scale = 0.043483f;
        cfg.lifetimeFrames = 0x39;
        cfg.textureId = 0xc75;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0x7fff;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80500100;
        cfg.renderFlags = 0x8000800;
        break;
    case 0x396:
        cfg.scale = 0.026f;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1c0100;
        cfg.textureId = 0x159;
        break;
    case 0x394:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams != 0) {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosX = spawnParams->posZ;
        }
        cfg.sourceVecX = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.sourceVecY = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.sourceVecX = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.sourcePosX = 0.0f;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.scale = 0.0005f * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x2f);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x6100100;
        cfg.textureId = 0xc79;
        break;
    case 0x395:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams != 0) {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosX = spawnParams->posZ;
        }
        cfg.sourceVecX = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.sourceVecY = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.sourceVecX = (s16)(s32)randomGetRange(0, 0xffff);
        cfg.sourcePosX = 0.0f;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.scale = 0.005f * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.lifetimeFrames = randomGetRange(0x50, 0x64);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x6100110;
        cfg.textureId = 0xc79;
        break;
    case 0x393:
        cfg.startPosZ = (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x14);
        cfg.startPosX = 0.3f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.velocityY = 0.042f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.scale = 0.004245f;
        cfg.lifetimeFrames = randomGetRange(0x212, 0x2a8);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480208;
        cfg.textureId = 0xc0d;
        break;
    case 0x392:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = 0.02f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.scale = 0.00047f * (f32)(s32)randomGetRange(0xa, 0xf);
        cfg.lifetimeFrames = randomGetRange(0x5a, 0x8c);
        cfg.behaviorFlags = 0x80400201;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x390:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams != 0) {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        } else {
            cfg.startPosZ = 15.0f;
            cfg.startPosY = 1e+01f;
        }
        cfg.velocityZ = 0.012f * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(-0x4, 0x4);
        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(0xa, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x8e;
        cfg.behaviorFlags = 0x40180100;
        break;
    case 0x391:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams != 0) {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        } else {
            cfg.startPosZ = 15.0f;
            cfg.startPosY = 1e+01f;
        }
        cfg.velocityZ = 0.018f * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(-0x4, 0x4);
        cfg.scale = 2e-05f * (f32)(s32)randomGetRange(0x28, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0x3c) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0a;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x42000100;
        break;
    case 0x38f:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x8c, 0x8c);
        cfg.startPosY = (f32)(s32)randomGetRange(-0x28, 0x8c);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x8c, 0x8c);
        cfg.velocityX = 0.06f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.023f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityZ = 0.06f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = 0.0055f;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x167;
        cfg.renderFlags = 0x300000;
        cfg.behaviorFlags = 0x2000110;
        break;
    case 0x38a:
        if (spawnParams == 0) {
            FILL320();
        }
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xa, -0xa);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(-0x14, -0xa);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityX = 0.003f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.003f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.initialAlpha = 0xff;
        if (spawnParams != 0) {
            cfg.startPosX = cfg.startPosX + spawnParams->posX;
            cfg.startPosY = cfg.startPosY + spawnParams->posY;
            cfg.startPosZ = cfg.startPosZ + spawnParams->posZ;
        }
        cfg.scale = 0.00088f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x55;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x125;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = (randomGetRange(0, 0x2710) + 0x10000) - 0x2711;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = cfg.colorWord0 / 10;
        cfg.overrideColor1 = cfg.colorWord1 / 10;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0xa0;
        break;
    case 0x38b:
        cfg.scale = 0.00138f;
        cfg.lifetimeFrames = 0x4b;
        cfg.behaviorFlags = 0x82000108;
        cfg.renderFlags = 0x80;
        cfg.textureId = 0xc0a;
        cfg.initialAlpha = 0xff;
        break;
    case 0x38c:
        cfg.startPosY = 4e+01f;
        cfg.scale = 0.0068f;
        cfg.lifetimeFrames = 0x190;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x167;
        cfg.initialAlpha = 0x9b;
        break;
    case 0x38d:
        if (spawnParams == 0) {
            FILL320();
        }
        if (spawnParams != 0) {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.startPosY = 4e+02f;
        cfg.velocityX = 0.015f * (f32)(s32)randomGetRange(-0xa, 0xa) + 0.01f;
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.velocityZ = 0.015f * (f32)(s32)randomGetRange(-0xa, 1) + 0.01f;
        cfg.scale = 0.0038f;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x3010000 - 0x8000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x167;
        cfg.initialAlpha = 0xff;
        break;
    case 0x38e:
        cfg.velocityX = 0.15f * (f32)(s32)randomGetRange(-0xa, 0xa) + 0.01f;
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.velocityZ = 0.15f * (f32)(s32)randomGetRange(-0xa, 1) + 0.01f;
        cfg.scale = 0.0038f;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x167;
        cfg.initialAlpha = 0xff;
        break;
    case 0x389:
        if (spawnParams == 0) {
            FILL320();
        }
        cfg.startPosX = (f32)(s32)randomGetRange(-5, 5);
        cfg.startPosY = (f32)(s32)randomGetRange(1, 5);
        cfg.startPosZ = (f32)(s32)randomGetRange(-5, 5);
        es.scale = 0.003f * (f32)(s32)randomGetRange(0, 0x258) + 1.5f;
        cfg.velocityY = 0.001f * (f32)(s32)randomGetRange(0, 0xc8) + 1.0f;
        cfg.velocityX = 0.015f * (f32)(s32)randomGetRange(0, 0x14) + 0.1f;
        cfg.velocityY = cfg.velocityY * es.scale;
        cfg.velocityX = cfg.velocityX * es.scale;
        cfg.scale = 6e-05f * (f32)(s32)randomGetRange(0, 0xa) + 0.0048f;
        cfg.lifetimeFrames = randomGetRange(0xb4, 0xc8);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x3000120;
        cfg.renderFlags = 0x200800;
        cfg.textureId = 0xc0a;
        cfg.quadVertex3Pad06 = 0x385;
        break;
    case 0x388:
        cfg.startPosX = (f32)(s32)randomGetRange(0, 0x10);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x2e, 0x2e);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(0x10, 0x1e);
        cfg.scale = 0.0025f;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0x37;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x100;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x1fb;
        break;
    case 0x384:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x37, 0x37);
        cfg.startPosY = (f32)(s32)randomGetRange(0xa, 0xf);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x37, 0x37);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-8, 8);
        cfg.velocityY = 0.1f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-8, 8);
        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(0, 0xa) + 0.0028945f;
        cfg.lifetimeFrames = randomGetRange(0x78, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x385;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x1001100;
        cfg.textureId = 0xc0a;
        break;
    case 0x387:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x19, 0x19);
        cfg.startPosY = (f32)(s32)randomGetRange(1, 5);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x19, 0x19);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-8, 8);
        cfg.velocityY = 0.1f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-8, 8);
        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(0, 0xa) + 0.0028945f;
        cfg.lifetimeFrames = randomGetRange(0x78, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x385;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x81000120;
        cfg.textureId = 0xc0a;
        break;
    case 0x385:
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(2, 0x14);
        cfg.scale = 0.008445f;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = randomGetRange(0, 0xc350) + 0x3caf;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        break;
    case 0x386:
        cfg.startPosY = (f32)(s32)randomGetRange(1, 5);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(0, 0xa) + 0.0004245f;
        cfg.lifetimeFrames = randomGetRange(0xe6, 0x118);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xc0d;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) {
        cfg.behaviorFlags ^= 2;
    }
    if ((cfg.behaviorFlags & 1) != 0) {
        if ((spawnFlags & 0x200000) != 0) {
            cfg.startPosX = cfg.startPosX + cfg.sourcePosX;
            cfg.startPosY = cfg.startPosY + cfg.sourcePosY;
            cfg.startPosZ = cfg.startPosZ + cfg.sourcePosZ;
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
#undef FILL320

void Effect1_updateFrameState(void) {
    f32 sum;
    f32 step;
    sum = gEffect1AnimRampA + (step = 0.001f * timeDelta);
    gEffect1AnimRampA = sum;
    if (sum > 1.0f) {
        gEffect1AnimRampA = 0.1f;
    }
    sum = gEffect1AnimRampB + step;
    gEffect1AnimRampB = sum;
    if (sum > 1.0f) {
        gEffect1AnimRampB = 0.3f;
    }
    gEffect1SineWaveAPhase = gEffect1SineWaveAPhase + framesThisStep * 0x64;
    if (gEffect1SineWaveAPhase > 0x7fff) {
        gEffect1SineWaveAPhase = 0;
    }
    gEffect1SineWaveA = mathSinf(3.1415927f * (f32)(s16)gEffect1SineWaveAPhase / 32768.0f);
    gEffect1SineWaveBPhase = gEffect1SineWaveBPhase + framesThisStep * 0x32;
    if (gEffect1SineWaveBPhase > 0x7fff) {
        gEffect1SineWaveBPhase = 0;
    }
    gEffect1SineWaveB = mathSinf(3.1415927f * (f32)(s16)gEffect1SineWaveBPhase / 32768.0f);
}

void Effect1_func03_nop(void) {
}

void Effect1_release(void) {
}

void Effect1_initialise(void) {
}

ObjectDescriptor6 Effect1_funcs = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect1_initialise,
    (ObjectDescriptorCallback)Effect1_release,
    0,
    (ObjectDescriptorCallback)Effect1_func03_nop,
    (ObjectDescriptorCallback)Effect1_spawnObject,
    (ObjectDescriptorCallback)Effect1_updateFrameState,
};
