#include "main/dll/partfx_interface.h"
#include "main/dll/mtxbuildarg_struct.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/modgfx.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frame_timing.h"
#include "main/dll/dll_001D_effect4.h"

f32 gEffect4SinValueA;
f32 gEffect4SinValueB;
int gEffect4SinPhaseCounterB;
int gEffect4SinPhaseCounterA;

f32 gEffect4SpawnCyclePhaseFast = 0.1f;
f32 gEffect4SpawnCyclePhaseSlow = 0.3f;
f32 gEffect4TickCyclePhaseFast = 0.1f;
f32 gEffect4TickCyclePhaseSlow = 0.3f;




ObjectDescriptor6 lbl_803108A0 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)Effect4_initialise,
    (ObjectDescriptorCallback)Effect4_release,
    NULL,
    (ObjectDescriptorCallback)Effect4_func03_nop,
    (ObjectDescriptorCallback)Effect4_func04,
    (ObjectDescriptorCallback)Effect4_func05,
};

#define FILL9()                                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        lbl_8039C398.posX = 0.0f;                                                                                      \
        lbl_8039C398.posY = 0.0f;                                                                                      \
        lbl_8039C398.posZ = 0.0f;                                                                                      \
        lbl_8039C398.scale = 1.0f;                                                                                     \
        lbl_8039C398.unk0 = 0;                                                                                         \
        lbl_8039C398.unk2 = 0;                                                                                         \
        lbl_8039C398.unk4 = 0;                                                                                         \
        spawnParams = (PartFxSpawnParams*)&lbl_8039C398;                                                               \
    } while (0)

#undef FILL9

#define FILL8()                                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        lbl_8039C380.posX = 0.0f;                                                                                      \
        lbl_8039C380.posY = 0.0f;                                                                                      \
        lbl_8039C380.posZ = 0.0f;                                                                                      \
        lbl_8039C380.scale = 1.0f;                                                                                     \
        lbl_8039C380.unk0 = 0;                                                                                         \
        lbl_8039C380.unk2 = 0;                                                                                         \
        lbl_8039C380.unk4 = 0;                                                                                         \
        spawnParams = (PartFxSpawnParams*)&lbl_8039C380;                                                               \
    } while (0)

#undef FILL8

#define FILL338()                                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        lbl_8039C338.posX = lbl_803DF884;                                                                              \
        lbl_8039C338.posY = lbl_803DF884;                                                                              \
        lbl_8039C338.posZ = lbl_803DF884;                                                                              \
        lbl_8039C338.scale = lbl_803DF878;                                                                             \
        lbl_8039C338.unk0 = 0;                                                                                         \
        lbl_8039C338.unk2 = 0;                                                                                         \
        lbl_8039C338.unk4 = 0;                                                                                         \
        spawnParams = (PartFxSpawnParams*)&lbl_8039C338;                                                               \
    } while (0)

#undef FILL338

#define FILL368()                                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        lbl_8039C368.posX = lbl_803DFCEC;                                                                              \
        lbl_8039C368.posY = lbl_803DFCEC;                                                                              \
        lbl_8039C368.posZ = lbl_803DFCEC;                                                                              \
        lbl_8039C368.scale = lbl_803DFCE0;                                                                             \
        lbl_8039C368.unk0 = 0;                                                                                         \
        lbl_8039C368.unk2 = 0;                                                                                         \
        lbl_8039C368.unk4 = 0;                                                                                         \
        spawnParams = (PartFxSpawnParams*)&lbl_8039C368;                                                               \
    } while (0)

#undef FILL368

#define FILL350()                                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        lbl_8039C350.posX = lbl_803DF9D0;                                                                              \
        lbl_8039C350.posY = lbl_803DF9D0;                                                                              \
        lbl_8039C350.posZ = lbl_803DF9D0;                                                                              \
        lbl_8039C350.scale = lbl_803DF9D4;                                                                             \
        lbl_8039C350.unk0 = 0;                                                                                         \
        lbl_8039C350.unk2 = 0;                                                                                         \
        lbl_8039C350.unk4 = 0;                                                                                         \
        spawnParams = (PartFxSpawnParams*)&lbl_8039C350;                                                               \
    } while (0)

#undef FILL350

int Effect4_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   s16* extraArgs)
{
    int spawnResult;
    int randPick;
    MtxBuildArg es;
    PartFxSpawn cfg;

    gEffect4SpawnCyclePhaseFast += 0.001f;
    if (gEffect4SpawnCyclePhaseFast > 1.0f)
        gEffect4SpawnCyclePhaseFast = 0.1f;
    gEffect4SpawnCyclePhaseSlow += 0.0003f;
    if (gEffect4SpawnCyclePhaseSlow > 1.0f)
        gEffect4SpawnCyclePhaseSlow = 0.3f;
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
    cfg.startPosX = (0.0f);
    cfg.startPosY = (0.0f);
    cfg.startPosZ = (0.0f);
    cfg.velocityX = (0.0f);
    cfg.velocityY = (0.0f);
    cfg.velocityZ = (0.0f);
    cfg.scale = (0.0f);
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
    case 0x1c8:
        cfg.startPosY = (0.1f) * (f32)(s32)randomGetRange(0, 0x64);
        cfg.velocityX = (0.022f) * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityZ = cfg.velocityX * ((0.022f) * (f32)(s32)randomGetRange(-0x1e, 0x1e));
        cfg.scale = (3.5e-06f) * (f32)(s32)randomGetRange(0xc8, 0x118);
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80118;
        cfg.renderFlags = 0x8;
        cfg.textureId = 0x566;
        break;
    case 0x1c9:
        cfg.startPosZ = (12.0f);
        es.a = (0.0f);
        es.b = (0.0f);
        es.c = (0.0f);
        es.w = 1.0f;
        es.rz = 0;
        es.ry = 0;
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es.rotation.x, &cfg.startPosX);
        cfg.scale = (1.75e-05f) * (f32)(s32)randomGetRange(0xc8, 0x118);
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xe1;
        cfg.behaviorFlags = 0x400000;
        cfg.textureId = 0x4f9;
        break;
    case 0x1ca:
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.scale = (5e-05f) * (f32)(s32)randomGetRange(0xc8, 0x118);
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xe1;
        cfg.behaviorFlags = 0x400110;
        if ((int)randomGetRange(0, 2) == 0)
        {
            cfg.renderFlags = cfg.renderFlags | 0x100;
        }
        else
        {
            cfg.renderFlags = cfg.renderFlags | 0x400;
        }
        cfg.textureId = 0x4f9;
        break;
    case 0x1c7:
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x1c, 0x1c);
        cfg.startPosX = (f32)(s32)randomGetRange(-0x46, 0x46);
        cfg.startPosY = (f32)(s32)randomGetRange(0x82, 0xaa);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x46, 0x46);
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x190;
        cfg.initialAlpha = 0xff;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0;
        cfg.behaviorFlags = 0x80480108;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x33;
        break;
    case 0x1c5:
        cfg.startPosX = (4.5e+02f);
        es.a = (0.0f);
        es.b = (0.0f);
        es.c = (0.0f);
        es.w = 1.0f;
        es.rz = randomGetRange(0, 0xffff);
        es.ry = randomGetRange(0, 0xffff);
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es.rotation.x, &cfg.startPosX);
        cfg.scale = (0.005f);
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x33;
        break;
    case 0x1c4:
        cfg.startPosX = (3.5e+02f);
        es.a = (0.0f);
        es.b = (0.0f);
        es.c = (0.0f);
        es.w = 1.0f;
        es.rz = randomGetRange(0, 0xffff);
        es.ry = randomGetRange(0, 0xffff);
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es.rotation.x, &cfg.startPosX);
        cfg.scale = (0.008f);
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x26c;
        break;
    case 0x1c6:
        cfg.startPosX = (2.5e+02f) + (f32)(s32)randomGetRange(0, 0x5a);
        cfg.startPosY = (f32)(s32)randomGetRange(-0xa, 0xa);
        es.a = (0.0f);
        es.b = (0.0f);
        es.c = (0.0f);
        es.w = 1.0f;
        es.rz = 0;
        es.ry = 0;
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es.rotation.x, &cfg.startPosX);
        cfg.scale = (0.0002f) * (f32)(s32)randomGetRange(1, 0x14);
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480100;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x23c;
        break;
    case 0x1c3:
        cfg.velocityY = (0.1f);
        cfg.scale = (0.008f);
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0xa100110;
        cfg.textureId = 0x23b;
        break;
    case 0x190:
        cfg.scale = (0.0037f) * (f32)(s32)randomGetRange(1, 5);
        cfg.lifetimeFrames = randomGetRange(0xa, 0x14);
        cfg.renderFlags = 0x2;
        cfg.linkGroup = 0;
        cfg.textureId = 0xdf;
        break;
    case 0x191:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x8, 0x8);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x8, 0x8);
        cfg.velocityY = (0.05f) * (f32)(s32)randomGetRange(-0x3, 0x3);
        cfg.scale = (0.001f);
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x110;
        cfg.textureId = 0xde;
        break;
    case 0x192:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x9e, 0x9e);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x78);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0xd0, 0xd0);
        cfg.velocityY = (0.04f) * (f32)(s32)randomGetRange(-0x3, 0x3);
        cfg.scale = (0.065f);
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80080112;
        cfg.textureId = 0x1dd;
        break;
    case 0x193:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x9e, 0x9e);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x78);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x3a, 0x3a);
        cfg.velocityY = (0.05f) * (f32)(s32)randomGetRange(-0x3, 0x3);
        cfg.scale = (0.065f);
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80080112;
        cfg.textureId = 0xde;
        break;
    case 0x194:
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x3a, 0x3a);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0, 0x78);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x3a, 0x3a);
        cfg.startPosX = (f32)(s32)randomGetRange(-0x5, 0x5);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x5, 0x5);
        cfg.scale = (0.0015f);
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480110;
        cfg.renderFlags = 0x8;
        cfg.textureId = 0xde;
        break;
    case 0x195:
        cfg.scale = (0.0018f);
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480214;
        cfg.textureId = 0xde;
        break;
    case 0x196:
        cfg.startPosX = (0.1f) * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = (0.1f) * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityX = (0.0005f) * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.velocityY = (0.045f) * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.velocityZ = (0.0005f) * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.scale = (0.013f);
        cfg.lifetimeFrames = 0x78;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0x8acf;
        cfg.overrideColor0 = 0xafc8;
        cfg.overrideColor1 = 0x3a98;
        cfg.overrideColor2 = 0x5dc;
        cfg.behaviorFlags = 0x81080200;
        cfg.renderFlags = 0x24;
        cfg.textureId = 0x1dd;
        break;
    case 0x197:
        cfg.startPosX = (0.1f) * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = (0.1f) * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityX = (0.006f) * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.velocityY = (0.015f) * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.velocityZ = (0.006f) * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.colorWord0 = 0xf82f;
        cfg.colorWord1 = 0xf447;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xa7f8;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0;
        cfg.behaviorFlags = 0x80080610;
        cfg.renderFlags = 0x24;
        cfg.textureId = 0x1de;
        break;
    case 0x198:
        cfg.startPosY = (0.8f) * (f32)(s32)randomGetRange(0, 0x3c);
        cfg.scale = (0.035f);
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100200;
        cfg.textureId = 0x91;
        break;
    case 0x199:
        cfg.scale = (2e-06f) * (f32)(s32)randomGetRange(0, 0x32) + (0.0007f);
        cfg.lifetimeFrames = 0;
        cfg.initialAlpha = (u8)(randomGetRange(0, 0x37) + 0xc8);
        cfg.linkGroup = 0;
        randPick = randomGetRange(0, 2);
        if (randPick == 0)
        {
            cfg.textureId = 0x156;
        }
        else if (randPick == 1)
        {
            cfg.textureId = 0x157;
        }
        else if (randPick == 2)
        {
            cfg.textureId = 0xc0e;
        }
        cfg.behaviorFlags = 0x80011;
        cfg.renderFlags = 0x2;
        break;
    case 0x19a:
        cfg.scale = (2e-06f) * (f32)(s32)randomGetRange(0, 0x32) + (0.0012f);
        cfg.lifetimeFrames = 0xc;
        cfg.initialAlpha = 0x37;
        cfg.linkGroup = 0;
        cfg.textureId = 0x153;
        cfg.behaviorFlags = 0x180011;
        cfg.renderFlags = 0x2;
        break;
    case 0x19b:
        cfg.scale = (2e-06f) * (f32)(s32)randomGetRange(0, 0x32) + (0.0012f);
        cfg.lifetimeFrames = 0;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0;
        cfg.textureId = 0x153;
        cfg.behaviorFlags = 0x80011;
        cfg.renderFlags = 0x2;
        break;
    case 0x19c:
        cfg.scale = (0.0006f);
        cfg.lifetimeFrames = 0x2;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0;
        randPick = randomGetRange(0, 2);
        if (randPick == 0)
        {
            cfg.textureId = 0x156;
        }
        else if (randPick == 1)
        {
            cfg.textureId = 0x157;
        }
        else if (randPick == 2)
        {
            cfg.textureId = 0xc0e;
        }
        cfg.behaviorFlags = 0x480001;
        break;
    case 0x19d:
        cfg.scale = (0.0016f);
        cfg.lifetimeFrames = 0xf;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0;
        cfg.textureId = 0x153;
        cfg.behaviorFlags = 0x180201;
        break;
    case 0x19f:
        cfg.startPosX = (0.005f) * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosY = (0.005f) * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosZ = (0.005f) * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = (2.2e-05f) * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.lifetimeFrames = randomGetRange(0x37, 0x4b);
        cfg.initialAlpha = 0x37;
        cfg.textureId = 0xdb;
        cfg.behaviorFlags = 0x80080000;
        cfg.renderFlags = 0x4402800;
        break;
    case 0x1a0:
        cfg.scale = (8e-05f) * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.initialAlpha = 0x37;
        cfg.lifetimeFrames = 0xf;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdb;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x4000800;
        break;
    case 0x1bc:
        cfg.startPosX = (0.005f) * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosY = (0.005f) * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosZ = (0.005f) * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = (2.2e-05f) * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.lifetimeFrames = randomGetRange(0x8c, 0xa5);
        cfg.initialAlpha = 0x37;
        cfg.textureId = 0x167;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x4400000;
        break;
    case 0x1bd:
        cfg.scale = (8e-05f) * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.initialAlpha = 0x37;
        cfg.lifetimeFrames = 0xf;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0x64;
        cfg.behaviorFlags = 0x4080100;
        break;
    case 0x1a1:
        cfg.startPosX = (0.2f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = (0.2f) * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityX = (0.045f) * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = (0.02f) * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.scale = (0.0032f);
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x1a2;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x7b;
        break;
    case 0x1a2:
        cfg.scale = (0.0032f);
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x7b;
        break;
    case 0x1a3:
        cfg.startPosX = (0.1f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (0.1f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0, 0x1e) + (0.2f);
        cfg.scale = (0.00047f) * (f32)(s32)randomGetRange(1, 0xa);
        cfg.lifetimeFrames = randomGetRange(0x5a, 0x8c);
        cfg.behaviorFlags = 0x80500209;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x1a4:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = (1e+02f) + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.startPosY = (2.6e+02f);
            cfg.startPosZ = (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = (0.03f) * (f32)(s32)randomGetRange(0, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = (0.0004f) * (f32)(s32)randomGetRange(0, 0xa) + (0.000945f);
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.quadVertex3Pad06 = 0x281;
        cfg.behaviorFlags = 0x81488000;
        randPick = randomGetRange(0, 2);
        if (randPick == 0)
        {
            cfg.textureId = 0x208;
        }
        else if (randPick == 1)
        {
            cfg.textureId = 0x209;
        }
        else if (randPick == 2)
        {
            cfg.textureId = 0x20a;
        }
        break;
    case 0x1a5:
        if (spawnParams != 0)
        {
            if (spawnParams->scale <= 0.01f)
            {
                spawnParams->scale = 0.01f;
            }
            cfg.velocityY = -spawnParams->scale;
        }
        else
        {
            cfg.velocityY = (-0.03f) * (f32)(s32)randomGetRange(0, 0x14);
        }
        cfg.velocityX = (0.002f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = (0.002f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = (0.0001545f) * (f32)(s32)randomGetRange(2, 0xa);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x46);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480108;
        cfg.textureId = 0xc13;
        break;
    case 0x1a6:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.startPosY = (2.6e+02f);
            cfg.startPosZ = (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = (0.03f) * (f32)(s32)randomGetRange(0, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = (0.0004f) * (f32)(s32)randomGetRange(0, 0xa) + (0.000945f);
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.quadVertex3Pad06 = 0x281;
        cfg.behaviorFlags = 0x81488000;
        randPick = randomGetRange(0, 2);
        if (randPick == 0)
        {
            cfg.textureId = 0x208;
        }
        else if (randPick == 1)
        {
            cfg.textureId = 0x209;
        }
        else if (randPick == 2)
        {
            cfg.textureId = 0x20a;
        }
        cfg.colorWord0 = 0x3200;
        cfg.colorWord1 = 0x3200;
        cfg.colorWord2 = 0x7800;
        cfg.overrideColor0 = 0x3200;
        cfg.overrideColor1 = 0x3200;
        cfg.overrideColor2 = 0x7800;
        cfg.renderFlags = 0x20;
        break;
    case 0x1b6:
        if (spawnParams != 0)
        {
            cfg.velocityY = spawnParams->scale;
        }
        else
        {
            cfg.velocityY = (0.04f) * (f32)(s32)randomGetRange(-3, 3);
        }
        cfg.scale = (0.035f);
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x88100200;
        cfg.textureId = 0xc79;
        break;
    case 0x1a7:
        cfg.scale = (0.016f);
        cfg.lifetimeFrames = randomGetRange(0, 0xfa) + 0x96;
        cfg.linkGroup = 0;
        cfg.quadVertex3Pad06 = 0x1a8;
        cfg.behaviorFlags = 0x80490008;
        cfg.textureId = 0x167;
        break;
    case 0x1a8:
        cfg.scale = (0.026f);
        cfg.lifetimeFrames = 0xa;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480100;
        cfg.textureId = 0x167;
        break;
    case 0x1a9:
        if ((int)randomGetRange(0, 0x50) == 0)
        {
            cfg.lifetimeFrames = 0xf0;
            cfg.velocityX = (1.35f);
        }
        else
        {
            cfg.lifetimeFrames = 0x78;
            cfg.velocityX = (0.45f);
        }
        es.a = (0.0f);
        es.b = (0.0f);
        es.c = (0.0f);
        es.w = 1.0f;
        es.rz = randomGetRange(0, 0xffff);
        es.ry = randomGetRange(0, 0xffff);
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es.rotation.x, &cfg.velocityX);
        cfg.scale = (0.005f);
        cfg.linkGroup = 0x10;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0xdf;
        break;
    case 0x1b3:
        if (spawnParams == 0)
            return -1;
        cfg.velocityX = (0.0001f) * (f32)(s32)randomGetRange(-0xf, 0xf) + (0.001f);
        cfg.velocityY = (0.0001f) * (f32)(s32)randomGetRange(-0xf, 0xf) + (0.001f);
        cfg.velocityZ = (0.0001f) * (f32)(s32)randomGetRange(-0xf, 0xf) + (0.001f);
        cfg.startPosY = (35.0f);
        vecRotateZXY(&spawnParams->rotX, &cfg.velocityX);
        cfg.scale = (4e-05f) * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.initialAlpha = 0xff;
        cfg.lifetimeFrames = 0x64;
        cfg.linkGroup = 0x10;
        cfg.quadVertex3Pad06 = 0x1b4;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0x159;
        break;
    case 0x1b4:
        cfg.scale = (6e-05f) * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.initialAlpha = 0x37;
        cfg.lifetimeFrames = 0x14;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80201;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x159;
        break;
    case 0x1aa:
        if (spawnParams == 0)
            return -1;
        cfg.velocityX = (0.001f) * (f32)(s32)randomGetRange(0, 0x640) + (0.25f);
        vecRotateZXY(&spawnParams->rotX, &cfg.velocityX);
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.scale = (0.005f);
            cfg.initialAlpha = 0xff;
        }
        else
        {
            cfg.scale = (0.015f);
            cfg.initialAlpha = 0x9b;
        }
        cfg.lifetimeFrames = 0xf0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xdf;
        break;
    case 0x1af:
        if (spawnParams == 0)
            return -1;
        cfg.velocityX = spawnParams->posX * (f32)(s32)randomGetRange(-1, 1);
        cfg.velocityY = spawnParams->posX * (f32)(s32)randomGetRange(-1, 1);
        cfg.velocityZ = spawnParams->posX * (f32)(s32)randomGetRange(-1, 1);
        cfg.scale = (1.3e-05f) * (f32)(s32)randomGetRange(0x190, 0x1f4);
        cfg.initialAlpha = 0xff;
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0xa0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80080404;
        cfg.textureId = 0x5c;
        cfg.colorWord0 = 0xfffe;
        cfg.colorWord1 = 0x8ace;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0x4e20;
        cfg.overrideColor1 = 0x9c40;
        cfg.overrideColor2 = 0xfffe;
        cfg.renderFlags = 0x20;
        break;
    case 0x1b0:
        if (spawnParams == 0)
            return -1;
        cfg.startPosX = (0.4f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (0.4f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = (0.5f);
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (0.0f);
        cfg.sourcePosZ = (0.0f);
        cfg.sourcePosW = (0.0f);
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x6100214;
        cfg.textureId = 0x167;
        break;
    case 0x1b1:
        if (spawnParams == 0)
            return -1;
        cfg.startPosX = (0.4f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (0.4f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = spawnParams->posX * ((0.113f) * (f32)(s32)randomGetRange(1, 5));
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (0.0f);
        cfg.sourcePosZ = (0.0f);
        cfg.sourcePosW = (0.0f);
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x6100214;
        cfg.textureId = 0x30;
        break;
    case 0x1b2:
        cfg.velocityX = (0.12f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = (0.12f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = (0.12f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = (1.3e-05f) * (f32)(s32)randomGetRange(0xc8, 0x3e8);
        cfg.initialAlpha = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x3c;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x81480204;
        cfg.textureId = 0x30;
        break;
    case 0x1ae:
        cfg.velocityX = (0.12f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = (0.12f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = (0.12f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = (1.3e-05f) * (f32)(s32)randomGetRange(0xc8, 0x3e8);
        cfg.initialAlpha = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x3c;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480104;
        cfg.renderFlags = 8;
        cfg.textureId = 0x30;
        break;
    case 0x1ab:
        cfg.startPosX = (45.0f);
        es.a = (0.0f);
        es.b = (0.0f);
        es.c = (0.0f);
        es.w = 1.0f;
        es.rz = randomGetRange(0, 0xffff);
        es.ry = randomGetRange(0, 0xffff);
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es.rotation.x, &cfg.startPosX);
        cfg.velocityX = cfg.startPosX / (1e+02f);
        cfg.velocityY = cfg.startPosY / (1e+02f);
        cfg.velocityZ = cfg.startPosZ / (1e+02f);
        cfg.scale = (7e-06f) * (f32)(s32)randomGetRange(0xc8, 0x3e8);
        cfg.initialAlpha = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.lifetimeFrames = 0x50;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480504;
        cfg.textureId = 0x30;
        break;
    case 0x1ac:
        cfg.startPosX = (1.2f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = (1.2f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (1.2f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = (6.8e-05f) * (f32)(s32)randomGetRange(0x1f4, 0x3e8);
        cfg.initialAlpha = randomGetRange(0x9b, 0xff);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x1e;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80180104;
        cfg.textureId = 0x60;
        cfg.overrideColor0 = 0x6400;
        cfg.overrideColor1 = (randomGetRange(0, 0x55) + 0xaa) << 8;
        cfg.overrideColor2 = (randomGetRange(0, 0x37) + 0xc8) << 8;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.renderFlags = 0x20;
        break;
    case 0x1ad:
        cfg.startPosX = (0.4f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = (0.4f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (0.4f) * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = (6e-05f) * (f32)(s32)randomGetRange(0xc8, 0x5dc);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x1e;
        cfg.initialAlpha = (u8)(randomGetRange(0xb4, 0xc8) + 0x37);
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80580104;
        cfg.textureId = 0xc22;
        cfg.overrideColor0 = 0xc800;
        cfg.overrideColor1 = (randomGetRange(0, 0x37) + 0xc8) << 8;
        cfg.overrideColor2 = (randomGetRange(0, 0x19) + 0xe6) << 8;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.renderFlags = 0x20;
        break;
    case 0x1b9:
        cfg.startPosZ = 0.01f * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.startPosX = (-0.1f) * (f32)(s32)randomGetRange(0, 0x3e8) + (1e+01f);
        cfg.startPosY = (0.69f) * cfg.startPosX;
        cfg.velocityX = (-0.01f) * (f32)(s32)randomGetRange(0, 0xa) + (-0.15f);
        cfg.velocityY = (0.69f) * cfg.velocityX;
        cfg.scale = (0.00015f) * (f32)(s32)randomGetRange(1, 6);
        cfg.lifetimeFrames = 0xbe;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x6000100;
        cfg.textureId = 0x20;
        cfg.sourceVecZ = 0;
        cfg.sourceVecY = 0x5fb4;
        cfg.sourceVecX = -0x3fff;
        cfg.sourcePosY = (0.0f);
        cfg.sourcePosZ = (0.0f);
        cfg.sourcePosW = (0.0f);
        break;
    case 0x1bf:
        cfg.startPosX = (0.1f) * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosY = (0.1f) * (f32)(s32)randomGetRange(0, 0x3e8);
        cfg.startPosZ = (0.1f) * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityX = (0.03f) * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = (0.0065f) * (f32)(s32)randomGetRange(0x1f4, 0x258);
        cfg.velocityZ = (0.03f) * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = (0.0105f);
        cfg.lifetimeFrames = 0x15e;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x300020;
        cfg.behaviorFlags = 0x3008000;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x63bf;
        cfg.overrideColor1 = 0x9e7;
        cfg.overrideColor2 = 0x3e8;
        cfg.textureId = 0x23b;
        break;
    case 0x1c0:
        cfg.startPosX = (0.1f) * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.startPosZ = (0.1f) * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityY = (0.0065f) * (f32)(s32)randomGetRange(0x1f4, 0x258);
        cfg.scale = (0.0105f);
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x2000200;
        cfg.textureId = 0x23b;
        break;
    case 0x1c1:
        cfg.startPosX = (0.1f) * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.startPosZ = (0.1f) * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityY = (0.0025f) * (f32)(s32)randomGetRange(0x1f4, 0x258);
        cfg.scale = (0.002f) * (f32)(s32)randomGetRange(0x1e, 0x32);
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0x9b;
        cfg.renderFlags = 0x20;
        cfg.behaviorFlags = 0x80100;
        cfg.colorWord0 = randomGetRange(0, 0x7530) + 0x63bf;
        cfg.colorWord1 = cfg.colorWord0 / (int)randomGetRange(1, 3);
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = randomGetRange(0, 0x2710);
        cfg.overrideColor1 = (int)cfg.overrideColor0 / (int)randomGetRange(1, 3);
        cfg.overrideColor2 = 0;
        cfg.textureId = 0x60;
        break;
    case 0x1c2:
        cfg.startPosZ = (0.1f) * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = (0.1f) * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.velocityZ = (0.0065f) * (f32)(s32)randomGetRange(0xc8, 0x320);
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.velocityZ *= (-1.0f);
        }
        cfg.velocityY = (0.0065f) * (f32)(s32)randomGetRange(0xc8, 0x320);
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.velocityY *= (-1.0f);
        }
        cfg.scale = (0.008f);
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x14;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x2000200;
        cfg.textureId = 0x23b;
        break;
    case 0x1ba:
        cfg.startPosY = (1.3e+02f);
        cfg.startPosX = (0.1f) * (f32)(s32)randomGetRange(-0x3e8, 0x3e8);
        cfg.startPosZ = 0.01f * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = (0.69f) * cfg.startPosX;
        cfg.scale = (0.00035f) * (f32)(s32)randomGetRange(1, 6);
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x20;
        break;
    case 0x1b8:
        cfg.startPosX = 0.01f * (f32)(s32)randomGetRange(-0xbb8, 0xbb8);
        cfg.startPosZ = 0.01f * (f32)(s32)randomGetRange(-0xbb8, 0xbb8);
        cfg.scale = (0.003f) * (f32)(s32)randomGetRange(1, 4);
        cfg.lifetimeFrames = 0x5a;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x56;
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

void Effect4_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect4TickCyclePhaseFast + (step = (0.001f) * timeDelta);
    gEffect4TickCyclePhaseFast = sum;
    if (sum > 1.0f)
    {
        gEffect4TickCyclePhaseFast = (0.1f);
    }
    sum = gEffect4TickCyclePhaseSlow + step;
    gEffect4TickCyclePhaseSlow = sum;
    if (sum > 1.0f)
    {
        gEffect4TickCyclePhaseSlow = (0.3f);
    }
    gEffect4SinPhaseCounterA = gEffect4SinPhaseCounterA + framesThisStep * 0x64;
    if (gEffect4SinPhaseCounterA > 0x7fff)
    {
        gEffect4SinPhaseCounterA = 0;
    }
    gEffect4SinValueA = mathSinf(3.1415927f * (f32)(s16)gEffect4SinPhaseCounterA / 32768.0f);
    gEffect4SinPhaseCounterB = gEffect4SinPhaseCounterB + framesThisStep * 0x32;
    if (gEffect4SinPhaseCounterB > 0x7fff)
    {
        gEffect4SinPhaseCounterB = 0;
    }
    gEffect4SinValueB = mathSinf(3.1415927f * (f32)(s16)gEffect4SinPhaseCounterB / 32768.0f);
}

void Effect4_func03_nop(void)
{
}

void Effect4_release(void)
{
}

void Effect4_initialise(void)
{
}

#define FILL320()                                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        lbl_8039C320.posX = 0.0f;                                                                                      \
        lbl_8039C320.posY = 0.0f;                                                                                      \
        lbl_8039C320.posZ = 0.0f;                                                                                      \
        lbl_8039C320.scale = 1.0f;                                                                                     \
        lbl_8039C320.unk0 = 0;                                                                                         \
        lbl_8039C320.unk2 = 0;                                                                                         \
        lbl_8039C320.unk4 = 0;                                                                                         \
        spawnParams = (PartFxSpawnParams*)&lbl_8039C320;                                                               \
    } while (0)

#undef FILL320
