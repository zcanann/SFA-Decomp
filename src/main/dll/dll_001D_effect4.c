#include "main/dll/mtxbuildarg_struct.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/sfa_shared_decls.h"

void Effect4_func03_nop(void)
{
}

void Effect4_release(void)
{
}

void Effect4_initialise(void)
{
}

ObjectDescriptor11 projgfx_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
    projgfx_initialise,
    (ObjectDescriptorCallback)projgfx_release_doUnsupported,
    0,
    projgfx_onMapSetup,
    (ObjectDescriptorCallback)projgfx_func04_ret_m1,
    (ObjectDescriptorCallback)projgfx_func05_nop,
    (ObjectDescriptorCallback)projgfx_func06_nop,
    (ObjectDescriptorCallback)projgfx_func07_nop,
    (ObjectDescriptorCallback)projgfx_getObjectTypeId,
    (ObjectDescriptorCallback)projgfx_setzscale_doUnsupported,
    (ObjectDescriptorCallback)projgfx_rayhit_doUnsupported,
};

char sProjgfxRayhitDoNoLongerSupported[] = "<projgfx rayhit Do>No Longer supported \n";
static u8 sProjgfxStringPad0[] = {0, 0, 0};
char sProjgfxSetzscaleDoNoLongerSupported[] = "<projgfx setzscale  Do>No Longer supported \n";
static u8 sProjgfxStringPad1[] = {0, 0, 0};
char sProjgfxReleaseDoNoLongerSupported[] = "<projgfx release Do>No Longer supported \n";
static u8 sProjgfxStringPad2[] = {0, 0, 0, 0, 0, 0};

extern f32 timeDelta;
extern u8 framesThisStep;

extern f32 gEffect4TickCyclePhaseFast;
extern f32 gEffect4TickCyclePhaseSlow;
extern int gEffect4SinPhaseCounterA;
extern int gEffect4SinPhaseCounterB;
extern f32 gEffect4SinValueB;
extern f32 gEffect4SinValueA;
extern f32 lbl_803DF878;
extern f32 lbl_803DFA88;
extern f32 lbl_803DFA8C;
extern f32 lbl_803DFA90;
extern f32 lbl_803DFA98;
extern f32 gEffect4Pi;
extern f32 gEffect4SinPhaseScale;
extern f32 lbl_803DFCE0;

#pragma scheduling off
#pragma peephole off
void Effect4_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect4TickCyclePhaseFast + (step = lbl_803DFA88 * timeDelta);
    gEffect4TickCyclePhaseFast = sum;
    if (sum > 1.0f)
    {
        gEffect4TickCyclePhaseFast = lbl_803DFA8C;
    }
    sum = gEffect4TickCyclePhaseSlow + step;
    gEffect4TickCyclePhaseSlow = sum;
    if (sum > 1.0f)
    {
        gEffect4TickCyclePhaseSlow = lbl_803DFA98;
    }
    gEffect4SinPhaseCounterA = gEffect4SinPhaseCounterA + framesThisStep * 0x64;
    if (gEffect4SinPhaseCounterA > 0x7fff)
    {
        gEffect4SinPhaseCounterA = 0;
    }
    gEffect4SinValueA = mathSinf(gEffect4Pi * (f32)(s16)gEffect4SinPhaseCounterA / gEffect4SinPhaseScale);
    gEffect4SinPhaseCounterB = gEffect4SinPhaseCounterB + framesThisStep * 0x32;
    if (gEffect4SinPhaseCounterB > 0x7fff)
    {
        gEffect4SinPhaseCounterB = 0;
    }
    gEffect4SinValueB = mathSinf(gEffect4Pi * (f32)(s16)gEffect4SinPhaseCounterB / gEffect4SinPhaseScale);
}

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

extern FxNode9 lbl_8039C398;

#define FILL9() do {                            \
    lbl_8039C398.posX = 0.0f;             \
    lbl_8039C398.posY = 0.0f;            \
    lbl_8039C398.posZ = 0.0f;            \
    lbl_8039C398.scale = 1.0f;             \
    lbl_8039C398.unk0 = 0;                         \
    lbl_8039C398.unk2 = 0;                         \
    lbl_8039C398.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C398;             \
  } while (0)

#undef FILL9

extern FxNode9 lbl_8039C380;

#define FILL8() do {                            \
    lbl_8039C380.posX = 0.0f;             \
    lbl_8039C380.posY = 0.0f;            \
    lbl_8039C380.posZ = 0.0f;            \
    lbl_8039C380.scale = 1.0f;             \
    lbl_8039C380.unk0 = 0;                         \
    lbl_8039C380.unk2 = 0;                         \
    lbl_8039C380.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C380;             \
  } while (0)

#undef FILL8

extern FxNode9 lbl_8039C338;
extern f32 lbl_803DF884;

#define FILL338() do {                          \
    lbl_8039C338.posX = lbl_803DF884;             \
    lbl_8039C338.posY = lbl_803DF884;            \
    lbl_8039C338.posZ = lbl_803DF884;            \
    lbl_8039C338.scale = lbl_803DF878;             \
    lbl_8039C338.unk0 = 0;                         \
    lbl_8039C338.unk2 = 0;                         \
    lbl_8039C338.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C338;             \
  } while (0)

extern void vecRotateZXY(void* obj, f32* vec);

#undef FILL338

extern FxNode9 lbl_8039C368;
extern f32 lbl_803DFCEC;

#define FILL368() do {                          \
    lbl_8039C368.posX = lbl_803DFCEC;             \
    lbl_8039C368.posY = lbl_803DFCEC;            \
    lbl_8039C368.posZ = lbl_803DFCEC;            \
    lbl_8039C368.scale = lbl_803DFCE0;             \
    lbl_8039C368.unk0 = 0;                         \
    lbl_8039C368.unk2 = 0;                         \
    lbl_8039C368.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C368;             \
  } while (0)

#undef FILL368

extern FxNode9 lbl_8039C350;
extern f32 lbl_803DF9D0;
extern f32 lbl_803DF9D4;

#define FILL350() do {                          \
    lbl_8039C350.posX = lbl_803DF9D0;             \
    lbl_8039C350.posY = lbl_803DF9D0;            \
    lbl_8039C350.posZ = lbl_803DF9D0;            \
    lbl_8039C350.scale = lbl_803DF9D4;             \
    lbl_8039C350.unk0 = 0;                         \
    lbl_8039C350.unk2 = 0;                         \
    lbl_8039C350.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C350;             \
  } while (0)

#undef FILL350

extern f32 gEffect4SpawnCyclePhaseFast;
extern f32 gEffect4SpawnCyclePhaseSlow;
extern f32 gEffect4SpawnCyclePhaseSlowStep;
extern f32 lbl_803DFA9C;
extern f32 lbl_803DFAA0;
extern f32 lbl_803DFAA4;
extern f32 lbl_803DFAA8;
extern f32 lbl_803DFAAC;
extern f32 lbl_803DFAB0;
extern f32 lbl_803DFAB4;
extern f32 lbl_803DFAB8;
extern f32 lbl_803DFABC;
extern f32 lbl_803DFAC0;
extern f32 lbl_803DFAC4;
extern f32 lbl_803DFAC8;
extern f32 lbl_803DFACC;
extern f32 lbl_803DFAD0;
extern f32 lbl_803DFAD4;
extern f32 lbl_803DFAD8;
extern f32 lbl_803DFADC;
extern f32 lbl_803DFAE0;
extern f32 lbl_803DFAE4;
extern f32 lbl_803DFAE8;
extern f32 lbl_803DFAEC;
extern f32 lbl_803DFAF0;
extern f32 lbl_803DFAF4;
extern f32 lbl_803DFAF8;
extern f32 lbl_803DFAFC;
extern f32 lbl_803DFB00;
extern f32 lbl_803DFB04;
extern f32 lbl_803DFB08;
extern f32 lbl_803DFB0C;
extern f32 lbl_803DFB10;
extern f32 lbl_803DFB14;
extern f32 lbl_803DFB18;
extern f32 lbl_803DFB1C;
extern f32 lbl_803DFB20;
extern f32 lbl_803DFB24;
extern f32 lbl_803DFB28;
extern f32 lbl_803DFB2C;
extern f32 lbl_803DFB30;
extern f32 lbl_803DFB34;
extern f32 lbl_803DFB38;
extern f32 lbl_803DFB3C;
extern f32 lbl_803DFB40;
extern f32 lbl_803DFB44;
extern f32 lbl_803DFB48;
extern f32 lbl_803DFB4C;
extern f32 lbl_803DFB50;
extern f32 lbl_803DFB54;
extern f32 lbl_803DFB58;
extern f32 lbl_803DFB5C;
extern f32 lbl_803DFB60;
extern f32 lbl_803DFB64;
extern f32 lbl_803DFB68;
extern f32 lbl_803DFB6C;
extern f32 lbl_803DFB70;
extern f32 lbl_803DFB74;
extern f32 lbl_803DFB78;
extern f32 lbl_803DFB7C;
extern f32 lbl_803DFB80;
extern f32 lbl_803DFB84;
extern f32 lbl_803DFB88;
extern f32 lbl_803DFB8C;
extern f32 lbl_803DFB90;
extern f32 lbl_803DFB94;
extern f32 lbl_803DFB98;
extern f32 lbl_803DFB9C;
extern f32 lbl_803DFBA0;
extern f32 lbl_803DFBA4;
extern f32 lbl_803DFBA8;
extern f32 lbl_803DFBAC;
extern f32 lbl_803DFBB0;
extern f32 lbl_803DFBB4;
extern f32 lbl_803DFBB8;
extern f32 lbl_803DFBBC;
extern f32 lbl_803DFBC0;
extern f32 lbl_803DFBC4;
extern f32 lbl_803DFBC8;

int Effect4_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    int randPick;
    MtxBuildArg es;
    PartFxSpawn cfg;

    gEffect4SpawnCyclePhaseFast = gEffect4SpawnCyclePhaseFast + lbl_803DFA88;
    if (gEffect4SpawnCyclePhaseFast > 1.0f) gEffect4SpawnCyclePhaseFast = lbl_803DFA8C;
    gEffect4SpawnCyclePhaseSlow = gEffect4SpawnCyclePhaseSlow + gEffect4SpawnCyclePhaseSlowStep;
    if (gEffect4SpawnCyclePhaseSlow > 1.0f) gEffect4SpawnCyclePhaseSlow = lbl_803DFA98;
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
    cfg.startPosX = lbl_803DFA9C;
    cfg.startPosY = lbl_803DFA9C;
    cfg.startPosZ = lbl_803DFA9C;
    cfg.velocityX = lbl_803DFA9C;
    cfg.velocityY = lbl_803DFA9C;
    cfg.velocityZ = lbl_803DFA9C;
    cfg.scale = lbl_803DFA9C;
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
        cfg.startPosY = lbl_803DFA8C * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.velocityX = lbl_803DFAA0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = cfg.velocityX * (lbl_803DFAA0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e)
        )
        ;
        cfg.scale = lbl_803DFAA4 * (f32)(s32)
        randomGetRange(0xc8, 0x118);
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80118;
        cfg.renderFlags = 0x8;
        cfg.textureId = 0x566;
        break;
    case 0x1c9:
        cfg.startPosZ = lbl_803DFAA8;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = 0;
        es.ry = 0;
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.scale = lbl_803DFAAC * (f32)(s32)
        randomGetRange(0xc8, 0x118);
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xe1;
        cfg.behaviorFlags = 0x400000;
        cfg.textureId = 0x4f9;
        break;
    case 0x1ca:
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.scale = lbl_803DFAB4 * (f32)(s32)
        randomGetRange(0xc8, 0x118);
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
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.velocityY = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x1c, 0x1c);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x46, 0x46);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0x82, 0xaa);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x46, 0x46);
        cfg.scale = lbl_803DFAB0;
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
        cfg.startPosX = lbl_803DFAB8;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = randomGetRange(0, 0xffff);
        es.ry = randomGetRange(0, 0xffff);
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.scale = lbl_803DFABC;
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x33;
        break;
    case 0x1c4:
        cfg.startPosX = lbl_803DFAC0;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = randomGetRange(0, 0xffff);
        es.ry = randomGetRange(0, 0xffff);
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.scale = lbl_803DFAC4;
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x26c;
        break;
    case 0x1c6:
        cfg.startPosX = lbl_803DFAC8 + (f32)(s32)
        randomGetRange(0, 0x5a);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0xa, 0xa);
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = 0;
        es.ry = 0;
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.scale = lbl_803DFACC * (f32)(s32)
        randomGetRange(1, 0x14);
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480100;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x23c;
        break;
    case 0x1c3:
        cfg.velocityY = lbl_803DFA8C;
        cfg.scale = lbl_803DFAC4;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0xa100110;
        cfg.textureId = 0x23b;
        break;
    case 0x190:
        cfg.scale = lbl_803DFAD0 * (f32)(s32)
        randomGetRange(1, 5);
        cfg.lifetimeFrames = randomGetRange(0xa, 0x14);
        cfg.renderFlags = 0x2;
        cfg.linkGroup = 0;
        cfg.textureId = 0xdf;
        break;
    case 0x191:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x8, 0x8);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x8, 0x8);
        cfg.velocityY = lbl_803DFAD4 * (f32)(s32)
        randomGetRange(-0x3, 0x3);
        cfg.scale = lbl_803DFA88;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x110;
        cfg.textureId = 0xde;
        break;
    case 0x192:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x9e, 0x9e);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x78);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xd0, 0xd0);
        cfg.velocityY = lbl_803DFAD8 * (f32)(s32)
        randomGetRange(-0x3, 0x3);
        cfg.scale = lbl_803DFADC;
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80080112;
        cfg.textureId = 0x1dd;
        break;
    case 0x193:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x9e, 0x9e);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x78);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x3a, 0x3a);
        cfg.velocityY = lbl_803DFAD4 * (f32)(s32)
        randomGetRange(-0x3, 0x3);
        cfg.scale = lbl_803DFADC;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80080112;
        cfg.textureId = 0xde;
        break;
    case 0x194:
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x3a, 0x3a);
        cfg.velocityY = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(0, 0x78);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x3a, 0x3a);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x5, 0x5);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x5, 0x5);
        cfg.scale = lbl_803DFAE0;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480110;
        cfg.renderFlags = 0x8;
        cfg.textureId = 0xde;
        break;
    case 0x195:
        cfg.scale = lbl_803DFAE4;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480214;
        cfg.textureId = 0xde;
        break;
    case 0x196:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityX = lbl_803DFAE8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803DFAEC * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.velocityZ = lbl_803DFAE8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.scale = lbl_803DFAF0;
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
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityX = lbl_803DFAF4 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803DFAF8 * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.velocityZ = lbl_803DFAF4 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.scale = lbl_803DFAB0;
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
        cfg.startPosY = lbl_803DFAFC * (f32)(s32)
        randomGetRange(0, 0x3c);
        cfg.scale = lbl_803DFB00;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100200;
        cfg.textureId = 0x91;
        break;
    case 0x199:
        cfg.scale = lbl_803DFB08 * (f32)(s32)
        randomGetRange(0, 0x32) + lbl_803DFB04;
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
        cfg.scale = lbl_803DFB08 * (f32)(s32)
        randomGetRange(0, 0x32) + lbl_803DFB0C;
        cfg.lifetimeFrames = 0xc;
        cfg.initialAlpha = 0x37;
        cfg.linkGroup = 0;
        cfg.textureId = 0x153;
        cfg.behaviorFlags = 0x180011;
        cfg.renderFlags = 0x2;
        break;
    case 0x19b:
        cfg.scale = lbl_803DFB08 * (f32)(s32)
        randomGetRange(0, 0x32) + lbl_803DFB0C;
        cfg.lifetimeFrames = 0;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0;
        cfg.textureId = 0x153;
        cfg.behaviorFlags = 0x80011;
        cfg.renderFlags = 0x2;
        break;
    case 0x19c:
        cfg.scale = lbl_803DFB10;
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
        cfg.scale = lbl_803DFB14;
        cfg.lifetimeFrames = 0xf;
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0;
        cfg.textureId = 0x153;
        cfg.behaviorFlags = 0x180201;
        break;
    case 0x19f:
        cfg.startPosX = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosZ = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFB18 * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.lifetimeFrames = randomGetRange(0x37, 0x4b);
        cfg.initialAlpha = 0x37;
        cfg.textureId = 0xdb;
        cfg.behaviorFlags = 0x80080000;
        cfg.renderFlags = 0x4402800;
        break;
    case 0x1a0:
        cfg.scale = lbl_803DFB1C * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.initialAlpha = 0x37;
        cfg.lifetimeFrames = 0xf;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdb;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x4000800;
        break;
    case 0x1bc:
        cfg.startPosX = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosZ = lbl_803DFABC * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFB18 * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.lifetimeFrames = randomGetRange(0x8c, 0xa5);
        cfg.initialAlpha = 0x37;
        cfg.textureId = 0x167;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x4400000;
        break;
    case 0x1bd:
        cfg.scale = lbl_803DFB1C * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.initialAlpha = 0x37;
        cfg.lifetimeFrames = 0xf;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0x64;
        cfg.behaviorFlags = 0x4080100;
        break;
    case 0x1a1:
        cfg.startPosX = lbl_803DFB20 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DFB20 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityX = lbl_803DFAEC * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB24 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DFB28;
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x1a2;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x7b;
        break;
    case 0x1a2:
        cfg.scale = lbl_803DFB28;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x7b;
        break;
    case 0x1a3:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(0, 0x1e) + lbl_803DFB20;
        cfg.scale = lbl_803DFB2C * (f32)(s32)
        randomGetRange(1, 0xa);
        cfg.lifetimeFrames = randomGetRange(0x5a, 0x8c);
        cfg.behaviorFlags = 0x80500209;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x1a4:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = lbl_803DFB30 + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.startPosY = lbl_803DFB34;
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB38 * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB40 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFB3C;
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
            if (spawnParams->scale <= lbl_803DFAB0)
            {
                spawnParams->scale = *(f32*)&lbl_803DFAB0;
            }
            cfg.velocityY = -spawnParams->scale;
        }
        else
        {
            cfg.velocityY = lbl_803DFB44 * (f32)(s32)
            randomGetRange(0, 0x14);
        }
        cfg.velocityX = lbl_803DFB48 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFB48 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB4C * (f32)(s32)
        randomGetRange(2, 0xa);
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
            cfg.startPosX = (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.startPosY = lbl_803DFB34;
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.velocityX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB38 * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.velocityZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB40 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFB3C;
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
            cfg.velocityY = lbl_803DFAD8 * (f32)(s32)
            randomGetRange(-3, 3);
        }
        cfg.scale = lbl_803DFB00;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x88100200;
        cfg.textureId = 0xc79;
        break;
    case 0x1a7:
        cfg.scale = lbl_803DFB50;
        cfg.lifetimeFrames = randomGetRange(0, 0xfa) + 0x96;
        cfg.linkGroup = 0;
        cfg.quadVertex3Pad06 = 0x1a8;
        cfg.behaviorFlags = 0x80490008;
        cfg.textureId = 0x167;
        break;
    case 0x1a8:
        cfg.scale = lbl_803DFB54;
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
            cfg.velocityX = lbl_803DFB58;
        }
        else
        {
            cfg.lifetimeFrames = 0x78;
            cfg.velocityX = lbl_803DFB5C;
        }
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = randomGetRange(0, 0xffff);
        es.ry = randomGetRange(0, 0xffff);
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DFABC;
        cfg.linkGroup = 0x10;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0xdf;
        break;
    case 0x1b3:
        if (spawnParams == 0) return -1;
        cfg.velocityX = lbl_803DFB60 * (f32)(s32)
        randomGetRange(-0xf, 0xf) + lbl_803DFA88;
        cfg.velocityY = lbl_803DFB60 * (f32)(s32)
        randomGetRange(-0xf, 0xf) + lbl_803DFA88;
        cfg.velocityZ = lbl_803DFB60 * (f32)(s32)
        randomGetRange(-0xf, 0xf) + lbl_803DFA88;
        cfg.startPosY = lbl_803DFB64;
        vecRotateZXY(spawnParams, &cfg.velocityX);
        cfg.scale = lbl_803DFB68 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.initialAlpha = 0xff;
        cfg.lifetimeFrames = 0x64;
        cfg.linkGroup = 0x10;
        cfg.quadVertex3Pad06 = 0x1b4;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0x159;
        break;
    case 0x1b4:
        cfg.scale = lbl_803DFB6C * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.initialAlpha = 0x37;
        cfg.lifetimeFrames = 0x14;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80201;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x159;
        break;
    case 0x1aa:
        if (spawnParams == 0) return -1;
        cfg.velocityX = lbl_803DFA88 * (f32)(s32)
        randomGetRange(0, 0x640) + lbl_803DFB70;
        vecRotateZXY(spawnParams, &cfg.velocityX);
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.scale = lbl_803DFABC;
            cfg.initialAlpha = 0xff;
        }
        else
        {
            cfg.scale = lbl_803DFAF8;
            cfg.initialAlpha = 0x9b;
        }
        cfg.lifetimeFrames = 0xf0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xdf;
        break;
    case 0x1af:
        if (spawnParams == 0) return -1;
        cfg.velocityX = spawnParams->posX * (f32)(s32)
        randomGetRange(-1, 1);
        cfg.velocityY = spawnParams->posX * (f32)(s32)
        randomGetRange(-1, 1);
        cfg.velocityZ = spawnParams->posX * (f32)(s32)
        randomGetRange(-1, 1);
        cfg.scale = lbl_803DFB74 * (f32)(s32)
        randomGetRange(0x190, 0x1f4);
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
        if (spawnParams == 0) return -1;
        cfg.startPosX = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB7C;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = lbl_803DFA9C;
        cfg.sourcePosZ = lbl_803DFA9C;
        cfg.sourcePosW = lbl_803DFA9C;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x6100214;
        cfg.textureId = 0x167;
        break;
    case 0x1b1:
        if (spawnParams == 0) return -1;
        cfg.startPosX = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = spawnParams->posX * (lbl_803DFB80 * (f32)(s32)
        randomGetRange(1, 5)
        )
        ;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = lbl_803DFA9C;
        cfg.sourcePosZ = lbl_803DFA9C;
        cfg.sourcePosW = lbl_803DFA9C;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x6100214;
        cfg.textureId = 0x30;
        break;
    case 0x1b2:
        cfg.velocityX = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB74 * (f32)(s32)
        randomGetRange(0xc8, 0x3e8);
        cfg.initialAlpha = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x3c;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x81480204;
        cfg.textureId = 0x30;
        break;
    case 0x1ae:
        cfg.velocityX = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFB84 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB74 * (f32)(s32)
        randomGetRange(0xc8, 0x3e8);
        cfg.initialAlpha = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.lifetimeFrames = randomGetRange(0, 0x28) + 0x3c;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480104;
        cfg.renderFlags = 8;
        cfg.textureId = 0x30;
        break;
    case 0x1ab:
        cfg.startPosX = lbl_803DFB88;
        es.a = lbl_803DFA9C;
        es.b = lbl_803DFA9C;
        es.c = lbl_803DFA9C;
        es.w = lbl_803DFA90;
        es.rz = randomGetRange(0, 0xffff);
        es.ry = randomGetRange(0, 0xffff);
        es.rx = randomGetRange(0, 0xffff);
        vecRotateZXY(&es, &cfg.startPosX);
        cfg.velocityX = cfg.startPosX / lbl_803DFB30;
        cfg.velocityY = cfg.startPosY / lbl_803DFB30;
        cfg.velocityZ = cfg.startPosZ / lbl_803DFB30;
        cfg.scale = lbl_803DFB8C * (f32)(s32)
        randomGetRange(0xc8, 0x3e8);
        cfg.initialAlpha = (u8)(randomGetRange(0x64, 0xc8) + 0x37);
        cfg.lifetimeFrames = 0x50;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480504;
        cfg.textureId = 0x30;
        break;
    case 0x1ac:
        cfg.startPosX = lbl_803DFB90 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DFB90 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFB90 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB94 * (f32)(s32)
        randomGetRange(0x1f4, 0x3e8);
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
        cfg.startPosX = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DFB78 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DFB6C * (f32)(s32)
        randomGetRange(0xc8, 0x5dc);
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
        cfg.startPosZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.startPosX = lbl_803DFB9C * (f32)(s32)
        randomGetRange(0, 0x3e8) + lbl_803DFB98;
        cfg.startPosY = lbl_803DFBA0 * cfg.startPosX;
        cfg.velocityX = lbl_803DFBA8 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFBA4;
        cfg.velocityY = lbl_803DFBA0 * cfg.velocityX;
        cfg.scale = lbl_803DFBAC * (f32)(s32)
        randomGetRange(1, 6);
        cfg.lifetimeFrames = 0xbe;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x6000100;
        cfg.textureId = 0x20;
        cfg.sourceVecZ = 0;
        cfg.sourceVecY = 0x5fb4;
        cfg.sourceVecX = -0x3fff;
        cfg.sourcePosY = lbl_803DFA9C;
        cfg.sourcePosZ = lbl_803DFA9C;
        cfg.sourcePosW = lbl_803DFA9C;
        break;
    case 0x1bf:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFA8C * (f32)(s32)
        randomGetRange(0, 0x3e8);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityX = lbl_803DFB38 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFBB0 * (f32)(s32)
        randomGetRange(0x1f4, 0x258);
        cfg.velocityZ = lbl_803DFB38 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFBB4;
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
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityY = lbl_803DFBB0 * (f32)(s32)
        randomGetRange(0x1f4, 0x258);
        cfg.scale = lbl_803DFBB4;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x2000200;
        cfg.textureId = 0x23b;
        break;
    case 0x1c1:
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityY = lbl_803DFBB8 * (f32)(s32)
        randomGetRange(0x1f4, 0x258);
        cfg.scale = lbl_803DFB48 * (f32)(s32)
        randomGetRange(0x1e, 0x32);
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
        cfg.startPosZ = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.velocityZ = lbl_803DFBB0 * (f32)(s32)
        randomGetRange(0xc8, 0x320);
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.velocityZ = cfg.velocityZ * lbl_803DFBBC;
        }
        cfg.velocityY = lbl_803DFBB0 * (f32)(s32)
        randomGetRange(0xc8, 0x320);
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.velocityY = cfg.velocityY * lbl_803DFBBC;
        }
        cfg.scale = lbl_803DFAC4;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x14;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x2000200;
        cfg.textureId = 0x23b;
        break;
    case 0x1ba:
        cfg.startPosY = lbl_803DFBC0;
        cfg.startPosX = lbl_803DFA8C * (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8);
        cfg.startPosZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = lbl_803DFBA0 * cfg.startPosX;
        cfg.scale = lbl_803DFBC4 * (f32)(s32)
        randomGetRange(1, 6);
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x20;
        break;
    case 0x1b8:
        cfg.startPosX = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0xbb8, 0xbb8);
        cfg.startPosZ = lbl_803DFAB0 * (f32)(s32)
        randomGetRange(-0xbb8, 0xbb8);
        cfg.scale = lbl_803DFBC8 * (f32)(s32)
        randomGetRange(1, 4);
        cfg.lifetimeFrames = 0x5a;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x56;
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

// VERIFY lbl_803DF720 may already exist in modgfx.c
// VERIFY lbl_803DF724 may already exist in modgfx.c
// VERIFY lbl_803DF728 may already exist in modgfx.c
// VERIFY lbl_803DF730 may already exist in modgfx.c
extern FxNode9 lbl_8039C320;
/* MtxBuildArg, vecRotateZXY, randFn_80080100, gExpgfxInterface, randomGetRange
   already declared in modgfx.c. */

/* ===== (2) FILL macro ===== */
#define FILL320() do {                          \
    lbl_8039C320.posX = 0.0f;             \
    lbl_8039C320.posY = 0.0f;            \
    lbl_8039C320.posZ = 0.0f;            \
    lbl_8039C320.scale = 1.0f;             \
    lbl_8039C320.unk0 = 0;                         \
    lbl_8039C320.unk2 = 0;                         \
    lbl_8039C320.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C320;             \
  } while (0)

#undef FILL320
