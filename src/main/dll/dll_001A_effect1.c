#include "main/dll/mtxbuildarg_struct.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/sfa_shared_decls.h"

void Effect1_func03_nop(void)
{
}

void Effect1_release(void)
{
}

void Effect1_initialise(void)
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

extern f32 lbl_803DF720;
extern f32 lbl_803DF724;
extern f32 lbl_803DF730;
extern f32 lbl_803DF868;
extern f32 gEffect1SinePhaseScale;
extern f32 gEffect1AnimRampA;
extern f32 gEffect1AnimRampB;
extern int gEffect1SineWaveAPhase;
extern int gEffect1SineWaveBPhase;
extern f32 gEffect1SineWaveB;
extern f32 gEffect1SineWaveA;

#pragma scheduling off
void Effect1_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect1AnimRampA + (step = lbl_803DF720 * timeDelta);
    gEffect1AnimRampA = sum;
    if (sum > 1.0f)
    {
        gEffect1AnimRampA = lbl_803DF724;
    }
    sum = gEffect1AnimRampB + step;
    gEffect1AnimRampB = sum;
    if (sum > 1.0f)
    {
        gEffect1AnimRampB = lbl_803DF730;
    }
    gEffect1SineWaveAPhase = gEffect1SineWaveAPhase + framesThisStep * 0x64;
    if (gEffect1SineWaveAPhase > 0x7fff)
    {
        gEffect1SineWaveAPhase = 0;
    }
    gEffect1SineWaveA = mathSinf(lbl_803DF868 * (f32)(s16)gEffect1SineWaveAPhase / gEffect1SinePhaseScale);
    gEffect1SineWaveBPhase = gEffect1SineWaveBPhase + framesThisStep * 0x32;
    if (gEffect1SineWaveBPhase > 0x7fff)
    {
        gEffect1SineWaveBPhase = 0;
    }
    gEffect1SineWaveB = mathSinf(lbl_803DF868 * (f32)(s16)gEffect1SineWaveBPhase / gEffect1SinePhaseScale);
}

extern f32 lbl_803DF878;
extern f32 lbl_803DFCE0;

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

extern f32 gEffect1AnimRampC;
extern f32 gEffect1AnimRampD;
// VERIFY lbl_803DF720 may already exist in modgfx.c
// VERIFY lbl_803DF724 may already exist in modgfx.c
// VERIFY lbl_803DF728 may already exist in modgfx.c
extern f32 lbl_803DF72C;
// VERIFY lbl_803DF730 may already exist in modgfx.c
extern f32 lbl_803DF734;
extern f32 lbl_803DF738;
extern f32 lbl_803DF73C;
extern f32 lbl_803DF740;
extern f32 lbl_803DF744;
extern f32 lbl_803DF748;
extern f32 lbl_803DF74C;
extern f32 lbl_803DF750;
extern f32 lbl_803DF754;
extern f32 lbl_803DF758;
extern f32 lbl_803DF75C;
extern f32 lbl_803DF760;
extern f32 lbl_803DF764;
extern f32 lbl_803DF768;
extern f32 lbl_803DF76C;
extern f32 lbl_803DF770;
extern f32 lbl_803DF774;
extern f32 lbl_803DF778;
extern f32 lbl_803DF77C;
extern f32 lbl_803DF780;
extern f32 lbl_803DF784;
extern f32 lbl_803DF788;
extern f32 lbl_803DF78C;
extern f32 lbl_803DF790;
extern f32 lbl_803DF794;
extern f32 lbl_803DF798;
extern f32 lbl_803DF79C;
extern f32 lbl_803DF7A0;
extern f32 lbl_803DF7A4;
extern f32 lbl_803DF7A8;
extern f32 lbl_803DF7AC;
extern f32 lbl_803DF7B0;
extern f32 lbl_803DF7B4;
extern f32 lbl_803DF7B8;
extern f32 lbl_803DF7BC;
extern f32 lbl_803DF7C0;
extern f32 lbl_803DF7C4;
extern f32 lbl_803DF7C8;
extern f32 lbl_803DF7CC;
extern f32 lbl_803DF7D0;
extern f32 lbl_803DF7D4;
extern f32 lbl_803DF7D8;
extern f32 lbl_803DF7DC;
extern f32 lbl_803DF7E0;
extern f32 lbl_803DF7E4;
extern f32 lbl_803DF7E8;
extern f32 lbl_803DF7EC;
extern f32 lbl_803DF7F0;
extern f32 lbl_803DF7F4;
extern f32 lbl_803DF7F8;
extern f32 lbl_803DF7FC;
extern f32 lbl_803DF800;
extern f32 lbl_803DF804;
extern f32 lbl_803DF808;
extern f32 lbl_803DF80C;
extern f32 lbl_803DF810;
extern f32 lbl_803DF814;
extern f32 lbl_803DF818;
extern f32 lbl_803DF81C;
extern f32 lbl_803DF820;
extern f32 lbl_803DF824;
extern f32 lbl_803DF828;
extern f32 lbl_803DF82C;
extern f32 lbl_803DF830;
extern f32 lbl_803DF834;
extern f32 lbl_803DF838;
extern f32 lbl_803DF83C;
extern f32 lbl_803DF840;
extern f32 lbl_803DF844;
extern f32 lbl_803DF848;
extern f32 lbl_803DF84C;
extern f32 lbl_803DF850;
extern f32 lbl_803DF854;
extern f32 lbl_803DF858;
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

#pragma peephole off
int Effect1_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    MtxBuildArg es;
    PartFxSpawn cfg;

    gEffect1AnimRampC = gEffect1AnimRampC + lbl_803DF720;
    if (gEffect1AnimRampC > 1.0f) gEffect1AnimRampC = lbl_803DF724;
    gEffect1AnimRampD = gEffect1AnimRampD + lbl_803DF72C;
    if (gEffect1AnimRampD > 1.0f) gEffect1AnimRampD = lbl_803DF730;
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
    case 0x5fc: /* L_800AF9D8 */
        cfg.scale = lbl_803DF738;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x5c;
        break;
    case 0x5fb: /* L_800AF9F8 */
        cfg.scale = lbl_803DF738;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xe7;
        break;
    case 0x5fa: /* L_800AFA18 */
        cfg.startPosX = lbl_803DF73C * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.startPosZ = lbl_803DF73C * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.velocityY = lbl_803DF740 * (f32)(s32)
        randomGetRange(0x320, 0x4b0);
        cfg.scale = lbl_803DF744;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x26c;
        break;
    case 0x5f9: /* L_800AFAE0 */
        cfg.startPosX = lbl_803DF748 * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.startPosZ = lbl_803DF748 * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.velocityY = lbl_803DF74C * (f32)(s32)
        randomGetRange(0x320, 0x4b0);
        cfg.scale = lbl_803DF750;
        cfg.lifetimeFrames = 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480100;
        cfg.renderFlags = 0x2000000;
        cfg.quadVertex3Pad06 = 0x5e9;
        cfg.textureId = 0x26c;
        break;
    case 0x5e9: /* L_800AFBBC */
        cfg.scale = lbl_803DF750;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x26c;
        break;
    case 0x3a7: /* L_800AFBF0 */
        cfg.scale = lbl_803DF754;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1c0100;
        cfg.textureId = 0x73;
        break;
    case 0x3a5: /* L_800AFC1C */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        }
        else
        {
            cfg.startPosZ = lbl_803DF758;
            cfg.startPosY = lbl_803DF75C;
        }
        cfg.velocityZ = lbl_803DF760 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x4, 0x4);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0xa, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x8e;
        cfg.behaviorFlags = 0x40180100;
        break;
    case 0x3a6: /* L_800AFD80 */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        }
        else
        {
            cfg.startPosZ = lbl_803DF758;
            cfg.startPosY = lbl_803DF75C;
        }
        cfg.velocityZ = lbl_803DF76C * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x4, 0x4);
        cfg.scale = lbl_803DF770 * (f32)(s32)
        randomGetRange(0x28, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0x3c) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0a;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x42000100;
        break;
    case 0x3a3: /* L_800AFEEC */
        cfg.scale = lbl_803DF73C;
        cfg.lifetimeFrames = 0x4;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0x64;
        cfg.initialAlpha = 0x9b;
        break;
    case 0x3a4: /* L_800AFF20 */
        cfg.velocityX = lbl_803DF774 * (f32)(s32)
        randomGetRange(0x19, 0x64);
        cfg.velocityY = lbl_803DF778 * (f32)(s32)
        randomGetRange(0x42, 0x64);
        cfg.velocityZ = lbl_803DF77C * (f32)(s32)
        randomGetRange(0x11, 0x64);
        cfg.startPosX = lbl_803DF780 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DF734;
        cfg.startPosZ = lbl_803DF784 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DF788 * (f32)(s32)
        randomGetRange(0x27, 0x50);
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
    case 0x3a8: /* L_800B00EC */
    case 0x3a2:
        if (spawnParams == 0)
            FILL320();
        if (spawnParams == 0) return -1;
        cfg.velocityX = spawnParams->scale * (lbl_803DF78C * (f32)(s32)
        randomGetRange(-0x64, 0x64)
        )
        ;
        cfg.velocityY = spawnParams->scale * (lbl_803DF790 * (f32)(s32)
        randomGetRange(0x50, 0x8c)
        )
        ;
        cfg.velocityZ = spawnParams->scale * (lbl_803DF794 * (f32)(s32)
        randomGetRange(-0x64, 0x64)
        )
        ;
        cfg.startPosX = lbl_803DF798 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DF75C;
        cfg.startPosZ = lbl_803DF79C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = spawnParams->scale * (lbl_803DF7A0 * (f32)(s32)
        randomGetRange(0x16, 0x46)
        )
        ;
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
        if (effectId == 0x3a2)
        {
            cfg.behaviorFlags |= 0x20000000LL;
        }
        cfg.renderFlags = 0x8400820;
        break;
    case 0x3a1: /* L_800B032C */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams == 0) return -1;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = lbl_803DF7A4 + spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityZ = lbl_803DF724 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityX = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        es.a = 0.0f;
        es.b = 0.0f;
        es.c = 0.0f;
        es.w = 1.0f;
        es.rz = ((s16*)sourceObj)[2];
        es.ry = ((s16*)sourceObj)[1];
        es.rx = *(s16*)sourceObj;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x167;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x2000110;
        break;
    case 0x3a0: /* L_800B04A0 */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams == 0) return -1;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = lbl_803DF7A4 + spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityZ = lbl_803DF7AC * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityX = lbl_803DF760 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF7B0 * (f32)(s32)
        randomGetRange(2, 6);
        es.a = 0.0f;
        es.b = 0.0f;
        es.c = 0.0f;
        es.w = 1.0f;
        es.rz = ((s16*)sourceObj)[2];
        es.ry = ((s16*)sourceObj)[1];
        es.rx = *(s16*)sourceObj;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DF764 * (f32)(s32)
        randomGetRange(8, 0x14);
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
    case 0x39f: /* L_800B066C */
        cfg.velocityY = lbl_803DF7B4 * (f32)(s32)
        randomGetRange(0xa, 0xe);
        cfg.scale = lbl_803DF7B8;
        cfg.lifetimeFrames = 0x1;
        cfg.initialAlpha = 0x23;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x64;
        break;
    case 0x39a: /* L_800B06CC */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7BC;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x17c;
        break;
    case 0x39b: /* L_800B06FC */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x17c;
        break;
    case 0x39c: /* L_800B0724 */
        cfg.initialAlpha = 0x37;
        cfg.scale = lbl_803DF7A8;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x17c;
        break;
    case 0x39d: /* L_800B0750 */
        cfg.initialAlpha = 0x87;
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2000;
        cfg.textureId = 0x17c;
        break;
    case 0x39e: /* L_800B0788 */
        cfg.velocityZ = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityX = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.initialAlpha = 0x87;
        cfg.scale = lbl_803DF7C0 * (f32)(s32)
        randomGetRange(0x320, 0x4b0);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0x1480200;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0x17c;
        break;
    case 0x399: /* L_800B0888 */
        if (spawnParams == 0)
            FILL320();
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = lbl_803DF7C4 + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.sourceVecX = spawnParams->rotX;
            cfg.sourceVecZ = spawnParams->rotZ;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7C8;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x6100100;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x64;
        break;
    case 0x397: /* L_800B095C */
        cfg.startPosX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.startPosZ = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.velocityY = lbl_803DF7CC * (f32)(s32)
        randomGetRange(0x320, 0x4b0);
        cfg.scale = lbl_803DF7D0;
        cfg.lifetimeFrames = 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080110;
        cfg.quadVertex3Pad06 = 0x398;
        cfg.textureId = 0xc0d;
        break;
    case 0x398: /* L_800B0A30 */
        cfg.scale = lbl_803DF7D0;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0xc0d;
        break;
    case 0x5f7: /* L_800B0A64 */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7D4;
        cfg.lifetimeFrames = 0x73;
        cfg.behaviorFlags = 0x8100110;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x77;
        break;
    case 0x5f6: /* L_800B0A98 */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7D8;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x202;
        cfg.textureId = 0x26c;
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7DC;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x528;
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.initialAlpha = 0x37;
        cfg.scale = lbl_803DF7B0;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2;
        cfg.textureId = 0x528;
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, 0, effectId, 0);
        cfg.initialAlpha = 0x87;
        cfg.scale = lbl_803DF7DC;
        cfg.lifetimeFrames = 0xa;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2002;
        cfg.textureId = 0x528;
        break;
    case 0x5f5: /* L_800B0BC8 */
        cfg.velocityX = lbl_803DF7E0 * (f32)(s32)
        randomGetRange(-0x384, 0x384);
        cfg.velocityZ = lbl_803DF7E0 * (f32)(s32)
        randomGetRange(-0x384, 0x384);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7E4;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x110;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0xe4;
        break;
    case 0x5f4: /* L_800B0C64 */
        cfg.startPosX = lbl_803DF740 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = lbl_803DF740 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.velocityZ = lbl_803DF7E0 * (f32)(s32)
        randomGetRange(0x12c, 0x190);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7E0;
        cfg.lifetimeFrames = 0x8c;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x528;
        break;
    case 0x5f0: /* L_800B0D2C */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7BC;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x26c;
        break;
    case 0x5f1: /* L_800B0D5C */
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x528;
        break;
    case 0x5f2: /* L_800B0D84 */
        cfg.initialAlpha = 0x37;
        cfg.scale = lbl_803DF7A8;
        cfg.lifetimeFrames = 0x12c;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x528;
        break;
    case 0x5f3: /* L_800B0DB0 */
        cfg.initialAlpha = 0x87;
        cfg.scale = lbl_803DF740;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x480200;
        cfg.renderFlags = 0x2000;
        cfg.textureId = 0x528;
        break;
    case 0x5ef: /* L_800B0DE8 */
        cfg.startPosX = lbl_803DF720 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosZ = lbl_803DF720 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.velocityY = lbl_803DF7E8;
        cfg.initialAlpha = 0x9b;
        cfg.scale = lbl_803DF7EC;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x3f2;
        break;
    case 0x5ee: /* L_800B0E9C */
        cfg.velocityZ = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7F4;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x2000100;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x33;
        break;
    case 0x5f8: /* L_800B0F48 */
        cfg.velocityX = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7F4;
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x3c;
        cfg.behaviorFlags = 0x2000100;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x33;
        break;
    case 0x5ed: /* L_800B0FF4 */
        if (spawnParams == 0)
            FILL320();
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = lbl_803DF7C4 + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.sourceVecX = spawnParams->rotX;
            cfg.sourceVecZ = spawnParams->rotZ;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7C8;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x6100100;
        cfg.textureId = 0x5fe;
        break;
    case 0x5fd: /* L_800B10B4 */
        if (spawnParams == 0)
            FILL320();
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = lbl_803DF7C4 + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.sourceVecX = spawnParams->rotX;
            cfg.sourceVecZ = spawnParams->rotZ;
        }
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DF7C8 * (f32)(s32)
        randomGetRange(1, 3);
        cfg.lifetimeFrames = randomGetRange(0, 0x64) + 0x78;
        cfg.behaviorFlags = 0x6100000;
        cfg.renderFlags = 0x10000 - 0x8000;
        cfg.textureId = 0x5ff;
        break;
    case 0x5eb: /* L_800B11B4 */
        cfg.velocityZ = lbl_803DF7F8 * (f32)(s32)
        randomGetRange(0xb4, 0xc8);
        cfg.velocityX = lbl_803DF7F0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF740 * (f32)(s32)
        randomGetRange(0, 0x28);
        cfg.initialAlpha = 0x9b;
        cfg.scale = lbl_803DF7AC;
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
    case 0x5ea: /* L_800B12D4 */
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x19, 0x19);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x19, 0x19);
        cfg.initialAlpha = 0x9b;
        cfg.scale = lbl_803DF7B0;
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
    case 0x5e3: /* L_800B13B0 */
        cfg.scale = lbl_803DF7FC * (f32)(s32)
        randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0xf0;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x156;
        break;
    case 0x5e4: /* L_800B1410 */
        cfg.scale = lbl_803DF7FC * (f32)(s32)
        randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0xf0;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x156;
        break;
    case 0x5e5: /* L_800B1470 */
        cfg.scale = lbl_803DF800;
        cfg.lifetimeFrames = 0xf0;
        cfg.initialAlpha = 0xb9;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x156;
        break;
    case 0x5e6: /* L_800B149C */
        cfg.scale = lbl_803DF7FC * (f32)(s32)
        randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0x12c;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0x156;
        break;
    case 0x5e7: /* L_800B14FC */
        cfg.scale = lbl_803DF7FC * (f32)(s32)
        randomGetRange(0x19, 0x23);
        cfg.lifetimeFrames = 0x6;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x156;
        break;
    case 0x5e8: /* L_800B155C */
        cfg.scale = lbl_803DF800;
        cfg.lifetimeFrames = 0x6;
        cfg.initialAlpha = 0x55;
        cfg.behaviorFlags = 0x480000;
        cfg.textureId = 0x156;
        break;
    case 0x5dd: /* L_800B1588 */
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.velocityX = lbl_803DF804 * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.velocityY = cfg.startPosY / lbl_803DF808;
        cfg.velocityZ = cfg.startPosZ / lbl_803DF808;
        cfg.scale = lbl_803DF80C * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0xc79;
        break;
    case 0x5de: /* L_800B168C */
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.velocityX = lbl_803DF804 * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.velocityY = cfg.startPosY / lbl_803DF808;
        cfg.velocityZ = cfg.startPosZ / lbl_803DF808;
        cfg.scale = lbl_803DF80C * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x166;
        break;
    case 0x5df: /* L_800B1790 */
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0xc, 0xc);
        cfg.velocityX = lbl_803DF804 * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.velocityY = cfg.startPosY / lbl_803DF808;
        cfg.velocityZ = cfg.startPosZ / lbl_803DF808;
        cfg.scale = lbl_803DF80C * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = 0x528;
        break;
    case 0x5e0: /* L_800B1894 */
        cfg.velocityX = lbl_803DF810 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.scale = lbl_803DF814;
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
    case 0x5e1: /* L_800B1938 */
        cfg.velocityX = lbl_803DF810 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.scale = lbl_803DF814;
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
    case 0x5e2: /* L_800B19DC */
        cfg.velocityX = lbl_803DF810 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.scale = lbl_803DF814;
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
    case 0x396: /* L_800B1A80 */
        cfg.scale = lbl_803DF754;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1c0100;
        cfg.textureId = 0x159;
        break;
    case 0x394: /* L_800B1AAC */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosX = spawnParams->posZ;
        }
        cfg.sourceVecX = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourceVecY = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourceVecX = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.scale = lbl_803DF818 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x2f);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x6100100;
        cfg.textureId = 0xc79;
        break;
    case 0x395: /* L_800B1BBC */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosX = spawnParams->posZ;
        }
        cfg.sourceVecX = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourceVecY = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourceVecX = (s16)(s32)
        randomGetRange(0, 0xffff);
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.scale = lbl_803DF740 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.lifetimeFrames = randomGetRange(0x50, 0x64);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x6100110;
        cfg.textureId = 0xc79;
        break;
    case 0x393: /* L_800B1CCC */
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.startPosX = lbl_803DF730 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.velocityY = lbl_803DF7B4 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DF81C;
        cfg.lifetimeFrames = randomGetRange(0x212, 0x2a8);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480208;
        cfg.textureId = 0xc0d;
        break;
    case 0x392: /* L_800B1DC4 */
        cfg.startPosX = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityX = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.scale = lbl_803DF820 * (f32)(s32)
        randomGetRange(0xa, 0xf);
        cfg.lifetimeFrames = randomGetRange(0x5a, 0x8c);
        cfg.behaviorFlags = 0x80400201;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x390: /* L_800B1F2C */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        }
        else
        {
            cfg.startPosZ = lbl_803DF758;
            cfg.startPosY = lbl_803DF75C;
        }
        cfg.velocityZ = lbl_803DF760 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x4, 0x4);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0xa, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0xa) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x8e;
        cfg.behaviorFlags = 0x40180100;
        break;
    case 0x391: /* L_800B2090 */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosZ = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
        }
        else
        {
            cfg.startPosZ = lbl_803DF758;
            cfg.startPosY = lbl_803DF75C;
        }
        cfg.velocityZ = lbl_803DF76C * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(-0x4, 0x4);
        cfg.scale = lbl_803DF770 * (f32)(s32)
        randomGetRange(0x28, 0x32);
        cfg.lifetimeFrames = randomGetRange(0, 0x3c) + 0x50;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0a;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x42000100;
        break;
    case 0x38f: /* L_800B21FC */
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x28, 0x8c);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.velocityX = lbl_803DF73C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF824 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DF73C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DF7E4;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x167;
        cfg.renderFlags = 0x300000;
        cfg.behaviorFlags = 0x2000110;
        break;
    case 0x38a: /* L_800B2354 */
        if (spawnParams == 0)
            FILL320();
        cfg.startPosX = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0xa, -0xa);
        cfg.startPosY = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0x14, -0xa);
        cfg.startPosZ = lbl_803DF724 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityX = lbl_803DF7DC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF7DC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.initialAlpha = 0xff;
        if (spawnParams != 0)
        {
            cfg.startPosX = cfg.startPosX + spawnParams->posX;
            cfg.startPosY = cfg.startPosY + spawnParams->posY;
            cfg.startPosZ = cfg.startPosZ + spawnParams->posZ;
        }
        cfg.scale = lbl_803DF828 * (f32)(s32)
        randomGetRange(0xa, 0x14);
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
    case 0x38b: /* L_800B25A8 */
        cfg.scale = lbl_803DF82C;
        cfg.lifetimeFrames = 0x4b;
        cfg.behaviorFlags = 0x82000108;
        cfg.renderFlags = 0x80;
        cfg.textureId = 0xc0a;
        cfg.initialAlpha = 0xff;
        break;
    case 0x38c: /* L_800B25DC */
        cfg.startPosY = lbl_803DF830;
        cfg.scale = lbl_803DF834;
        cfg.lifetimeFrames = 0x190;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x167;
        cfg.initialAlpha = 0x9b;
        break;
    case 0x38d: /* L_800B2610 */
        if (spawnParams == 0)
            FILL320();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.startPosY = lbl_803DF838;
        cfg.velocityX = lbl_803DF7B0 * (f32)(s32)
        randomGetRange(-0xa, 0xa) + lbl_803DF738;
        cfg.velocityY = lbl_803DF738 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.velocityZ = lbl_803DF7B0 * (f32)(s32)
        randomGetRange(-0xa, 1) + lbl_803DF738;
        cfg.scale = lbl_803DF83C;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x3010000 - 0x8000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x167;
        cfg.initialAlpha = 0xff;
        break;
    case 0x38e: /* L_800B2740 */
        cfg.velocityX = lbl_803DF840 * (f32)(s32)
        randomGetRange(-0xa, 0xa) + lbl_803DF738;
        cfg.velocityY = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.velocityZ = lbl_803DF840 * (f32)(s32)
        randomGetRange(-0xa, 1) + lbl_803DF738;
        cfg.scale = lbl_803DF83C;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x167;
        cfg.initialAlpha = 0xff;
        break;
    case 0x389: /* L_800B2818 */
        if (spawnParams == 0)
            FILL320();
        cfg.startPosX = (f32)(s32)
        randomGetRange(-5, 5);
        cfg.startPosY = (f32)(s32)
        randomGetRange(1, 5);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-5, 5);
        es.w = lbl_803DF7DC * (f32)(s32)
        randomGetRange(0, 0x258) + lbl_803DF844;
        cfg.velocityY = lbl_803DF720 * (f32)(s32)
        randomGetRange(0, 0xc8) + 1.0f;
        cfg.velocityX = lbl_803DF7B0 * (f32)(s32)
        randomGetRange(0, 0x14) + lbl_803DF724;
        cfg.velocityY = cfg.velocityY * es.w;
        cfg.velocityX = cfg.velocityX * es.w;
        cfg.scale = lbl_803DF84C * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF848;
        cfg.lifetimeFrames = randomGetRange(0xb4, 0xc8);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x3000120;
        cfg.renderFlags = 0x200800;
        cfg.textureId = 0xc0a;
        cfg.quadVertex3Pad06 = 0x385;
        break;
    case 0x388: /* L_800B2A08 */
        cfg.startPosX = (f32)(s32)
        randomGetRange(0, 0x10);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x2e, 0x2e);
        cfg.velocityY = lbl_803DF748 * (f32)(s32)
        randomGetRange(0x10, 0x1e);
        cfg.scale = lbl_803DF7EC;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0x37;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x100;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x1fb;
        break;
    case 0x384: /* L_800B2ACC */
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x37, 0x37);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xa, 0xf);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x37, 0x37);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF724 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DF738 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF850;
        cfg.lifetimeFrames = randomGetRange(0x78, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x385;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x1001100;
        cfg.textureId = 0xc0a;
        break;
    case 0x387: /* L_800B2C64 */
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x19, 0x19);
        cfg.startPosY = (f32)(s32)
        randomGetRange(1, 5);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x19, 0x19);
        cfg.velocityX = lbl_803DF738 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF724 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DF738 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF850;
        cfg.lifetimeFrames = randomGetRange(0x78, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x385;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x81000120;
        cfg.textureId = 0xc0a;
        break;
    case 0x385: /* L_800B2DFC */
        cfg.velocityY = lbl_803DF764 * (f32)(s32)
        randomGetRange(2, 0x14);
        cfg.scale = lbl_803DF854;
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
    case 0x386: /* L_800B2EA4 */
        cfg.startPosY = (f32)(s32)
        randomGetRange(1, 5);
        cfg.velocityY = lbl_803DF7A8 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DF768 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF858;
        cfg.lifetimeFrames = randomGetRange(0xe6, 0x118);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xc0d;
        break;
    default: /* L_800B2F6C */
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
#undef FILL320
