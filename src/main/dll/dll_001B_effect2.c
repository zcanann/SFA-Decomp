/*
 * effect2 (DLL 0x1B) - one of the "effect" particle DLLs (effect2..effect9
 * share the same modgfx/projgfx engine source; this object exports only its
 * own five Effect2_* entry points).
 *
 * Effect2_func04 is the spawn dispatcher: given an effectId it fills a
 * PartFxSpawn request (velocity / start position / scale / lifetime / texture /
 * behavior+render flags / colors, mostly randomised per spawn) and hands it to
 * gExpgfxInterface->spawnEffect. Effect2_func05 advances this DLL's animated
 * scroll/oscillation globals once per step. Effect2_func03_nop / _release /
 * _initialise are the descriptor stubs.
 *
 * The remaining modgfx_* / projgfx_* bodies are the shared effect-engine source
 * (vertex texcoord scroll, rgb/alpha/scale/rotation blend channels, active-effect
 * registry teardown, expgfx pool alloc); they are matched in their sibling effect
 * DLLs, not in this object's symbol set.
 */
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/dll/DR/dr_shared.h"

void Effect2_func03_nop(void)
{
}

void Effect2_release(void)
{
}

void Effect2_initialise(void)
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

extern f32 gEffect2ScrollPhaseA;
extern f32 gEffect2ScrollPhaseB;
extern int gEffect2SinAngleA;
extern int gEffect2SinAngleB;
extern f32 gEffect2SinValueB;
extern f32 gEffect2SinValueA;
extern f32 lbl_803DF870;
extern f32 lbl_803DF874;
extern f32 lbl_803DF878;
extern f32 lbl_803DF880;
extern f32 lbl_803DF9C8;
extern f32 lbl_803DF9CC;

#pragma scheduling off
#pragma peephole off
void Effect2_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect2ScrollPhaseA + (step = lbl_803DF870 * timeDelta);
    gEffect2ScrollPhaseA = sum;
    if (sum > 1.0f)
    {
        gEffect2ScrollPhaseA = lbl_803DF874;
    }
    sum = gEffect2ScrollPhaseB + step;
    gEffect2ScrollPhaseB = sum;
    if (sum > 1.0f)
    {
        gEffect2ScrollPhaseB = lbl_803DF880;
    }
    gEffect2SinAngleA = gEffect2SinAngleA + framesThisStep * 0x64;
    if (gEffect2SinAngleA > 0x7fff)
    {
        gEffect2SinAngleA = 0;
    }
    gEffect2SinValueA = mathSinf(lbl_803DF9C8 * (f32)(s16)gEffect2SinAngleA / lbl_803DF9CC);
    gEffect2SinAngleB = gEffect2SinAngleB + framesThisStep * 0x32;
    if (gEffect2SinAngleB > 0x7fff)
    {
        gEffect2SinAngleB = 0;
    }
    gEffect2SinValueB = mathSinf(lbl_803DF9C8 * (f32)(s16)gEffect2SinAngleB / lbl_803DF9CC);
}

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

/* Per-config velocity-range band count (emit[6]/sub[6]/col[6] parallel tables). */
#define EFFECT2_VELOCITY_RANGE_COUNT 6

typedef struct EmitterCfg
{
    f32 vel[7][3];
    f32 g08[3];
    f32 f60;
    int emit[EFFECT2_VELOCITY_RANGE_COUNT];
    int sub[EFFECT2_VELOCITY_RANGE_COUNT];
    u16 col[EFFECT2_VELOCITY_RANGE_COUNT];
    u8 b_a0;
    u8 b_a1;
    u8 pad[2];
} EmitterCfg;

extern EmitterCfg gEffect2VelocityRangeTable;
extern FxNode9 lbl_8039C338;
extern int lbl_803DD2C4;
extern int lbl_803DD348;
extern f32 gEffect2SpawnPhaseA;
extern f32 gEffect2SpawnPhaseB;
extern f32 lbl_803DF87C;
extern f32 lbl_803DF884;
extern f32 lbl_803DF888;
extern f32 lbl_803DF88C;
extern f32 lbl_803DF890;
extern f32 lbl_803DF894;
extern f32 lbl_803DF898;
extern f32 lbl_803DF89C;
extern f32 lbl_803DF8A0;
extern f32 lbl_803DF8A4;
extern f32 lbl_803DF8A8;
extern f32 lbl_803DF8AC;
extern f32 lbl_803DF8B0;
extern f32 lbl_803DF8B4;
extern f32 lbl_803DF8B8;
extern f32 lbl_803DF8BC;
extern f32 lbl_803DF8C0;
extern f32 lbl_803DF8C4;
extern f32 lbl_803DF8C8;
extern f32 lbl_803DF8CC;
extern f32 lbl_803DF8D0;
extern f32 lbl_803DF8D4;
extern f32 lbl_803DF8D8;
extern f32 lbl_803DF8DC;
extern f32 lbl_803DF8E0;
extern f32 lbl_803DF8E4;
extern f32 lbl_803DF8E8;
extern f32 lbl_803DF8EC;
extern f32 lbl_803DF8F0;
extern f32 lbl_803DF8F4;
extern f32 lbl_803DF8F8;
extern f32 lbl_803DF8FC;
extern f32 lbl_803DF900;
extern f32 lbl_803DF904;
extern f32 lbl_803DF908;
extern f32 lbl_803DF90C;
extern f32 lbl_803DF910;
extern f32 lbl_803DF914;
extern f32 lbl_803DF918;
extern f32 lbl_803DF91C;
extern f32 lbl_803DF920;
extern f32 lbl_803DF924;
extern f32 lbl_803DF928;
extern f32 lbl_803DF92C;
extern f32 lbl_803DF930;
extern f32 lbl_803DF934;
extern f32 lbl_803DF938;
extern f32 lbl_803DF93C;
extern f32 lbl_803DF940;
extern f32 lbl_803DF944;
extern f32 lbl_803DF948;
extern f32 lbl_803DF94C;
extern f32 lbl_803DF950;
extern f32 lbl_803DF954;
extern f32 lbl_803DF958;
extern f32 lbl_803DF95C;
extern f32 lbl_803DF960;
extern f32 lbl_803DF964;
extern f32 lbl_803DF968;
extern f32 lbl_803DF96C;
extern f32 lbl_803DF970;
extern f32 lbl_803DF974;
extern f32 lbl_803DF978;
extern f32 lbl_803DF97C;
extern f32 lbl_803DF980;
extern f32 lbl_803DF984;
extern f32 lbl_803DF988;
extern f32 lbl_803DF98C;
extern f32 lbl_803DF990;
extern f32 lbl_803DF994;
extern f32 lbl_803DF998;
extern f32 lbl_803DF99C;
extern f32 lbl_803DF9A0;
extern f32 lbl_803DF9A4;
extern f32 lbl_803DF9A8;
extern f32 lbl_803DF9AC;
extern f32 lbl_803DF9B0;
extern f32 lbl_803DF9B4;
extern f32 lbl_803DF9B8;
extern f32 lbl_803DF9BC;

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

extern s32 gEffect2TextureIdTable[];

int Effect2_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    int i;
    PartFxSpawn cfg;

    gEffect2SpawnPhaseA = gEffect2SpawnPhaseA + lbl_803DF870;
    if (gEffect2SpawnPhaseA > 1.0f) gEffect2SpawnPhaseA = lbl_803DF874;
    gEffect2SpawnPhaseB = gEffect2SpawnPhaseB + lbl_803DF87C;
    if (gEffect2SpawnPhaseB > 1.0f) gEffect2SpawnPhaseB = lbl_803DF880;
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
    cfg.startPosX = lbl_803DF884;
    cfg.startPosY = lbl_803DF884;
    cfg.startPosZ = lbl_803DF884;
    cfg.velocityX = lbl_803DF884;
    cfg.velocityY = lbl_803DF884;
    cfg.velocityZ = lbl_803DF884;
    cfg.scale = lbl_803DF884;
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
    case 0x2b0:
        cfg.velocityX = lbl_803DF888 * (f32)(s32)
        randomGetRange(-0x7c, 0x7c);
        cfg.velocityY = lbl_803DF88C * (f32)(s32)
        randomGetRange(0x392, 0x4d6);
        cfg.velocityZ = lbl_803DF890 * (f32)(s32)
        randomGetRange(-0x7c, 0x7c);
        cfg.startPosX = lbl_803DF894 * (f32)(s32)
        randomGetRange(-0x1d0, 0x1d0);
        cfg.startPosY = lbl_803DF884;
        cfg.startPosZ = lbl_803DF898 * (f32)(s32)
        randomGetRange(-0x1c8, 0x1c8);
        cfg.scale = lbl_803DF89C * (f32)(s32)
        randomGetRange(0x1d, 0x21);
        cfg.lifetimeFrames = 0x13f;
        cfg.textureId = 0x26d;
        cfg.behaviorFlags = 0x400100;
        break;
    case 0x2b1:
        cfg.velocityX = gEffect2VelocityRangeTable.vel[0][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[0][1], gEffect2VelocityRangeTable.vel[0][2]);
        cfg.velocityY = gEffect2VelocityRangeTable.vel[1][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[1][1], gEffect2VelocityRangeTable.vel[1][2]);
        cfg.velocityZ = gEffect2VelocityRangeTable.vel[2][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[2][1], gEffect2VelocityRangeTable.vel[2][2]);
        cfg.startPosX = gEffect2VelocityRangeTable.vel[3][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[3][1], gEffect2VelocityRangeTable.vel[3][2]);
        cfg.startPosY = gEffect2VelocityRangeTable.vel[4][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[4][1], gEffect2VelocityRangeTable.vel[4][2]);
        cfg.startPosZ = gEffect2VelocityRangeTable.vel[5][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[5][1], gEffect2VelocityRangeTable.vel[5][2]);
        cfg.scale = gEffect2VelocityRangeTable.vel[6][0] * (f32)(s32)
        randomGetRange((s32)gEffect2VelocityRangeTable.vel[6][1], gEffect2VelocityRangeTable.vel[6][2]);
        cfg.lifetimeFrames = randomGetRange((s32)gEffect2VelocityRangeTable.g08[1], gEffect2VelocityRangeTable.g08[2]) + (s32)gEffect2VelocityRangeTable.g08[
            0];
        cfg.colorWord0 = gEffect2VelocityRangeTable.col[0];
        cfg.colorWord1 = gEffect2VelocityRangeTable.col[1];
        cfg.colorWord2 = gEffect2VelocityRangeTable.col[2];
        cfg.overrideColor0 = gEffect2VelocityRangeTable.col[3];
        cfg.overrideColor1 = gEffect2VelocityRangeTable.col[4];
        cfg.overrideColor2 = gEffect2VelocityRangeTable.col[5];
        for (i = 0; i < EFFECT2_VELOCITY_RANGE_COUNT; i++) if (gEffect2VelocityRangeTable.emit[i] != 0) cfg.behaviorFlags |= 1 << (gEffect2VelocityRangeTable.emit[i] - 1);
        cfg.renderFlags = 0x2000000;
        for (i = 0; i < EFFECT2_VELOCITY_RANGE_COUNT; i++) if (gEffect2VelocityRangeTable.sub[i] != 0) cfg.renderFlags |= 1 << (gEffect2VelocityRangeTable.sub[i] - 1);
        cfg.textureId = (s32)gEffect2VelocityRangeTable.f60;
        cfg.initialAlpha = randomGetRange(gEffect2VelocityRangeTable.b_a0, gEffect2VelocityRangeTable.b_a1);
        break;
    case 0x2b2:
        cfg.velocityX = lbl_803DF8A0 * (f32)(s32)
        randomGetRange(-0x128, 0xf9);
        cfg.velocityY = lbl_803DF8A4 * (f32)(s32)
        randomGetRange(0x150, 0x2de);
        cfg.velocityZ = lbl_803DF8A8 * (f32)(s32)
        randomGetRange(-0xfc, 0xf9);
        randomGetRange(0, 0);
        cfg.startPosX = lbl_803DF884;
        randomGetRange(1, 1);
        cfg.startPosY = lbl_803DF884;
        cfg.startPosZ = lbl_803DF8AC * (f32)(s32)
        randomGetRange(0, 0);
        cfg.scale = lbl_803DF8B0 * (f32)(s32)
        randomGetRange(0xa, 0x30);
        cfg.lifetimeFrames = randomGetRange(1, 0x26) + 0xe;
        cfg.textureId = 0x1f;
        cfg.behaviorFlags = 0x1000200;
        break;
    case 0x2af:
        cfg.scale = lbl_803DF8B4;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        if ((int)randomGetRange(0, 1) != 0) cfg.behaviorFlags = 0x8100210;
        else cfg.behaviorFlags = 0x180210;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x205;
        break;
    case 0x2ae:
        cfg.startPosY = lbl_803DF8B8;
        cfg.scale = lbl_803DF8B4;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100210;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x205;
        break;
    case 0x2ad:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DF8BC * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.scale = lbl_803DF8C0;
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x400200;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x156;
        break;
    case 0x2ac:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0x3e8, 0x640);
        cfg.velocityY = lbl_803DF8C4 * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.scale = lbl_803DF8C0;
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x400100;
        cfg.textureId = 0xc0e;
        break;
    case 0x2ab:
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = lbl_803DF8C8 * (f32)(s32)
        randomGetRange(0x64, 0x96);
        cfg.velocityZ = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DF8CC;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x23b;
        break;
    case 0x2aa:
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = lbl_803DF8D0 * (f32)(s32)
        randomGetRange(0x64, 0x96);
        cfg.velocityZ = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DF8CC;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x23b;
        break;
    case 0x2a9:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x1f4);
        cfg.scale = lbl_803DF8D4;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100200;
        cfg.textureId = 0x26d;
        break;
    case 0x2a8:
        cfg.velocityX = lbl_803DF8D8 * (f32)(s32)
        randomGetRange(-0x10, 0x10);
        cfg.velocityY = lbl_803DF8DC * (f32)(s32)
        randomGetRange(5, 0x10);
        cfg.velocityZ = lbl_803DF8E0 * (f32)(s32)
        randomGetRange(-0x10, 0x10);
        cfg.scale = lbl_803DF8E4;
        cfg.lifetimeFrames = 0x12;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x2000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x201;
        break;
    case 0x2a7:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x3c, 0x14);
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF8E8 * (f32)(s32)
        randomGetRange(7, 0xa);
        cfg.velocityY = lbl_803DF8EC * (f32)(s32)
        randomGetRange(-0x28, -0x1e);
        cfg.scale = lbl_803DF8F0 * (f32)(s32)
        randomGetRange(5, 0x19);
        cfg.lifetimeFrames = randomGetRange(0x186, 0x1c2);
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.overrideColor0 = cfg.colorWord0 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.overrideColor1 = cfg.colorWord1 = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.overrideColor2 = cfg.colorWord2 = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.renderFlags = 0x1000020;
        cfg.behaviorFlags = 0x86000000;
        cfg.textureId = 0x3a2;
        break;
    case 0x2a6:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x3c, 0x14);
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF8E8 * (f32)(s32)
        randomGetRange(7, 0xa);
        cfg.velocityY = lbl_803DF8F4 * (f32)(s32)
        randomGetRange(-0x28, -0x1e);
        cfg.scale = lbl_803DF8F8 * (f32)(s32)
        randomGetRange(0x64, 0x78);
        cfg.lifetimeFrames = 0x3b6;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = (u32)randFn_80080100;
        cfg.textureId = 0x5c;
        break;
    case 0x2a5:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x3c);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x78, 0x78);
        cfg.velocityZ = lbl_803DF8BC * (f32)(s32)
        randomGetRange(-2, 2);
        cfg.velocityY = lbl_803DF8FC * (f32)(s32)
        randomGetRange(2, 5);
        cfg.velocityZ = lbl_803DF8BC * (f32)(s32)
        randomGetRange(-2, 2);
        cfg.scale = lbl_803DF900 * (f32)(s32)
        randomGetRange(0x50, 0x78);
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x180208;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5f;
        break;
    case 0x2a4:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x5a, 0x5a);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityX = lbl_803DF904 * (f32)(s32)
        randomGetRange(-2, 2);
        cfg.velocityY = lbl_803DF908 * (f32)(s32)
        randomGetRange(2, 5);
        cfg.velocityZ = lbl_803DF90C * (f32)(s32)
        randomGetRange(-2, 2);
        cfg.scale = lbl_803DF87C * (f32)(s32)
        randomGetRange(0x50, 0xc8);
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x180208;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5f;
        break;
    case 0x2a3:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.velocityZ = lbl_803DF910 * (f32)(s32)
        randomGetRange(0x46, 0x64);
        cfg.scale = lbl_803DF8F4 * (f32)(s32)
        randomGetRange(1, 0xa);
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0x2d;
        cfg.behaviorFlags = 0x100;
        cfg.textureId = 0x16c;
        break;
    case 0x2a2:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = lbl_803DF914;
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityY = lbl_803DF918 * (f32)(s32)
        randomGetRange(0xc, 0x10);
        cfg.velocityZ = lbl_803DF91C * (f32)(s32)
        randomGetRange(0xc, 0x10);
        cfg.scale = lbl_803DF920;
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x2000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0xc9d;
        break;
    case 0x29d:
        if (spawnParams == 0)
            FILL338();
        cfg.sourceVecX = 0x3e8;
        cfg.sourceVecY = 0x3e8;
        cfg.sourceVecZ = 0x3e8;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.lifetimeFrames = 6;
        cfg.initialAlpha = 0xe1;
        cfg.behaviorFlags = 0x4a0010;
        if ((int)randomGetRange(0, 1) != 0) cfg.renderFlags = 0x202;
        else cfg.renderFlags = 0x102;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF87C * (f32)(s32)
            randomGetRange(0, 3) + lbl_803DF870;
            cfg.textureId = 0xc0f;
        }
        else
        {
            cfg.scale = lbl_803DF87C * (f32)(s32)
            randomGetRange(0, 3) + lbl_803DF924;
            cfg.textureId = 0xc0f;
        }
        break;
    case 0x29e:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480010;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF928;
            cfg.textureId = 0x74;
        }
        else
        {
            cfg.scale = lbl_803DF92C;
            cfg.textureId = 0x74;
        }
        cfg.renderFlags = 2;
        break;
    case 0x29f:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480010;
        cfg.renderFlags = 2;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF8C8;
            cfg.textureId = 0xc22;
        }
        else
        {
            cfg.scale = lbl_803DF930;
            cfg.textureId = 0xdc;
        }
        break;
    case 0x2a0:
        if (spawnParams == 0)
            FILL338();
        cfg.lifetimeFrames = 0x1e;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180010;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF934 * (f32)(s32)
            randomGetRange(0x14, 0x32);
            cfg.textureId = 0x73;
        }
        else
        {
            cfg.scale = lbl_803DF938 * (f32)(s32)
            randomGetRange(0x14, 0x32);
            cfg.textureId = 0x73;
        }
        break;
    case 0x2a1:
        if (spawnParams == 0)
            FILL338();
        cfg.lifetimeFrames = 0x3c;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x480010;
        cfg.renderFlags = 2;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = lbl_803DF93C * (f32)(s32)
            randomGetRange(0x46, 0x50);
            cfg.textureId = 0x73;
        }
        else
        {
            cfg.scale = lbl_803DF940 * (f32)(s32)
            randomGetRange(0x46, 0x50);
            cfg.textureId = 0x73;
        }
        break;
    case 0x297:
        cfg.velocityX = lbl_803DF944 * (f32)(s32)
        randomGetRange(-0x10, 0x10);
        cfg.velocityY = lbl_803DF948 * (f32)(s32)
        randomGetRange(5, 0x10);
        cfg.velocityZ = lbl_803DF94C * (f32)(s32)
        randomGetRange(-0x10, 0x10);
        cfg.scale = lbl_803DF950;
        cfg.lifetimeFrames = 0x54;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x2000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x1fe;
        break;
    case 0x25b:
        cfg.scale = lbl_803DF954;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x7b;
        break;
    case 0x25c:
    case 0x269:
    case 0x27d:
        cfg.startPosX = lbl_803DF8B4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF8FC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF958 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityX = lbl_803DF95C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF960 * (f32)(s32)
        randomGetRange(0xe, 0x12);
        cfg.scale = lbl_803DF964;
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        if (effectId == 0x25c)
        {
            cfg.textureId = 0x7a;
            cfg.quadVertex3Pad06 = 0x25d;
        }
        else if (effectId == 0x272)
        {
            cfg.textureId = 0x202;
            cfg.quadVertex3Pad06 = 0x273;
        }
        else if (effectId == 0x27d)
        {
            cfg.textureId = 0x7a;
            cfg.quadVertex3Pad06 = 0x27e;
        }
        else
        {
            cfg.textureId = 0x1fe;
            cfg.quadVertex3Pad06 = 0x26a;
        }
        break;
    case 0x25d:
    case 0x26a:
    case 0x273:
    case 0x27e:
        cfg.scale = lbl_803DF964;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x7a;
        if (effectId == 0x25d)
        {
            cfg.textureId = 0x7a;
        }
        else if (effectId == 0x273)
        {
            cfg.textureId = 0x202;
        }
        else if (effectId == 0x27e)
        {
            cfg.textureId = 0x7a;
        }
        else
        {
            cfg.textureId = 0x1fe;
        }
        break;
    case 0x25e:
    case 0x26b:
    case 0x27b:
        cfg.startPosX = lbl_803DF8B4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = lbl_803DF8FC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF958 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityX = lbl_803DF8EC * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(0xe, 0x12);
        cfg.scale = lbl_803DF968;
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x25f;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        if (effectId == 0x25e)
        {
            cfg.textureId = 0x79;
            cfg.quadVertex3Pad06 = 0x25d;
        }
        else if (effectId == 0x27b)
        {
            cfg.textureId = 0x1fb;
            cfg.quadVertex3Pad06 = 0x27c;
        }
        else if (effectId == 0x274)
        {
            cfg.textureId = 0x202;
            cfg.quadVertex3Pad06 = 0x275;
        }
        else
        {
            cfg.textureId = 0x1ff;
            cfg.quadVertex3Pad06 = 0x26c;
        }
        break;
    case 0x25f:
    case 0x26c:
    case 0x275:
    case 0x27c:
        cfg.scale = lbl_803DF968;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        if (effectId == 0x25f)
        {
            cfg.textureId = 0x79;
        }
        else if (effectId == 0x275)
        {
            cfg.textureId = 0x202;
        }
        else if (effectId == 0x27c)
        {
            cfg.textureId = 0x1fb;
        }
        else
        {
            cfg.textureId = 0x1ff;
        }
        break;
    case 0x260:
    case 0x261:
    case 0x262:
    case 0x278:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x26, 0x26);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xa, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x6c, 0x6c);
        cfg.velocityX = lbl_803DF8EC * (f32)(s32)
        randomGetRange(-3, 3);
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(-6, 6);
        cfg.velocityZ = lbl_803DF95C * (f32)(s32)
        randomGetRange(-3, 3);
        cfg.scale = lbl_803DF96C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480110;
        if (effectId == 0x278) cfg.textureId = gEffect2TextureIdTable[3];
        else cfg.textureId = gEffect2TextureIdTable[effectId - 0x260];
        break;
    case 0x263:
    case 0x264:
    case 0x265:
    case 0x276:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF904 * (f32)(s32)
        randomGetRange(-3, 3);
        cfg.scale = lbl_803DF96C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x480110;
        if (effectId == 0x276) cfg.textureId = gEffect2TextureIdTable[3];
        else cfg.textureId = gEffect2TextureIdTable[effectId - 0x263];
        break;
    case 0x266:
    case 0x267:
    case 0x268:
    case 0x277:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF904 * (f32)(s32)
        randomGetRange(-3, 3);
        cfg.scale = lbl_803DF96C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x480100;
        if (effectId == 0x277) cfg.textureId = gEffect2TextureIdTable[3];
        else cfg.textureId = gEffect2TextureIdTable[effectId - 0x266];
        break;
    case 0x26d:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x3c, 0x3c);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x3c, 0x3c);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x12, 0x12);
        cfg.velocityZ = lbl_803DF970 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF974;
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x2000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x1fe;
        break;
    case 0x26e:
        cfg.scale = lbl_803DF974;
        cfg.lifetimeFrames = 0x55;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x2000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x1fe;
        break;
    case 0x26f:
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF978;
        cfg.lifetimeFrames = 0x7d;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80200;
        cfg.textureId = 0x125;
        break;
    case 0x270:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 5);
        cfg.scale = lbl_803DF97C;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x810020c;
        cfg.textureId = 0x167;
        break;
    case 0x271:
        cfg.startPosY = lbl_803DF884;
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF980;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100204;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0x167;
        break;
    case 0x286:
    case 0x287:
    case 0x288:
        cfg.startPosY = (f32)(s32)
        randomGetRange(-6, 2);
        cfg.velocityX = lbl_803DF96C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DF96C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DF984;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480208;
        if (effectId == 0x286) cfg.textureId = 0x160;
        else if (effectId == 0x287) cfg.textureId = 0x200;
        else if (effectId == 0x288) cfg.textureId = 0xdd;
        break;
    case 0x27f:
        cfg.scale = lbl_803DF988 * *(f32*)((char*)sourceObj + 8);
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x80080208;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0x6400;
        cfg.colorWord1 = 0x3200;
        cfg.colorWord2 = 0xa000;
        cfg.overrideColor0 = 0x1f4;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0x3e8;
        cfg.renderFlags = 0x20;
        break;
    case 0x280:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = lbl_803DF98C + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-0x14, 0x14);
            cfg.startPosY = lbl_803DF98C;
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0x14, 0x14);
        }
        cfg.velocityX = lbl_803DF95C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF8FC * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.velocityZ = lbl_803DF95C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DF994 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF990;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.quadVertex3Pad06 = 0x281;
        cfg.behaviorFlags = 0x81488000;
        cfg.textureId = randomGetRange(0, 2) + 0x208;
        break;
    case 0x281:
        cfg.velocityY = lbl_803DF998 * (f32)(s32)
        randomGetRange(2, 0x14);
        cfg.scale = lbl_803DF99C;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0xa;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0x5000;
        cfg.colorWord1 = 0x1e00;
        cfg.colorWord2 = 0x7800;
        cfg.overrideColor0 = 0x5000;
        cfg.overrideColor1 = 0x1e00;
        cfg.overrideColor2 = 0x7800;
        cfg.renderFlags = 0x20;
        break;
    case 0x282:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)
            randomGetRange(1, 0xa);
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0x96, 0x96);
        }
        cfg.velocityX = lbl_803DF95C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803DF970 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DF95C * (f32)(s32)
        randomGetRange(4, 4);
        cfg.scale = lbl_803DF900 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF9A0;
        cfg.lifetimeFrames = randomGetRange(0xe6, 0x118);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x284;
        cfg.behaviorFlags = 0x81488200;
        cfg.textureId = 0xc0a;
        break;
    case 0x283:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)
            randomGetRange(1, 0xa);
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0x96, 0x96);
        }
        cfg.velocityY = lbl_803DF960 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DF900 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF9A0;
        cfg.lifetimeFrames = randomGetRange(0xe6, 0x118);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xc0d;
        break;
    case 0x284:
        cfg.velocityY = lbl_803DF998 * (f32)(s32)
        randomGetRange(2, 0x14);
        cfg.scale = lbl_803DF9A4;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0x9b00;
        cfg.overrideColor0 = 0x9600;
        cfg.overrideColor1 = 0x1400;
        cfg.overrideColor2 = 0x1400;
        cfg.renderFlags = 0x20;
        break;
    case 0x285:
        if (spawnParams == 0)
            FILL338();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)
            randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)
            randomGetRange(1, 0xa);
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-0x96, 0x96);
        }
        cfg.velocityY = lbl_803DF998 * (f32)(s32)
        randomGetRange(2, 4);
        cfg.velocityZ = lbl_803DF8D0 * (f32)(s32)
        randomGetRange(2, 4);
        cfg.scale = lbl_803DF870 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF9A8;
        cfg.lifetimeFrames = randomGetRange(0, 0x32) + 0x32;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0xc0a;
        break;
    case 0x258:
        cfg.velocityX = lbl_803DF998 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF998 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DF998 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DF9AC;
        cfg.lifetimeFrames = randomGetRange(0x50, 0x82);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x7b;
        break;
    case 0x289:
        cfg.startPosX = lbl_803DF8B4 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.startPosZ = lbl_803DF8B4 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF95C * (f32)(s32)
        randomGetRange(0x28, 0x3c) + lbl_803DF880;
        cfg.scale = lbl_803DF93C * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x14, 0x8c);
        cfg.behaviorFlags = 0x80400209;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x28a:
        cfg.startPosX = lbl_803DF884;
        cfg.startPosY = lbl_803DF884;
        cfg.startPosZ = lbl_803DF9B0;
        cfg.scale = lbl_803DF904;
        cfg.initialAlpha = 0x55;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x40);
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0xc9d;
        break;
    case 0x28b:
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0x12c);
        cfg.scale = lbl_803DF978;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100200;
        cfg.textureId = 0x159;
        break;
    case 0x28c:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0, 0xc8);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityX = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DF870 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DF9B4 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x88108;
        cfg.textureId = 0x159;
        break;
    case 0x28d:
        cfg.scale = lbl_803DF93C * (f32)(s32)
        randomGetRange(0x5a, 0x64);
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0xa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x500200;
        cfg.textureId = 0x159;
        break;
    case 0x28e:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8);
        cfg.startPosY = lbl_803DF874 * (f32)(s32)
        randomGetRange(0x12c, 0x708);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8);
        cfg.velocityX = gEffect2ScrollPhaseA * (lbl_803DF970 * (f32)(s32)
        randomGetRange(-0x28, 0x28)
        )
        ;
        cfg.velocityZ = -gEffect2ScrollPhaseA * (lbl_803DF970 * (f32)(s32)
        randomGetRange(-0x28, 0x28)
        )
        ;
        cfg.scale = lbl_803DF96C;
        cfg.lifetimeFrames = 0x118;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x300020;
        cfg.behaviorFlags = 0x2008000;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x63bf;
        cfg.overrideColor1 = 0x9e7;
        cfg.overrideColor2 = 0x3e8;
        cfg.textureId = 0x23b;
        break;
    case 0x28f:
    case 0x290:
    case 0x291:
    case 0x292:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.scale = lbl_803DF93C * (f32)(s32)
        randomGetRange(5, 0x19);
        cfg.lifetimeFrames = 0x230;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.renderFlags = 0x20;
        cfg.behaviorFlags = 0x86000008;
        cfg.colorWord0 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.colorWord1 = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.colorWord2 = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.textureId = effectId + 0x113;
        break;
    case 0x293:
    case 0x294:
    case 0x295:
    case 0x296:
        cfg.startPosX = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosY = lbl_803DF9B8;
        cfg.startPosZ = lbl_803DF874 * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.velocityX = lbl_803DF9BC * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DF870 * (f32)(s32)
        randomGetRange(0x64, 0xc8);
        cfg.velocityZ = lbl_803DF9BC * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DF93C * (f32)(s32)
        randomGetRange(5, 0x19);
        cfg.lifetimeFrames = 0x7d0;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.renderFlags = 0x31000020;
        cfg.behaviorFlags = 0x8e000108;
        cfg.colorWord0 = (u16)(randomGetRange(0, (effectId - 0x292) * 0x2710) + 0x63bf);
        cfg.colorWord1 = (u16)(randomGetRange(0, (effectId - 0x292) * 0x2710) + 0x3caf);
        cfg.colorWord2 = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.textureId = effectId + 0x10f;
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
    lbl_803DD348 = lbl_803DD2C4;
    return spawnResult;
}
#undef FILL338

EmitterCfg gEffect2VelocityRangeTable =
{
    {
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.0f, 0.0f, 0.0f },
        { 0.01f, 0.0f, 0.0f },
    },
    { 10.0f, 0.0f, 0.0f },
    517.0f,
    { 0, 0, 0, 0, 0, 0 },
    { 0, 0, 0, 0, 0, 0 },
    { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
    0xFF,
    0xFF,
    { 0x00, 0x00 },
};

/* --- effect2 .data reconstruction (absorbed 0x80310604-0x80310670) --- */
extern void partfx_initialise();
extern void partfx_release();
extern void partfx_onMapSetup();
extern void partfx_spawnObject();
extern void partfx_updateFrameState();
extern void Effect1_initialise();
extern void Effect1_release();
extern void Effect1_func03_nop();
extern void Effect1_func04();
extern void Effect1_func05();

void* lbl_80310604[10] = {
    (void*)0, (void*)0, (void*)0, (void*)0x50000,
    (void*)partfx_initialise, (void*)partfx_release, (void*)0,
    (void*)partfx_onMapSetup, (void*)partfx_spawnObject, (void*)partfx_updateFrameState
};
char sModgfxAlphaDebugFormat[10] = "alpha %d\n";
void* lbl_80310638[10] = {
    (void*)0, (void*)0, (void*)0, (void*)0x50000,
    (void*)Effect1_initialise, (void*)Effect1_release, (void*)0,
    (void*)Effect1_func03_nop, (void*)Effect1_func04, (void*)Effect1_func05
};
s32 gEffect2TextureIdTable[4] = { 0xDF, 0x1FC, 0x200, 0x1FB };
