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
#include "main/dll/partfx_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/dll/modgfx.h"
#include "main/maketex_random_api.h"
#include "main/dll/dll_001B_effect2.h"
#include "main/dll/dll_000E_partfx.h"
#include "main/dll/dll_001A_effect1.h"

int lbl_803DD348;
f32 gEffect2SinValueA;
f32 gEffect2SinValueB;
int gEffect2SinAngleB;
int gEffect2SinAngleA;

f32 gEffect2SpawnPhaseA = 0.1f;
f32 gEffect2SpawnPhaseB = 0.3f;
f32 gEffect2ScrollPhaseA = 0.1f;
f32 gEffect2ScrollPhaseB = 0.3f;

extern f32 gEffect2ScrollPhaseA;
extern f32 gEffect2ScrollPhaseB;
extern int gEffect2SinAngleA;
extern int gEffect2SinAngleB;
extern f32 gEffect2SinValueB;
extern f32 gEffect2SinValueA;
extern EmitterCfg gEffect2VelocityRangeTable;
extern FxNode9 lbl_8039C338;
extern int lbl_803DD2C4;
extern int lbl_803DD348;
extern f32 gEffect2SpawnPhaseA;
extern f32 gEffect2SpawnPhaseB;
extern s32 gEffect2TextureIdTable[];

EmitterCfg gEffect2VelocityRangeTable = {
    {
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        {0.01f, 0.0f, 0.0f},
    },
    {10.0f, 0.0f, 0.0f},
    517.0f,
    {0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0},
    {0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
    0xFF,
    0xFF,
    {0x00, 0x00},
};

/* --- effect2 .data reconstruction (absorbed 0x80310604-0x80310670) --- */
void* lbl_80310604[10] = {(void*)0,
                          (void*)0,
                          (void*)0,
                          (void*)0x50000,
                          (void*)partfx_initialise,
                          (void*)partfx_release,
                          (void*)0,
                          (void*)partfx_onMapSetup,
                          (void*)partfx_spawnObject,
                          (void*)partfx_updateFrameState};
char sModgfxAlphaDebugFormat[10] = "alpha %d\n";
void* lbl_80310638[10] = {(void*)0,
                          (void*)0,
                          (void*)0,
                          (void*)0x50000,
                          (void*)Effect1_initialise,
                          (void*)Effect1_release,
                          (void*)0,
                          (void*)Effect1_func03_nop,
                          (void*)Effect1_func04,
                          (void*)Effect1_func05};
s32 gEffect2TextureIdTable[4] = {0xDF, 0x1FC, 0x200, 0x1FB};
void* lbl_80310670[10] = {(void*)0,
                          (void*)0,
                          (void*)0,
                          (void*)0x50000,
                          (void*)Effect2_initialise,
                          (void*)Effect2_release,
                          (void*)0,
                          (void*)Effect2_func03_nop,
                          (void*)Effect2_func04,
                          (void*)Effect2_func05};

#pragma scheduling off
#pragma peephole off

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

#define FILL338()                                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        lbl_8039C338.posX = 0.0f;                                                                              \
        lbl_8039C338.posY = 0.0f;                                                                              \
        lbl_8039C338.posZ = 0.0f;                                                                              \
        lbl_8039C338.scale = 1.0f;                                                                             \
        lbl_8039C338.unk0 = 0;                                                                                         \
        lbl_8039C338.unk2 = 0;                                                                                         \
        lbl_8039C338.unk4 = 0;                                                                                         \
        spawnParams = (PartFxSpawnParams*)&lbl_8039C338;                                                               \
    } while (0)

int Effect2_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   s16* extraArgs)
{
    int spawnResult;
    int i;
    PartFxSpawn cfg;

    gEffect2SpawnPhaseA += 0.001f;
    if (gEffect2SpawnPhaseA > 1.0f)
        gEffect2SpawnPhaseA = 0.1f;
    gEffect2SpawnPhaseB += 0.0003f;
    if (gEffect2SpawnPhaseB > 1.0f)
        gEffect2SpawnPhaseB = 0.3f;
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
    case 0x2b0:
        cfg.velocityX = 0.001481f * (f32)(s32)randomGetRange(-0x7c, 0x7c);
        cfg.velocityY = -0.000243f * (f32)(s32)randomGetRange(0x392, 0x4d6);
        cfg.velocityZ = 0.001443f * (f32)(s32)randomGetRange(-0x7c, 0x7c);
        cfg.startPosX = 0.109434f * (f32)(s32)randomGetRange(-0x1d0, 0x1d0);
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.155974f * (f32)(s32)randomGetRange(-0x1c8, 0x1c8);
        cfg.scale = 3e-05f * (f32)(s32)randomGetRange(0x1d, 0x21);
        cfg.lifetimeFrames = 0x13f;
        cfg.textureId = 0x26d;
        cfg.behaviorFlags = 0x400100;
        break;
    case 0x2b1:
        cfg.velocityX =
            gEffect2VelocityRangeTable.vel[0][0] *
            (f32)(s32)randomGetRange((s32)gEffect2VelocityRangeTable.vel[0][1], gEffect2VelocityRangeTable.vel[0][2]);
        cfg.velocityY =
            gEffect2VelocityRangeTable.vel[1][0] *
            (f32)(s32)randomGetRange((s32)gEffect2VelocityRangeTable.vel[1][1], gEffect2VelocityRangeTable.vel[1][2]);
        cfg.velocityZ =
            gEffect2VelocityRangeTable.vel[2][0] *
            (f32)(s32)randomGetRange((s32)gEffect2VelocityRangeTable.vel[2][1], gEffect2VelocityRangeTable.vel[2][2]);
        cfg.startPosX =
            gEffect2VelocityRangeTable.vel[3][0] *
            (f32)(s32)randomGetRange((s32)gEffect2VelocityRangeTable.vel[3][1], gEffect2VelocityRangeTable.vel[3][2]);
        cfg.startPosY =
            gEffect2VelocityRangeTable.vel[4][0] *
            (f32)(s32)randomGetRange((s32)gEffect2VelocityRangeTable.vel[4][1], gEffect2VelocityRangeTable.vel[4][2]);
        cfg.startPosZ =
            gEffect2VelocityRangeTable.vel[5][0] *
            (f32)(s32)randomGetRange((s32)gEffect2VelocityRangeTable.vel[5][1], gEffect2VelocityRangeTable.vel[5][2]);
        cfg.scale =
            gEffect2VelocityRangeTable.vel[6][0] *
            (f32)(s32)randomGetRange((s32)gEffect2VelocityRangeTable.vel[6][1], gEffect2VelocityRangeTable.vel[6][2]);
        cfg.lifetimeFrames = randomGetRange((s32)gEffect2VelocityRangeTable.lifetimeRange[1],
                                            gEffect2VelocityRangeTable.lifetimeRange[2]) +
                             (s32)gEffect2VelocityRangeTable.lifetimeRange[0];
        cfg.colorWord0 = gEffect2VelocityRangeTable.col[0];
        cfg.colorWord1 = gEffect2VelocityRangeTable.col[1];
        cfg.colorWord2 = gEffect2VelocityRangeTable.col[2];
        cfg.overrideColor0 = gEffect2VelocityRangeTable.col[3];
        cfg.overrideColor1 = gEffect2VelocityRangeTable.col[4];
        cfg.overrideColor2 = gEffect2VelocityRangeTable.col[5];
        for (i = 0; i < EFFECT2_VELOCITY_RANGE_COUNT; i++)
            if (gEffect2VelocityRangeTable.emit[i] != 0)
                cfg.behaviorFlags |= 1 << (gEffect2VelocityRangeTable.emit[i] - 1);
        cfg.renderFlags = 0x2000000;
        for (i = 0; i < EFFECT2_VELOCITY_RANGE_COUNT; i++)
            if (gEffect2VelocityRangeTable.sub[i] != 0)
                cfg.renderFlags |= 1 << (gEffect2VelocityRangeTable.sub[i] - 1);
        cfg.textureId = (s32)gEffect2VelocityRangeTable.textureId;
        cfg.initialAlpha = randomGetRange(gEffect2VelocityRangeTable.alphaMin, gEffect2VelocityRangeTable.alphaMax);
        break;
    case 0x2b2:
        cfg.velocityX = 0.002042f * (f32)(s32)randomGetRange(-0x128, 0xf9);
        cfg.velocityY = 0.001929f * (f32)(s32)randomGetRange(0x150, 0x2de);
        cfg.velocityZ = 0.002038f * (f32)(s32)randomGetRange(-0xfc, 0xf9);
        randomGetRange(0, 0);
        cfg.startPosX = 0.0f;
        randomGetRange(1, 1);
        cfg.startPosY = 0.0f;
        cfg.startPosZ = -0.073813f * (f32)(s32)randomGetRange(0, 0);
        cfg.scale = 8e-05f * (f32)(s32)randomGetRange(0xa, 0x30);
        cfg.lifetimeFrames = randomGetRange(1, 0x26) + 0xe;
        cfg.textureId = 0x1f;
        cfg.behaviorFlags = 0x1000200;
        break;
    case 0x2af:
        cfg.scale = 0.2f;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        if ((int)randomGetRange(0, 1) != 0)
            cfg.behaviorFlags = 0x8100210;
        else
            cfg.behaviorFlags = 0x180210;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x205;
        break;
    case 0x2ae:
        cfg.startPosY = 25.0f;
        cfg.scale = 0.2f;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100210;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x205;
        break;
    case 0x2ad:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityZ = -0.05f * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.scale = 0.007f;
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x400200;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x156;
        break;
    case 0x2ac:
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0x3e8, 0x640);
        cfg.velocityY = -0.02f * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.scale = 0.007f;
        cfg.lifetimeFrames = 0x82;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x400100;
        cfg.textureId = 0xc0e;
        break;
    case 0x2ab:
        cfg.velocityX = 0.001f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.008f * (f32)(s32)randomGetRange(0x64, 0x96);
        cfg.velocityZ = 0.001f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = 0.0035f;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x23b;
        break;
    case 0x2aa:
        cfg.velocityX = 0.001f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.006f * (f32)(s32)randomGetRange(0x64, 0x96);
        cfg.velocityZ = 0.001f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = 0.0035f;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x23b;
        break;
    case 0x2a9:
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0, 0x1f4);
        cfg.scale = 0.025f;
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100200;
        cfg.textureId = 0x26d;
        break;
    case 0x2a8:
        cfg.velocityX = 0.26f * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.velocityY = 0.56f * (f32)(s32)randomGetRange(5, 0x10);
        cfg.velocityZ = 0.236f * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.scale = 0.00325f;
        cfg.lifetimeFrames = 0x12;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x2000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x201;
        break;
    case 0x2a7:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0, 0x14);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x3c, 0x14);
        cfg.velocityX = 0.001f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = -0.01f * (f32)(s32)randomGetRange(7, 0xa);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(-0x28, -0x1e);
        cfg.scale = 5e-05f * (f32)(s32)randomGetRange(5, 0x19);
        cfg.lifetimeFrames = randomGetRange(0x186, 0x1c2);
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.overrideColor0 = cfg.colorWord0 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
        cfg.overrideColor1 = cfg.colorWord1 = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
        cfg.overrideColor2 = cfg.colorWord2 = (u16)(randomGetRange(0, 0x2710) + 0x159f);
        cfg.renderFlags = 0x1000020;
        cfg.behaviorFlags = 0x86000000;
        cfg.textureId = 0x3a2;
        break;
    case 0x2a6:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0, 0x14);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x3c, 0x14);
        cfg.velocityX = 0.001f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = -0.01f * (f32)(s32)randomGetRange(7, 0xa);
        cfg.velocityY = 0.003f * (f32)(s32)randomGetRange(-0x28, -0x1e);
        cfg.scale = 1e-05f * (f32)(s32)randomGetRange(0x64, 0x78);
        cfg.lifetimeFrames = 0x3b6;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = (u32)randFn_80080100;
        cfg.textureId = 0x5c;
        break;
    case 0x2a5:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0, 0x3c);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x78, 0x78);
        cfg.velocityZ = -0.05f * (f32)(s32)randomGetRange(-2, 2);
        cfg.velocityY = 0.03f * (f32)(s32)randomGetRange(2, 5);
        cfg.velocityZ = -0.05f * (f32)(s32)randomGetRange(-2, 2);
        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(0x50, 0x78);
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x180208;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5f;
        break;
    case 0x2a4:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x5a, 0x5a);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0, 0x64);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityX = 0.05f * (f32)(s32)randomGetRange(-2, 2);
        cfg.velocityY = 0.07f * (f32)(s32)randomGetRange(2, 5);
        cfg.velocityZ = -0.1f * (f32)(s32)randomGetRange(-2, 2);
        cfg.scale = 0.0003f * (f32)(s32)randomGetRange(0x50, 0xc8);
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x180208;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5f;
        break;
    case 0x2a3:
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.velocityZ = -0.03f * (f32)(s32)randomGetRange(0x46, 0x64);
        cfg.scale = 0.003f * (f32)(s32)randomGetRange(1, 0xa);
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0x2d;
        cfg.behaviorFlags = 0x100;
        cfg.textureId = 0x16c;
        break;
    case 0x2a2:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.startPosY = 1.4e+02f;
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x2bc, 0x2bc);
        cfg.velocityY = -0.16f * (f32)(s32)randomGetRange(0xc, 0x10);
        cfg.velocityZ = 0.0136f * (f32)(s32)randomGetRange(0xc, 0x10);
        cfg.scale = 0.0005f;
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
        if ((int)randomGetRange(0, 1) != 0)
            cfg.renderFlags = 0x202;
        else
            cfg.renderFlags = 0x102;
        if (0.0f == spawnParams->scale)
        {
            cfg.scale = 0.0003f * (f32)(s32)randomGetRange(0, 3) + 0.001f;
            cfg.textureId = 0xc0f;
        }
        else
        {
            cfg.scale = 0.0003f * (f32)(s32)randomGetRange(0, 3) + 0.0013f;
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
            cfg.scale = 0.0042f;
            cfg.textureId = 0x74;
        }
        else
        {
            cfg.scale = 0.0046f;
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
            cfg.scale = 0.008f;
            cfg.textureId = 0xc22;
        }
        else
        {
            cfg.scale = 0.012f;
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
            cfg.scale = 0.00013f * (f32)(s32)randomGetRange(0x14, 0x32);
            cfg.textureId = 0x73;
        }
        else
        {
            cfg.scale = 0.00021f * (f32)(s32)randomGetRange(0x14, 0x32);
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
            cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0x46, 0x50);
            cfg.textureId = 0x73;
        }
        else
        {
            cfg.scale = 0.00012f * (f32)(s32)randomGetRange(0x46, 0x50);
            cfg.textureId = 0x73;
        }
        break;
    case 0x297:
        cfg.velocityX = 0.16f * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.velocityY = 0.46f * (f32)(s32)randomGetRange(5, 0x10);
        cfg.velocityZ = 0.136f * (f32)(s32)randomGetRange(-0x10, 0x10);
        cfg.scale = 0.0125f;
        cfg.lifetimeFrames = 0x54;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x2000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x1fe;
        break;
    case 0x25b:
        cfg.scale = 0.0032f;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x2000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x7b;
        break;
    case 0x25c:
    case 0x269:
    case 0x27d:
        cfg.startPosX = 0.2f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = 0.03f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.0045f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0xe, 0x12);
        cfg.scale = 0.0017f;
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
        cfg.scale = 0.0017f;
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
        cfg.startPosX = 0.2f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.startPosY = 0.03f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.0045f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityX = 0.005f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0xe, 0x12);
        cfg.scale = 0.0011f;
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
        cfg.scale = 0.0011f;
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
        cfg.startPosX = (f32)(s32)randomGetRange(-0x26, 0x26);
        cfg.startPosY = (f32)(s32)randomGetRange(0xa, 0x50);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x6c, 0x6c);
        cfg.velocityX = 0.005f * (f32)(s32)randomGetRange(-3, 3);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(-6, 6);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-3, 3);
        cfg.scale = 0.0015f;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80480110;
        if (effectId == 0x278)
            cfg.textureId = gEffect2TextureIdTable[3];
        else
            cfg.textureId = gEffect2TextureIdTable[effectId - 0x260];
        break;
    case 0x263:
    case 0x264:
    case 0x265:
    case 0x276:
        cfg.startPosX = (f32)(s32)randomGetRange(-8, 8);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)randomGetRange(-8, 8);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(-3, 3);
        cfg.scale = 0.0015f;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x480110;
        if (effectId == 0x276)
            cfg.textureId = gEffect2TextureIdTable[3];
        else
            cfg.textureId = gEffect2TextureIdTable[effectId - 0x263];
        break;
    case 0x266:
    case 0x267:
    case 0x268:
    case 0x277:
        cfg.startPosX = (f32)(s32)randomGetRange(-8, 8);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x50);
        cfg.startPosZ = (f32)(s32)randomGetRange(-8, 8);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(-3, 3);
        cfg.scale = 0.0015f;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x480100;
        if (effectId == 0x277)
            cfg.textureId = gEffect2TextureIdTable[3];
        else
            cfg.textureId = gEffect2TextureIdTable[effectId - 0x266];
        break;
    case 0x26d:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x3c, 0x3c);
        cfg.startPosY = (f32)(s32)randomGetRange(-0x3c, 0x3c);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x12, 0x12);
        cfg.velocityZ = 0.06f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.0055f;
        cfg.lifetimeFrames = 0xc8;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x2000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x1fe;
        break;
    case 0x26e:
        cfg.scale = 0.0055f;
        cfg.lifetimeFrames = 0x55;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x2000200;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x1fe;
        break;
    case 0x26f:
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.015f;
        cfg.lifetimeFrames = 0x7d;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80200;
        cfg.textureId = 0x125;
        break;
    case 0x270:
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0, 5);
        cfg.scale = 0.032f;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x810020c;
        cfg.textureId = 0x167;
        break;
    case 0x271:
        cfg.startPosY = 0.0f;
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.062f;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100204;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0x167;
        break;
    case 0x286:
    case 0x287:
    case 0x288:
        cfg.startPosY = (f32)(s32)randomGetRange(-6, 2);
        cfg.velocityX = 0.0015f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.0015f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.00195f;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480208;
        if (effectId == 0x286)
            cfg.textureId = 0x160;
        else if (effectId == 0x287)
            cfg.textureId = 0x200;
        else if (effectId == 0x288)
            cfg.textureId = 0xdd;
        break;
    case 0x27f:
        cfg.scale = 0.0645f * *(f32*)((char*)sourceObj + 8);
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
            cfg.startPosY = 1e+02f + spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = (f32)(s32)randomGetRange(-0x14, 0x14);
            cfg.startPosY = 1e+02f;
            cfg.startPosZ = (f32)(s32)randomGetRange(-0x14, 0x14);
        }
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.03f * (f32)(s32)randomGetRange(0, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.0004f * (f32)(s32)randomGetRange(0, 0xa) + 0.000945f;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.quadVertex3Pad06 = 0x281;
        cfg.behaviorFlags = 0x81488000;
        cfg.textureId = randomGetRange(0, 2) + 0x208;
        break;
    case 0x281:
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(2, 0x14);
        cfg.scale = 0.018445f;
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
            cfg.startPosX = (f32)(s32)randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)randomGetRange(1, 0xa);
            cfg.startPosZ = (f32)(s32)randomGetRange(-0x96, 0x96);
        }
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = 0.06f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(4, 4);
        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(0, 0xa) + 0.0002945f;
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
            cfg.startPosX = (f32)(s32)randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)randomGetRange(1, 0xa);
            cfg.startPosZ = (f32)(s32)randomGetRange(-0x96, 0x96);
        }
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(0, 0xa) + 0.0002945f;
        cfg.lifetimeFrames = randomGetRange(0xe6, 0x118);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xc0d;
        break;
    case 0x284:
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(2, 0x14);
        cfg.scale = 0.004445f;
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
            cfg.startPosX = (f32)(s32)randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)randomGetRange(1, 0xa);
            cfg.startPosZ = (f32)(s32)randomGetRange(-0x96, 0x96);
        }
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(2, 4);
        cfg.velocityZ = 0.006f * (f32)(s32)randomGetRange(2, 4);
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0, 0xa) + 0.01245f;
        cfg.lifetimeFrames = randomGetRange(0, 0x32) + 0x32;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0xc0a;
        break;
    case 0x258:
        cfg.velocityX = 0.002f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = 0.002f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.00087f;
        cfg.lifetimeFrames = randomGetRange(0x50, 0x82);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x7b;
        break;
    case 0x289:
        cfg.startPosX = 0.2f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.startPosZ = 0.2f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0x28, 0x3c) + 0.3f;
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x14, 0x8c);
        cfg.behaviorFlags = 0x80400209;
        cfg.linkGroup = 0;
        cfg.textureId = 0x23b;
        break;
    case 0x28a:
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = -4e+01f;
        cfg.scale = 0.05f;
        cfg.initialAlpha = 0x55;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x40);
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0xc9d;
        break;
    case 0x28b:
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0, 0x12c);
        cfg.scale = 0.015f;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100200;
        cfg.textureId = 0x159;
        break;
    case 0x28c:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0, 0xc8);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.velocityX = 0.001f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityZ = 0.001f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = 5e-06f * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x88108;
        cfg.textureId = 0x159;
        break;
    case 0x28d:
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0x5a, 0x64);
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0xa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x500200;
        cfg.textureId = 0x159;
        break;
    case 0x28e:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x3e8, 0x3e8);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0x12c, 0x708);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x3e8, 0x3e8);
        cfg.velocityX = gEffect2ScrollPhaseA * (0.06f * (f32)(s32)randomGetRange(-0x28, 0x28));
        cfg.velocityZ = -gEffect2ScrollPhaseA * (0.06f * (f32)(s32)randomGetRange(-0x28, 0x28));
        cfg.scale = 0.0015f;
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
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x64);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(5, 0x19);
        cfg.lifetimeFrames = 0x230;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)randomGetRange(0xe6, 0x320);
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
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.startPosY = 0.5f;
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x190, 0x190);
        cfg.velocityX = 0.004f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.001f * (f32)(s32)randomGetRange(0x64, 0xc8);
        cfg.velocityZ = 0.004f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(5, 0x19);
        cfg.lifetimeFrames = 0x7d0;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)randomGetRange(0xe6, 0x320);
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
    lbl_803DD348 = lbl_803DD2C4;
    return spawnResult;
}
#undef FILL338



void Effect2_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect2ScrollPhaseA + (step = 0.001f * timeDelta);
    gEffect2ScrollPhaseA = sum;
    if (sum > 1.0f)
    {
        gEffect2ScrollPhaseA = 0.1f;
    }
    sum = gEffect2ScrollPhaseB + step;
    gEffect2ScrollPhaseB = sum;
    if (sum > 1.0f)
    {
        gEffect2ScrollPhaseB = 0.3f;
    }
    gEffect2SinAngleA = gEffect2SinAngleA + framesThisStep * 0x64;
    if (gEffect2SinAngleA > 0x7fff)
    {
        gEffect2SinAngleA = 0;
    }
    gEffect2SinValueA = mathSinf(3.1415927f * (f32)(s16)gEffect2SinAngleA / 32768.0f);
    gEffect2SinAngleB = gEffect2SinAngleB + framesThisStep * 0x32;
    if (gEffect2SinAngleB > 0x7fff)
    {
        gEffect2SinAngleB = 0;
    }
    gEffect2SinValueB = mathSinf(3.1415927f * (f32)(s16)gEffect2SinAngleB / 32768.0f);
}

void Effect2_func03_nop(void)
{
}

void Effect2_release(void)
{
}

void Effect2_initialise(void)
{
}
