/*
 * effect5 (DLL 0x1E) - one of the per-effect particle DLLs.
 *
 * Effect5_func04 is the spawn dispatcher: given an effect id (0xC8..0xD7) it
 * fills a PartFxSpawn request - position/velocity/scale jitter from
 * randomGetRange, texture id, lifetime, alpha and behavior/render flag words -
 * then hands it to gExpgfxInterface->spawnEffect. Effect5_func05 advances the
 * global per-frame scroll-phase accumulators (texture u/v scroll and two sine
 * oscillator angles). The three
 * Effect5_func03_nop / Effect5_release / Effect5_initialise stubs and the
 * lbl_803109B8 object descriptor complete the TU.
 */
#include "main/dll/mtxbuildarg_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/game_object.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/modgfx.h"
#include "main/frame_timing.h"

#define PARTFX_STAGE_COUNT 7

typedef struct PartfxEffectState
{
    void* instanceObject;
    void* sourceObject;
    void* auxSequenceBuffer;
    s16 sourceRotX;
    s16 sourceRotY;
    s16 sourceRotZ;
    f32 sourceScale;
    f32 sourcePosX;
    f32 sourcePosY;
    f32 sourcePosZ;
    f32 posStepX;
    f32 posStepY;
    f32 posStepZ;
    ModgfxScaleChannel scaleChannels[2];
    f32 drawPosX;
    f32 drawPosY;
    f32 drawPosZ;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    void* vertexBuffers[3];
    void* colorBuffers[3];
    void* baseVertexBuffer;
    void* baseColorBuffer;
    void* textureResource;
    void* emitterCommands;
    void* auxAllocation;
    u32 flags;
    s32 initialDelayFrames;
    ModgfxAlphaChannel alphaChannels[2];
    f32 blendColorR;
    f32 blendColorG;
    f32 blendColorB;
    f32 blendColorStepR;
    f32 blendColorStepG;
    f32 blendColorStepB;
    f32 renderScale;
    u8 padD8[0xE6 - 0xD8];
    s16 soundHandle;
    u8 padE8[0xEA - 0xE8];
    s16 vertexCount;
    s16 colorVertexCount;
    s16 stageDurations[PARTFX_STAGE_COUNT];
    s16 currentStage;
    s16 stageFrameCountdown;
    u8 pad100[0x106 - 0x100];
    s16 rotOffsetZ;
    s16 rotOffsetY;
    s16 rotOffsetX;
    s16 sequenceId;
    s16 nextStage;
    s16 stageTimer;
    u8 pad112[0x114 - 0x112];
    int word114;
    int word118;
    int word11C;
    s16 vec120;
    s16 vec122;
    s16 vec124;
    s8 byte126;
    u8 pad127[0x12C - 0x127];
    void* inlineData;
    u8 activeVertexBufferIndex;
    u8 textureFrame;
    u8 textureFrameTimer;
    u8 textureFrameStep;
    u8 textureFrameFadeStep;
    s8 sourceYawIndex;
    u8 drawGroupCount;
    u8 drawGroupStride;
    u8 initialStateByte;
    s8 emitterCount;
    u8 releaseRequested;
    char byte13B;
    u8 requestedStage;
    u8 byte13D;
    u8 frameUpdated;
    u8 textureIsBorrowed;
} PartfxEffectState;

STATIC_ASSERT(sizeof(PartfxEffectState) == 0x140);
STATIC_ASSERT(offsetof(PartfxEffectState, vertexBuffers) == 0x78);
STATIC_ASSERT(offsetof(PartfxEffectState, textureResource) == 0x98);
STATIC_ASSERT(offsetof(PartfxEffectState, flags) == 0xA4);
STATIC_ASSERT(offsetof(PartfxEffectState, drawPosX) == 0x60);
STATIC_ASSERT(offsetof(PartfxEffectState, velocityX) == 0x6C);
STATIC_ASSERT(offsetof(PartfxEffectState, alphaChannels) == 0xAC);
STATIC_ASSERT(offsetof(PartfxEffectState, blendColorR) == 0xBC);
STATIC_ASSERT(offsetof(PartfxEffectState, renderScale) == 0xD4);
STATIC_ASSERT(offsetof(PartfxEffectState, vertexCount) == 0xEA);
STATIC_ASSERT(offsetof(PartfxEffectState, colorVertexCount) == 0xEC);
STATIC_ASSERT(offsetof(PartfxEffectState, stageDurations) == 0xEE);
STATIC_ASSERT(offsetof(PartfxEffectState, sequenceId) == 0x10C);
STATIC_ASSERT(offsetof(PartfxEffectState, inlineData) == 0x12C);
STATIC_ASSERT(offsetof(PartfxEffectState, activeVertexBufferIndex) == 0x130);
STATIC_ASSERT(offsetof(PartfxEffectState, emitterCount) == 0x139);
STATIC_ASSERT(offsetof(PartfxEffectState, textureIsBorrowed) == 0x13F);

void Effect5_func03_nop(void);
void Effect5_release(void);
void Effect5_initialise(void);
int Effect5_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs);
void Effect5_func05(void);

void* lbl_803109B8[10] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00050000, Effect5_initialise, Effect5_release, (void*)0x00000000, Effect5_func03_nop, Effect5_func04, Effect5_func05 };

extern float mathSinf(float x);
extern f32 gEffect5AnimProgressC;
extern f32 gEffect5AnimProgressD;
extern int gEffect5SinPhaseA;
extern int gEffect5SinPhaseB;
extern f32 gEffect5SinValueB;
extern f32 gEffect5SinValueA;
extern f32 gEffect5Pi;
extern f32 gEffect5SinPhaseScale;

#pragma scheduling off
#pragma peephole off

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

extern void vecRotateZXY(void* obj, f32* vec);
extern f32 gEffect5AnimProgressA;
extern f32 gEffect5AnimProgressB;

int Effect5_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    MtxBuildArg es;
    PartFxSpawn cfg;

    gEffect5AnimProgressA += 0.001f;
    if (gEffect5AnimProgressA > 1.0f) gEffect5AnimProgressA = 0.1f;
    gEffect5AnimProgressB += 0.0003f;
    if (gEffect5AnimProgressB > 1.0f) gEffect5AnimProgressB = 0.3f;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0)
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
    case 0xc8:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.scale = 0.009f * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x24;
        cfg.initialAlpha = 0x41;
        cfg.behaviorFlags = 0x100111;
        cfg.textureId = 0xc10;
        break;
    case 0xca:
        if (spawnParams == 0) return 0;
        cfg.velocityX = 0.01f * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.01f * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.02f * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        es.a = 0.0f;
        es.b = 0.0f;
        es.c = 0.0f;
        es.w = 1.0f;
        es.rz = 0;
        es.ry = 0;
        es.rx = spawnParams->rotX;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = 0.002f * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x180108;
        cfg.renderFlags = 0x5000000;
        if (spawnParams->unk4 == 0)
        {
            cfg.textureId = 0x2b;
        }
        else if (spawnParams->unk4 == 1)
        {
            cfg.textureId = 0x1a1;
        }
        else if (spawnParams->unk4 == 2)
        {
            cfg.textureId = 0xc10;
            cfg.renderFlags = cfg.renderFlags | 0x800;
        }
        else
        {
            cfg.textureId = 0x2b;
        }
        break;
    case 0xcb:
        if (spawnParams == 0) return 0;
        cfg.velocityX = 0.025f * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.045f * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.025f * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        es.a = 0.0f;
        es.b = 0.0f;
        es.c = 0.0f;
        es.w = 1.0f;
        es.rz = 0;
        es.ry = 0;
        es.rx = spawnParams->rotX;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = 0.0001f * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x1080100;
        cfg.renderFlags = 0x5000000;
        if (spawnParams->unk4 == 0)
        {
            cfg.textureId = 0x2b;
        }
        else if (spawnParams->unk4 == 1)
        {
            cfg.textureId = 0x1a1;
        }
        else if (spawnParams->unk4 == 2)
        {
            cfg.textureId = 0xc10;
            cfg.renderFlags = cfg.renderFlags | 0x800;
        }
        else
        {
            cfg.textureId = 0x2b;
        }
        break;
    case 0xcc:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.startPosY = 180.0f * (f32)(s32)
        randomGetRange(1, 2);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityX = 0.04f * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.04f * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = 0.0004f * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80108;
        cfg.textureId = 0x5c;
        break;
    case 0xcd:
        cfg.startPosX = (f32)(s32)
        randomGetRange(0, 0xfa);
        {
            f32 rnd = (f32)(s32)randomGetRange(-5, 5);
            f32 v = 20.0f + cfg.startPosX / 20.0f;
            cfg.startPosY = v + rnd;
        }
        cfg.startPosZ = 0.7f * cfg.startPosX;
        cfg.scale = 0.00004f * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x80080118;
        cfg.textureId = 0x5c;
        break;
    case 0xce:
        cfg.startPosX = 290.0f + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = 40.0f + (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosZ = 175.0f + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.03f * (f32)(s32)
        randomGetRange(0, 0xa);
        cfg.scale = 0.0003f * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(80.0f + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xcf:
        cfg.startPosX = -(f32)(s32)
        randomGetRange(0, 0xfa);
        {
            f32 rnd = (f32)(s32)randomGetRange(-5, 5);
            f32 v = 20.0f + cfg.startPosX / 20.0f;
            cfg.startPosY = v + rnd;
        }
        cfg.startPosZ = -cfg.startPosX;
        cfg.scale = 0.00004f * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x80080118;
        cfg.textureId = 0x5c;
        break;
    case 0xd0:
        cfg.startPosX = -305.0f + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = 40.0f + (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosZ = 300.0f + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.03f * (f32)(s32)
        randomGetRange(0, 0xa);
        cfg.scale = 0.0003f * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(80.0f + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xd1:
        cfg.scale = 0.0003f * (f32)(s32)
        randomGetRange(0x46, 0x50);
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
        cfg.startPosX = -(f32)(s32)
        randomGetRange(0, 0xfa);
        cfg.startPosY = 10.0f + (f32)(s32)
        randomGetRange(-5, 5);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-5, 5);
        cfg.velocityZ = 0.1f * (f32)(s32)
        randomGetRange(-5, 5);
        cfg.scale = 0.00006f * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xa0;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x180108;
        cfg.textureId = 0x5c;
        break;
    case 0xd4:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0xa, 0x14);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x1c);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.05f * (f32)(s32)
        randomGetRange(0, 0xa);
        cfg.scale = 0.0013f * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(110.0f + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xd5:
        cfg.scale = 0.004f;
        cfg.quadVertex3Pad06 = 0xd6;
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
        cfg.startPosX = 0.08f * (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.startPosY = 0.08f * (f32)(s32)
        randomGetRange(-0x32, 0xa);
        cfg.startPosZ = 0.08f * (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.velocityY = 0.0035f * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.scale = 0.0015f * (f32)(s32)
        randomGetRange(1, 0xa);
        cfg.lifetimeFrames = 0x8c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80180100;
        cfg.textureId = 0x5f;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0)
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

void Effect5_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect5AnimProgressC + (step = 0.001f * timeDelta);
    gEffect5AnimProgressC = sum;
    if (sum > 1.0f)
    {
        gEffect5AnimProgressC = 0.1f;
    }
    sum = gEffect5AnimProgressD + step;
    gEffect5AnimProgressD = sum;
    if (sum > 1.0f)
    {
        gEffect5AnimProgressD = 0.3f;
    }
    gEffect5SinPhaseA = gEffect5SinPhaseA + framesThisStep * 0x64;
    if (gEffect5SinPhaseA > 0x7fff)
    {
        gEffect5SinPhaseA = 0;
    }
    gEffect5SinValueA = mathSinf(gEffect5Pi * (f32)(s16)gEffect5SinPhaseA / gEffect5SinPhaseScale);
    gEffect5SinPhaseB = gEffect5SinPhaseB + framesThisStep * 0x32;
    if (gEffect5SinPhaseB > 0x7fff)
    {
        gEffect5SinPhaseB = 0;
    }
    gEffect5SinValueB = mathSinf(gEffect5Pi * (f32)(s16)gEffect5SinPhaseB / gEffect5SinPhaseScale);
}

void Effect5_func03_nop(void)
{
}

void Effect5_release(void)
{
}

void Effect5_initialise(void)
{
}
