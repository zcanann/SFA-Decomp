/*
 * effect5 (DLL 0x1E) - one of the per-effect particle DLLs.
 *
 * Effect5_func04 is the spawn dispatcher: given an effect id (0xC8..0xD7) it
 * fills a PartFxSpawn request - position/velocity/scale jitter from
 * randomGetRange, texture id, lifetime, alpha and behavior/render flag words -
 * then hands it to gExpgfxInterface->spawnEffect. Effect5_func05 advances the
 * global per-frame scroll-phase accumulators (texture u/v scroll and two sine
 * oscillator angles) and is wrapped scheduling/peephole-off to match. The three
 * Effect5_func03_nop / Effect5_release / Effect5_initialise stubs and the
 * projgfx_funcs object descriptor complete the TU.
 */
#include "main/dll/mtxbuildarg_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/modgfx.h"

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

void Effect5_func03_nop(void)
{
}

void Effect5_release(void)
{
}

void Effect5_initialise(void)
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

extern f32 timeDelta;
extern u8 framesThisStep;

extern float mathSinf(float x);

extern f32 lbl_803DB7E8;
extern f32 lbl_803DB7EC;
extern int lbl_803DD360;
extern int lbl_803DD364;
extern f32 lbl_803DD368;
extern f32 lbl_803DD36C;
extern f32 lbl_803DFBE0;
extern f32 lbl_803DFBE4;
extern f32 lbl_803DFBE8;
extern f32 lbl_803DFBF0;
extern f32 lbl_803DFC78;
extern f32 lbl_803DFC7C;

#pragma scheduling off
#pragma peephole off
void Effect5_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB7E8 + (step = lbl_803DFBE0 * timeDelta);
    lbl_803DB7E8 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7E8 = lbl_803DFBE4;
    }
    sum = lbl_803DB7EC + step;
    lbl_803DB7EC = sum;
    if (sum > 1.0f)
    {
        lbl_803DB7EC = lbl_803DFBF0;
    }
    lbl_803DD360 = lbl_803DD360 + framesThisStep * 0x64;
    if (lbl_803DD360 > 0x7fff)
    {
        lbl_803DD360 = 0;
    }
    lbl_803DD36C = mathSinf(lbl_803DFC78 * (f32)(s16)lbl_803DD360 / lbl_803DFC7C);
    lbl_803DD364 = lbl_803DD364 + framesThisStep * 0x32;
    if (lbl_803DD364 > 0x7fff)
    {
        lbl_803DD364 = 0;
    }
    lbl_803DD368 = mathSinf(lbl_803DFC78 * (f32)(s16)lbl_803DD364 / lbl_803DFC7C);
}

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

extern void vecRotateZXY(void* obj, f32* vec);

extern f32 lbl_803DB7E0;
extern f32 lbl_803DB7E4;
extern f32 lbl_803DFBEC;
extern f32 lbl_803DFBF4;
extern f32 lbl_803DFBF8;
extern f32 lbl_803DFBFC;
extern f32 lbl_803DFC00;
extern f32 lbl_803DFC04;
extern f32 lbl_803DFC08;
extern f32 lbl_803DFC0C;
extern f32 lbl_803DFC10;
extern f32 lbl_803DFC14;
extern f32 lbl_803DFC18;
extern f32 lbl_803DFC1C;
extern f32 lbl_803DFC20;
extern f32 lbl_803DFC24;
extern f32 lbl_803DFC28;
extern f32 lbl_803DFC2C;
extern f32 lbl_803DFC30;
extern f32 lbl_803DFC34;
extern f32 lbl_803DFC38;
extern f32 lbl_803DFC3C;
extern f32 lbl_803DFC40;
extern f32 lbl_803DFC44;
extern f32 lbl_803DFC48;
extern f32 lbl_803DFC4C;
extern f32 lbl_803DFC50;
extern f32 lbl_803DFC54;
extern f32 lbl_803DFC58;
extern f32 lbl_803DFC5C;
extern f32 lbl_803DFC60;
extern f32 lbl_803DFC64;
extern f32 lbl_803DFC68;

int Effect5_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    MtxBuildArg es;
    PartFxSpawn cfg;

    lbl_803DB7E0 = lbl_803DB7E0 + lbl_803DFBE0;
    if (lbl_803DB7E0 > 1.0f) lbl_803DB7E0 = lbl_803DFBE4;
    lbl_803DB7E4 = lbl_803DB7E4 + lbl_803DFBEC;
    if (lbl_803DB7E4 > 1.0f) lbl_803DB7E4 = lbl_803DFBF0;
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
    cfg.startPosX = lbl_803DFBF4;
    cfg.startPosY = lbl_803DFBF4;
    cfg.startPosZ = lbl_803DFBF4;
    cfg.velocityX = lbl_803DFBF4;
    cfg.velocityY = lbl_803DFBF4;
    cfg.velocityZ = lbl_803DFBF4;
    cfg.scale = lbl_803DFBF4;
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
        cfg.scale = lbl_803DFBF8 * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x24;
        cfg.initialAlpha = 0x41;
        cfg.behaviorFlags = 0x100111;
        cfg.textureId = 0xc10;
        break;
    case 0xca:
        if (spawnParams == 0) return 0;
        cfg.velocityX = lbl_803DFBFC * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFBFC * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFC00 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        es.a = lbl_803DFBF4;
        es.b = lbl_803DFBF4;
        es.c = lbl_803DFBF4;
        es.w = lbl_803DFBE8;
        es.rz = 0;
        es.ry = 0;
        es.rx = spawnParams->rotX;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DFC04 * (f32)(s32)
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
        cfg.velocityX = lbl_803DFC08 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFC0C * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFC08 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        es.a = lbl_803DFBF4;
        es.b = lbl_803DFBF4;
        es.c = lbl_803DFBF4;
        es.w = lbl_803DFBE8;
        es.rz = 0;
        es.ry = 0;
        es.rx = spawnParams->rotX;
        vecRotateZXY(&es, &cfg.velocityX);
        cfg.scale = lbl_803DFC10 * (f32)(s32)
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
        cfg.startPosY = lbl_803DFC14 * (f32)(s32)
        randomGetRange(1, 2);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityX = lbl_803DFC18 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DFC18 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DFC1C * (f32)(s32)
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
            f32 v = lbl_803DFC20 + cfg.startPosX / lbl_803DFC20;
            cfg.startPosY = v + rnd;
        }
        cfg.startPosZ = lbl_803DFC24 * cfg.startPosX;
        cfg.scale = lbl_803DFC28 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x80080118;
        cfg.textureId = 0x5c;
        break;
    case 0xce:
        cfg.startPosX = lbl_803DFC2C + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFC30 + (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosZ = lbl_803DFC34 + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFC38 * (f32)(s32)
        randomGetRange(0, 0xa);
        cfg.scale = lbl_803DFBEC * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(lbl_803DFC3C + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xcf:
        cfg.startPosX = -(f32)(s32)
        randomGetRange(0, 0xfa);
        {
            f32 rnd = (f32)(s32)randomGetRange(-5, 5);
            f32 v = lbl_803DFC20 + cfg.startPosX / lbl_803DFC20;
            cfg.startPosY = v + rnd;
        }
        cfg.startPosZ = -cfg.startPosX;
        cfg.scale = lbl_803DFC28 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xfa;
        cfg.initialAlpha = 0x7d;
        cfg.behaviorFlags = 0x80080118;
        cfg.textureId = 0x5c;
        break;
    case 0xd0:
        cfg.startPosX = lbl_803DFC40 + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFC30 + (f32)(s32)
        randomGetRange(-8, 8);
        cfg.startPosZ = lbl_803DFC44 + (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFC38 * (f32)(s32)
        randomGetRange(0, 0xa);
        cfg.scale = lbl_803DFBEC * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(lbl_803DFC3C + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xd1:
        cfg.scale = lbl_803DFBEC * (f32)(s32)
        randomGetRange(0x46, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0xf) + 0x14;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x180210;
        cfg.textureId = 0x159;
        break;
    case 0xd2:
        cfg.scale = lbl_803DFBFC;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x400000;
        cfg.textureId = 0x159;
        break;
    case 0xd3:
        cfg.startPosX = -(f32)(s32)
        randomGetRange(0, 0xfa);
        cfg.startPosY = lbl_803DFC48 + (f32)(s32)
        randomGetRange(-5, 5);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-5, 5);
        cfg.velocityZ = lbl_803DFBE4 * (f32)(s32)
        randomGetRange(-5, 5);
        cfg.scale = lbl_803DFC4C * (f32)(s32)
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
        cfg.velocityY = lbl_803DFC50 * (f32)(s32)
        randomGetRange(0, 0xa);
        cfg.scale = lbl_803DFC54 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = (s32)(lbl_803DFC58 + (f32)(s32)randomGetRange(0, 0x14));
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x4c;
        break;
    case 0xd5:
        cfg.scale = lbl_803DFC5C;
        cfg.quadVertex3Pad06 = 0xd6;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80000;
        cfg.textureId = 0x159;
        break;
    case 0xd6:
        cfg.scale = lbl_803DFC5C;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x159;
        break;
    case 0xd7:
        cfg.startPosX = lbl_803DFC60 * (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.startPosY = lbl_803DFC60 * (f32)(s32)
        randomGetRange(-0x32, 0xa);
        cfg.startPosZ = lbl_803DFC60 * (f32)(s32)
        randomGetRange(-0x8c, 0x8c);
        cfg.velocityY = lbl_803DFC64 * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.scale = lbl_803DFC68 * (f32)(s32)
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}
