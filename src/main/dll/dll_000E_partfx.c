/*
 * partfx (DLL 0x000E) - the particle-effect spawn dispatcher.
 *
 * partfx_spawnObject is the central entry point: it maps an effect id to a
 * fully-populated Expgfx spawn request (cfg) and submits it through
 * gExpgfxInterface->spawnEffect. The big effect-id ranges at the top are
 * delegated to one of 20 lazily-acquired particle resource modules
 * (gPartfxResourceModuleNN, Resource_Acquire ids 0x1a through 0x2d); each delegation
 * arms a 2000-frame keep-alive in gPartfxResourceTimeouts[NN] and forwards the
 * call to the module's vtable slot 8. partfx_updateFrameState ticks the global
 * scroll/sin phases and decays those 20 timeouts, releasing a module once its
 * timeout expires; partfx_release frees them all. partfx_initialise zeroes the
 * timeout table and cached-module count.
 */
#include "main/dll/partfxspawn_struct.h"
#include "main/debug.h"
#include "main/dll/mtxbuildarg_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/resource.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "stdlib.h"
#include "main/frame_timing.h"
#include "main/dll/dll_000E_partfx.h"

extern u8 lbl_80380209[];
extern char sModgfxAlphaDebugFormat[];

f32 gPartfxSpawnAnimPhase0 = 0.1f;
f32 gPartfxSpawnAnimPhase1 = 0.3f;
f32 gPartfxFrameAnimPhase0 = 0.1f;
f32 gPartfxFrameAnimPhase1 = 0.3f;

f32 gPartfxOscSine0;
f32 gPartfxOscSine1;
s32 gPartfxOscAngle1;
s32 gPartfxOscAngle0;
void* gPartfxResourceModule19;
void* gPartfxResourceModule18;
void* gPartfxResourceModule17;
void* gPartfxResourceModule15;
void* gPartfxResourceModule14;
void* gPartfxResourceModule13;
void* gPartfxResourceModule12;
void* gPartfxResourceModule11;
void* gPartfxResourceModule10;
void* gPartfxResourceModule09;
void* gPartfxResourceModule08;
void* gPartfxResourceModule07;
void* gPartfxResourceModule06;
void* gPartfxResourceModule16;
void* gPartfxResourceModule05;
void* gPartfxResourceModule04;
void* gPartfxResourceModule03;
void* gPartfxResourceModule02;
void* gPartfxResourceModule01;
void* gPartfxResourceModule00;
u32 lbl_803DD2C4;
u8 gPartfxCachedResourceCount;

s16 gPartfxResourceTimeouts[20];
PartFxSpawnParams gPartfxDefaultSpawnParams;

int partfx_spawnObject(s16* sourceObj, int effectValue, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                       u8 modelId, f32* extraArgs)
{
    PartFxSpawnContext state;
    s16 i;
    int variant;
    MtxBuildArg rot;
    PartFxSpawn cfg;

    state.effectId = effectValue;

    if ((899 < state.effectId && state.effectId < 0x3b5) || 0x5dc < state.effectId && state.effectId < 0x641)
    {
        gPartfxResourceTimeouts[0] = 2000;
        if (gPartfxResourceModule00 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule00 = Resource_Acquire(0x1a, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule00)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                               modelId, extraArgs);
    }
    if (0x257 < state.effectId && state.effectId < 0x2bc)
    {
        gPartfxResourceTimeouts[1] = 2000;
        if (gPartfxResourceModule01 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule01 = Resource_Acquire(0x1b, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule01)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                               modelId, extraArgs);
    }
    if (0x1f3 < state.effectId && state.effectId < 0x258)
    {
        gPartfxResourceTimeouts[2] = 2000;
        if (gPartfxResourceModule02 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule02 = Resource_Acquire(0x1c, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule02)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x18f < state.effectId && state.effectId < 0x1f4)
    {
        gPartfxResourceTimeouts[3] = 2000;
        if (gPartfxResourceModule03 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule03 = Resource_Acquire(0x1d, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule03)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0xc7 < state.effectId && state.effectId < 0x12c)
    {
        gPartfxResourceTimeouts[4] = 2000;
        if (gPartfxResourceModule04 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule04 = Resource_Acquire(0x1e, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule04)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x419 < state.effectId && state.effectId < 0x44c)
    {
        gPartfxResourceTimeouts[5] = 2000;
        if (gPartfxResourceModule05 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule05 = Resource_Acquire(0x1f, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule05)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x739 < state.effectId && state.effectId < 0x76c)
    {
        gPartfxResourceTimeouts[16] = 2000;
        if (gPartfxResourceModule16 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule16 = Resource_Acquire(0x2a, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule16)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (state.effectId - 0x84U <= 1 || 0x89 < state.effectId && state.effectId < 200)
    {
        gPartfxResourceTimeouts[6] = 2000;
        if (gPartfxResourceModule06 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule06 = Resource_Acquire(0x20, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule06)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x3b5 < state.effectId && state.effectId < 0x3de)
    {
        gPartfxResourceTimeouts[8] = 2000;
        if (gPartfxResourceModule08 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule08 = Resource_Acquire(0x22, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule08)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x351 < state.effectId && state.effectId < 0x384)
    {
        gPartfxResourceTimeouts[7] = 2000;
        if (gPartfxResourceModule07 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule07 = Resource_Acquire(0x21, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule07)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x329 < state.effectId && state.effectId < 0x351)
    {
        gPartfxResourceTimeouts[9] = 2000;
        if (gPartfxResourceModule09 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule09 = Resource_Acquire(0x23, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule09)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x12b < state.effectId && state.effectId < 0x190)
    {
        gPartfxResourceTimeouts[10] = 2000;
        if (gPartfxResourceModule10 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule10 = Resource_Acquire(0x24, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule10)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x47d < state.effectId && state.effectId < 0x4b0)
    {
        gPartfxResourceTimeouts[11] = 2000;
        if (gPartfxResourceModule11 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule11 = Resource_Acquire(0x25, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule11)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x4af < state.effectId && state.effectId < 0x4e2)
    {
        gPartfxResourceTimeouts[12] = 2000;
        if (gPartfxResourceModule12 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule12 = Resource_Acquire(0x27, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule12)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (state.effectId >= 0x3e8 && state.effectId <= 0x419)
    {
        gPartfxResourceTimeouts[13] = 2000;
        if (gPartfxResourceModule13 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule13 = Resource_Acquire(0x28, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule13)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (0x44b < state.effectId && state.effectId < 0x47e)
    {
        gPartfxResourceTimeouts[14] = 2000;
        if (gPartfxResourceModule14 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule14 = Resource_Acquire(0x26, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule14)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (state.effectId >= 0x6d7 && state.effectId <= 0x707)
    {
        gPartfxResourceTimeouts[15] = 2000;
        if (gPartfxResourceModule15 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule15 = Resource_Acquire(0x29, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule15)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (state.effectId >= 0x708 && state.effectId <= 0x739)
    {
        gPartfxResourceTimeouts[17] = 2000;
        if (gPartfxResourceModule17 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule17 = Resource_Acquire(0x2b, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule17)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (state.effectId >= 0x76c && state.effectId <= 0x79d)
    {
        gPartfxResourceTimeouts[18] = 2000;
        if (gPartfxResourceModule18 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule18 = Resource_Acquire(0x2c, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule18)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    if (state.effectId >= 0x79e && state.effectId <= 0x833)
    {
        gPartfxResourceTimeouts[19] = 2000;
        if (gPartfxResourceModule19 == NULL)
        {
            gPartfxCachedResourceCount += 1;
            gPartfxResourceModule19 = Resource_Acquire(0x2d, 2);
        }
        return ((PartFxResource*)gPartfxResourceModule19)->vtable->spawnObject(sourceObj, state.effectId, spawnParams, spawnFlags,
                                                                   modelId, extraArgs);
    }
    gPartfxSpawnAnimPhase0 += 0.001f;
    if (gPartfxSpawnAnimPhase0 > 1.0f)
    {
        gPartfxSpawnAnimPhase0 = 0.1f;
    }
    gPartfxSpawnAnimPhase1 += 0.0003f;
    if (gPartfxSpawnAnimPhase1 > 1.0f)
    {
        gPartfxSpawnAnimPhase1 = 0.3f;
    }
    if (sourceObj == NULL)
    {
        return -1;
    }
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.sourcePosY = spawnParams->posX;
        cfg.sourcePosZ = spawnParams->posY;
        cfg.sourcePosW = spawnParams->posZ;
        cfg.sourcePosX = spawnParams->scale;
        cfg.sourceVecZ = spawnParams->rotZ;
        cfg.sourceVecY = spawnParams->rotY;
        cfg.sourceVecX = spawnParams->rotX;
        cfg.modelIdByte = modelId;
    }
    variant = '\0';
    cfg.behaviorFlags = 0x0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = state.effectId;
    cfg.attachedSource = sourceObj;
    *(state.startPos = cfg.startPos) = 0.0f;
    cfg.startPosY = 0.0f;
    cfg.startPosZ = 0.0f;
    cfg.velocityX = 0.0f;
    cfg.velocityY = 0.0f;
    cfg.velocityZ = 0.0f;
    cfg.scale = 0.0f;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = 0xffffffff;
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
    switch (state.effectId)
    {
    case 0x5e:

        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x80180000;
        cfg.textureId = 0x60;
        if (extraArgs != NULL)
        {
            cfg.colorWord0 = ((u16*)extraArgs)[3];
            cfg.colorWord1 = ((u16*)extraArgs)[4];
            cfg.colorWord2 = ((u16*)extraArgs)[5];
            cfg.overrideColor0 = (u32)((u16*)extraArgs)[0];
            cfg.overrideColor1 = (u32)((u16*)extraArgs)[1];
            cfg.overrideColor2 = (u32)((u16*)extraArgs)[2];
        }
        cfg.renderFlags = 0x8400820;
        break;
    case 0x5f:
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 4;
        cfg.behaviorFlags = 0x80000;
        cfg.textureId = 0x33;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.renderFlags = 0x8000820;
        break;
    case 0x60:

        *state.startPos = (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosY = (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.velocityX = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0x32, 100);
        cfg.behaviorFlags = 0x80180202;
        cfg.textureId = 0x60;
        if (extraArgs != NULL)
        {
            cfg.colorWord0 = ((u16*)extraArgs)[0];
            cfg.colorWord1 = ((u16*)extraArgs)[1];
            cfg.colorWord2 = ((u16*)extraArgs)[2];
            cfg.lifetimeFrames = (u32)((u16*)extraArgs)[3];
        }
        else
        {
            cfg.colorWord0 = 0x2000;
            cfg.colorWord1 = 0x2000;
            cfg.colorWord2 = 0x2000;
            cfg.lifetimeFrames = 0x78;
        }
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.initialAlpha = 0x7f;
        cfg.renderFlags = 0x4080020;
        break;
    case 0x68c:

        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x5f;
        cfg.behaviorFlags = 0x1180200;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = randomGetRange(0x8000, 0xffff);
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = randomGetRange(0, 0x8000);
        cfg.overrideColor2 = randomGetRange(0, 0xffff);
        cfg.renderFlags = 0x20;
        break;
    case 0x68d:
        *state.startPos = (f32)(s32)randomGetRange(0xfffffff9, 7);
        cfg.startPosY = (f32)(s32)randomGetRange(0xfffffff9, 7);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffff9, 7);
        cfg.velocityX = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x5a;
        cfg.initialAlpha = 0x96;
        cfg.behaviorFlags = 0x1080200;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = randomGetRange(0, 0xffff);
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.renderFlags = 0x20;
        break;
    case 0x68e:
        cfg.scale = 0.06f;
        cfg.lifetimeFrames = 0x5f;
        cfg.behaviorFlags = 0x180208;
        cfg.textureId = 0x62;
        cfg.colorWord0 = randomGetRange(0x8000, 0xffff);
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = randomGetRange(0, 0xffff);
        cfg.overrideColor1 = randomGetRange(0, 0x8000);
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        break;
    case 0x68f:

        *state.startPos = (f32)(s32)randomGetRange(0xfffffff9, 7);
        cfg.startPosY = (f32)(s32)randomGetRange(0xfffffff9, 7);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffff9, 7);
        cfg.velocityX = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 100;
        cfg.initialAlpha = 0x96;
        cfg.behaviorFlags = 0x1080200;
        cfg.textureId = 0x62;
        cfg.colorWord0 = randomGetRange(0, 0xffff);
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        break;
    case 0x690:
        *state.startPos = (f32)(s32)randomGetRange(0xfffffff9, 7);
        cfg.startPosY = (f32)(s32)randomGetRange(0xfffffff9, 7);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffff9, 7);
        cfg.velocityX = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = 0.075f * (f32)(s32)randomGetRange(0x14, 0x32);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0x96;
        cfg.behaviorFlags = 0x80208;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.renderFlags = 0x20;
        break;
    case 0x68b:
        if (spawnParams != NULL)
        {
            cfg.startPosX = spawnParams->posX - ((GameObject*)sourceObj)->anim.worldPosX;
            cfg.startPosZ = spawnParams->posZ - ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            *state.startPos = (f32)(s32)randomGetRange(0xfffffff9, 7);
            cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffff9, 7);
        }
        cfg.startPosY = 2.0f;
        cfg.velocityX = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.velocityY = 0.025f * (f32)(s32)randomGetRange(0, 0x32);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        {
            f32 scale;
            if (spawnParams != NULL)
            {
                scale = spawnParams->scale;
            }
            else
            {
                scale = 0.01f;
            }
            cfg.scale = scale;
        }
        cfg.lifetimeFrames = 0x32;
        cfg.initialAlpha = 0x96;
        cfg.behaviorFlags = 0x80080200;
        cfg.textureId = 0x62;
        cfg.colorWord0 = randomGetRange(0, 0xffff);
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x1000020;
        break;
    case 0x556:
        cfg.startPosY = 30.0f;
        cfg.scale = 0.0092f;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400200;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        /* fall through */
    case 0x55c:
        cfg.startPosY = 30.0f;
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400100;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        /* fall through */
    case 0x55d:
        cfg.startPosY = 30.0f;
        cfg.scale = 0.015f;
        cfg.lifetimeFrames = 0x2d;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100210;
        cfg.renderFlags = 0x200;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        /* fall through */
    case 0x557:
        cfg.startPosY = 30.0f;
        if (extraArgs != NULL)
        {
            cfg.velocityY = 0.2f;
        }
        else
        {
            cfg.velocityY = -0.2f;
        }
        cfg.scale = 0.0042f;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400200;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        /* fall through */
    case 0x558:
        cfg.startPosY = 30.0f;
        if (extraArgs != NULL)
        {
            cfg.velocityY = -0.2f;
        }
        else
        {
            cfg.velocityY = 0.2f;
        }
        cfg.scale = 0.0042f;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400200;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        /* fall through */
    case 0x559:
        cfg.startPosY = 30.0f;
        if (extraArgs != NULL)
        {
            cfg.velocityY = 0.2f;
        }
        else
        {
            cfg.velocityY = -0.2f;
        }
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400100;
        cfg.textureId = 0xe4;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        /* fall through */
    case 0x55b:
        cfg.startPosY = 30.0f;
        if (extraArgs != NULL)
        {
            cfg.velocityY = -0.2f;
        }
        else
        {
            cfg.velocityY = 0.2f;
        }
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0xaf;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x500010;
        cfg.renderFlags = 0x400100;
        cfg.textureId = 0xe4;
        break;
    case 0x55e:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.startPosY = spawnParams->posY + (f32)(s32)randomGetRange(0xfffffffa, 6);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.scale = 0.0015f;
        cfg.lifetimeFrames = 0x12;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x400010;
        cfg.renderFlags = 0x400008;
        cfg.textureId = 0xe4;
        break;
    case 0x551:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.startPosZ = -26.0f;
        cfg.scale = 0.06f;
        cfg.lifetimeFrames = 0x23;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x91;
        break;
    case 0x552:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.startPosZ = -26.0f;
        cfg.scale = 0.06f;
        cfg.lifetimeFrames = 0x23;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0xa100210;
        cfg.textureId = 0x91;
        break;
    case 0x554:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.startPosZ = -26.0f;
        cfg.scale = 0.16f;
        cfg.lifetimeFrames = 0x37;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0xa100210;
        cfg.textureId = 0x73;
        break;
    case 0x553:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = 0.06f * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.velocityZ = 0.02f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosZ = -26.0f;
        rot.a = 0.0f;
        rot.b = 0.0f;
        rot.c = 0.0f;
        rot.w = 1.0f;
        rot.rz = 0;
        rot.ry = 0;
        rot.rx = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY(&rot.rotation.x, state.startPos);
        cfg.scale = 0.0032f;
        cfg.lifetimeFrames = 0x91;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x3000010;
        cfg.renderFlags = 0x2600000;
        cfg.textureId = 0xe4;
        break;
    case 0x549:

        *state.startPos = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosY = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(10, 0x14);
        cfg.lifetimeFrames = randomGetRange(100, 0x96);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480110;
        if (extraArgs != NULL)
        {
            cfg.behaviorFlags |= 0x40000000LL;
        }
        cfg.textureId = 0x85;
        break;
    case 0x54a:
        *state.startPos = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosY = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(10, 0x14);
        cfg.lifetimeFrames = randomGetRange(100, 0x96);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480110;
        if (extraArgs != NULL)
        {
            cfg.behaviorFlags |= 0x40000000LL;
        }
        cfg.textureId = 0x84;
        break;
    case 0x54b:
        *state.startPos = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosY = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(10, 0x14);
        cfg.lifetimeFrames = randomGetRange(100, 0x96);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480110;
        if (extraArgs != NULL)
        {
            cfg.behaviorFlags |= 0x40000000LL;
        }
        cfg.textureId = 0xc0f;
        break;
    case 0x54c:

        *state.startPos = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosY = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosZ = 0.2f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(10, 0x14);
        cfg.lifetimeFrames = randomGetRange(100, 0x96);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480110;
        if (extraArgs != NULL)
        {
            cfg.behaviorFlags |= 0x40000000LL;
        }
        cfg.textureId = 0x157;
        break;
    case 0x54d:
        if (extraArgs != NULL)
        {
            variant = *(u8*)extraArgs;
        }
        else
        {
            variant = '\0';
        }
        if (variant == '\x01')
        {
            cfg.scale = 0.0001f * (f32)(s32)randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x202;
        }
        else if (variant == '\x02')
        {
            cfg.scale = 0.00015f * (f32)(s32)randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x102;
        }
        else
        {
            cfg.scale = 0.0006f * (f32)(s32)randomGetRange(0x12, 0x14);
            cfg.behaviorFlags = 0xc0800;
            cfg.renderFlags = 2;
        }
        cfg.lifetimeFrames = 1;
        cfg.initialAlpha = 0x60;
        cfg.textureId = 0x85;
        break;
    case 0x54e:
        if (extraArgs != NULL)
        {
            variant = *(u8*)extraArgs;
        }
        if (variant == '\x01')
        {
            cfg.scale = 0.0001f * (f32)(s32)randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x202;
        }
        else if (variant == '\x02')
        {
            cfg.scale = 0.00015f * (f32)(s32)randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x102;
        }
        else
        {
            cfg.scale = 0.0006f * (f32)(s32)randomGetRange(0x12, 0x14);
            cfg.behaviorFlags = 0xc0800;
            cfg.renderFlags = 2;
        }
        cfg.lifetimeFrames = 1;
        cfg.initialAlpha = 0x60;
        cfg.textureId = 0x84;
        break;
    case 0x54f:

        if (extraArgs != NULL)
        {
            variant = *(u8*)extraArgs;
        }
        if (variant == '\x01')
        {
            cfg.scale = 0.0001f * (f32)(s32)randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x202;
        }
        else if (variant == '\x02')
        {
            cfg.scale = 0.00015f * (f32)(s32)randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x102;
        }
        else
        {
            cfg.scale = 0.0006f * (f32)(s32)randomGetRange(0x12, 0x14);
            cfg.behaviorFlags = 0xc0800;
            cfg.renderFlags = 2;
        }
        cfg.lifetimeFrames = 1;
        cfg.initialAlpha = 0x60;
        cfg.textureId = 0xc0f;
        break;
    case 0x550:
        if (extraArgs != NULL)
        {
            variant = *(u8*)extraArgs;
        }
        if (variant == '\x01')
        {
            cfg.scale = 0.0001f * (f32)(s32)randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x202;
        }
        else if (variant == '\x02')
        {
            cfg.scale = 0.00015f * (f32)(s32)randomGetRange(10, 0x14);
            cfg.behaviorFlags = 0x4c0800;
            cfg.renderFlags = 0x102;
        }
        else
        {
            cfg.scale = 0.0006f * (f32)(s32)randomGetRange(0x12, 0x14);
            cfg.behaviorFlags = 0xc0800;
            cfg.renderFlags = 2;
        }
        cfg.lifetimeFrames = 1;
        cfg.initialAlpha = 0x60;
        cfg.textureId = 0x157;
        break;
    case 0x545:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.scale = 0.5f * spawnParams->scale;
        cfg.lifetimeFrames = 4;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 2;
        cfg.textureId = 0x527;
        cfg.initialAlpha = 0x69;
        break;
    case 0x546:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.scale = 0.65f * spawnParams->scale;
        cfg.lifetimeFrames = 4;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2000002;
        cfg.textureId = 0xc0e;
        cfg.initialAlpha = 0x73;
        break;
    case 0x547:
        cfg.startPosX = 60.0f;
        cfg.startPosY = (f32)(s32)randomGetRange(0xffffffb0, 0x50);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.scale = 0.0065f;
        cfg.lifetimeFrames = 300;
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0xc0e;
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x548;
        cfg.sourceVecX = 200;
        cfg.sourceVecY = 0;
        cfg.sourceVecX = 0;
        cfg.sourcePosY = 100.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x28;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags |= 0x20000LL;
        break;
    case 0x548:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.scale = 0.0055f;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x80201;
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0xc0e;
        cfg.initialAlpha = 0xff;
        break;
    case 0x52b:
    case 0x52c:
    case 0x52d:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams != NULL)
        {
            *state.startPos = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            *state.startPos -= ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
        }
        if ((int)randomGetRange(0, 0x28) == 0)
        {
            cfg.scale = 0.0003f;
        }
        else
        {
            cfg.scale = 0.0015f;
        }
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        cfg.textureId = state.effectId + -0x3d5;
        break;
    case 0x52f:
    case 0x530:
    case 0x531:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams != NULL)
        {
            *state.startPos = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            *state.startPos = *state.startPos - ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            cfg.velocityZ = 0.3f;
        }
        cfg.scale = 0.0015f;
        cfg.lifetimeFrames = 100;
        break;
    case 0x53c:

        if (extraArgs != NULL)
        {
            int alpha = cfg.initialAlpha = (int)(255.0f * (1.0f - *extraArgs));
            logPrintf(sModgfxAlphaDebugFormat, alpha);
        }
        cfg.scale = 4.0f;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x2000002;
        cfg.lifetimeFrames = 0;
        cfg.textureId = 0xe4;
        break;
    case 0x53d:
        cfg.startPosZ = 0.0f;
        cfg.initialAlpha = 0x69;
        cfg.scale = 0.03f;
        cfg.behaviorFlags = 0x80014;
        cfg.renderFlags = 0x22;
        cfg.lifetimeFrames = 0;
        cfg.textureId = 0x4fe;
        cfg.colorWord0 = 0xb1df;
        cfg.colorWord1 = 0xb1df;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        cfg.startPosZ = -200.0f;
        cfg.initialAlpha = 0x69;
        cfg.scale = 0.036f;
        cfg.behaviorFlags = 0x80014;
        cfg.renderFlags = 0x22;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xb1df;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.lifetimeFrames = 0;
        cfg.textureId = 0x4ff;
        (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        cfg.startPosZ = -400.0f;
        cfg.initialAlpha = 0x69;
        cfg.scale = 0.042f;
        cfg.behaviorFlags = 0x80014;
        cfg.renderFlags = 0x22;
        cfg.colorWord0 = 0xb1df;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        cfg.lifetimeFrames = 0;
        cfg.textureId = 0x4fe;
        break;
    case 0x53e:
        cfg.startPosX = -20.0f;
        cfg.scale = 0.2f;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 2;
        cfg.lifetimeFrames = 1;
        cfg.textureId = 100;
        break;
    case 0x53f:

        cfg.initialAlpha = 0x37;
        cfg.scale = 0.1f;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 2;
        cfg.lifetimeFrames = 1;
        cfg.textureId = 0x156;
        break;
    case 0x532:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = 0.002f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityZ = -0.026f * (f32)(s32)randomGetRange(0x14, 0x1e);
        rot.a = 0.0f;
        rot.b = 0.0f;
        rot.c = 0.0f;
        rot.w = 1.0f;
        rot.rz = sourceObj[2];
        rot.ry = sourceObj[1];
        rot.rx = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY(&rot.rotation.x, cfg.velocity);
        cfg.initialAlpha = 0xcd;
        cfg.behaviorFlags = 0x100110;
        cfg.scale = 0.00003f * (f32)(s32)randomGetRange(0x96, 200);
        cfg.lifetimeFrames = 0x28;
        cfg.textureId = 0x89;
        break;
    case 0x533:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = 0.002f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(8, 10);
        cfg.velocityZ = -0.005f * (f32)(s32)randomGetRange(10, 0x1e);
        rot.a = 0.0f;
        rot.b = 0.0f;
        rot.c = 0.0f;
        rot.w = 1.0f;
        rot.rz = sourceObj[2];
        rot.ry = sourceObj[1];
        rot.rx = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY(&rot.rotation.x, cfg.velocity);
        cfg.scale = 0.0003f * (f32)(s32)randomGetRange(8, 0x14);
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
    case 0x535:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityZ = -0.02f * (f32)(s32)randomGetRange(0x14, 0x1e);
        rot.a = 0.0f;
        rot.b = 0.0f;
        rot.c = 0.0f;
        rot.w = 1.0f;
        rot.rz = sourceObj[2];
        rot.ry = sourceObj[1];
        rot.rx = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY(&rot.rotation.x, cfg.velocity);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.000006f * (f32)(s32)randomGetRange(0x96, 200);
        cfg.behaviorFlags = 0x2000110;
        cfg.renderFlags = 0x2200000;
        cfg.lifetimeFrames = 0x19;
        cfg.textureId = 0x24;
        break;
    case 0x534:

        cfg.startPosY = 10.0f;
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(0xfffffff1, 0xf);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0xfffffff1, 0xf);
        cfg.velocityZ = -1.0f;
        rot.a = 0.0f;
        rot.b = 0.0f;
        rot.c = 0.0f;
        rot.w = 1.0f;
        rot.rz = sourceObj[2];
        rot.ry = sourceObj[1];
        rot.rx = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY(&rot.rotation.x, cfg.velocity);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.00004f * (f32)(s32)randomGetRange(10, 0x14);
        cfg.behaviorFlags = 0x2000110;
        cfg.renderFlags = 0x200000;
        cfg.lifetimeFrames = 0x19;
        cfg.textureId = 0x156;
        break;
    case 0x52a:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.01465f;
        cfg.lifetimeFrames = 10;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80440202;
        cfg.textureId = 0x4f9;
        cfg.renderFlags = 0x2000000;
        break;
    case 0x51f:

        cfg.startPosY = 5.0f;
        cfg.scale = 0.015565f;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x88140200;
        cfg.textureId = 0x159;
        break;
    case 0x51e:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.005565f;
        cfg.lifetimeFrames = 10;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80440202;
        cfg.textureId = 0x156;
        break;
    case 0x51c:
        *state.startPos = 0.1f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosY = 7.0f;
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0x19, 0x23);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(100, 0x96);
        cfg.lifetimeFrames = randomGetRange(0x5a, 0x78);
        cfg.behaviorFlags = 0x80100100;
        cfg.textureId = 0x60;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = randomGetRange(0, 10) * 0xacf;
        cfg.overrideColor1 = cfg.overrideColor0;
        cfg.overrideColor2 = cfg.overrideColor0;
        cfg.renderFlags = 0x20;
        break;
    case 0x51b: {
        f32 startZ;

        cfg.scale = 0.002f * (f32)(s32)randomGetRange(0, 0xf) + 0.03f;
        *state.startPos = 0.1f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0xffffffce, 0x32) + 10.0f;
        startZ = 0.1f * (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.startPosZ = startZ;
        cfg.velocityX = *state.startPos / 25.0f;
        cfg.velocityY = cfg.startPosY / 25.0f;
        cfg.velocityZ = startZ / 25.0f;
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100110;
        cfg.textureId = 0xe4;
        break;
    }
    case 0x2bc:
    case 0x2bd:
    case 0x2be:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams != NULL)
        {
            *state.startPos = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            *state.startPos -= ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
        }
        cfg.scale = 0.0003148f;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        cfg.renderFlags = 0x100;
        cfg.textureId = (s16)(state.effectId - 0x28c);
        break;
    case 0x4b:

        cfg.velocityX = 0.0f;
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.0f;
        cfg.scale = 0.0022f;
        cfg.lifetimeFrames = 0x14;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0xdf;
        break;
    case 0x3c:

        cfg.startPosY = 22.0f;
        cfg.scale = 0.003f * (f32)(s32)randomGetRange(1, 10) + 0.03f;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x28;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x6100214;
        cfg.textureId = 0xc79;
        break;
    case 0x329:
        *state.startPos = 0.1f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.startPosY = 50.0f;
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.velocityX = 0.001f * (f32)(s32)randomGetRange(100, 200);
        cfg.velocityY = 0.001f * (f32)(s32)randomGetRange(100, 200);
        cfg.velocityZ = 0.001f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.behaviorFlags = 0x1081010;
        if ((int)randomGetRange(0, 3) == 0)
        {
            cfg.scale = 0.000065f * (f32)(s32)randomGetRange(0x28, 0x50);
            cfg.initialAlpha = 0x8c;
        }
        else
        {
            cfg.scale = 0.00135f * (f32)(s32)randomGetRange(0x28, 0x50);
            cfg.initialAlpha = 10;
            cfg.behaviorFlags |= 0x100000LL;
        }
        if ((int)randomGetRange(0, 10) == 0)
        {
            spawnFlags ^= 4LL;
            spawnFlags |= 1;
        }
        cfg.lifetimeFrames = 0xdc;
        cfg.colorWord0 = 0xb1df;
        cfg.colorWord1 = 0x8acf;
        cfg.colorWord2 = 0x63bf;
        cfg.overrideColor0 = 0x3caf;
        cfg.overrideColor1 = 0x30f7;
        cfg.overrideColor2 = 10000;
        cfg.renderFlags = 0x20;
        cfg.renderFlags |= 0x100000LL;
        cfg.textureId = 0x60;
        break;
    case 0x3b9:

        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(0xffffffec, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(0xffffffec, 0x14);
        *state.startPos = (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xffffffce, 0x32);
        cfg.startPosY = (f32)(s32)randomGetRange(0x1e, 100);
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x4b0;
        cfg.initialAlpha = 200;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x62;
        break;
    case 0x3b8:
        *state.startPos = 0.25f * (f32)(s32)(0x3c - randomGetRange(0, 0x78));
        cfg.startPosY = 10.0f;
        cfg.startPosZ = 0.25f * (f32)(s32)(0x3cU - randomGetRange(0, 0x78));
        cfg.velocityX = 0.005f * (f32)(s32)(0x28U - randomGetRange(0, 0x50));
        cfg.velocityZ = 0.005f * (f32)(s32)(0x28 - randomGetRange(0, 0x50));
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xb4;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400201;
        cfg.textureId = 0x47;
        break;
    case 0x1:
        cfg.startPosY = 80.0f;
        cfg.velocityX = 0.002f * gPartfxFrameAnimPhase0 * (f32)(s32)randomGetRange(0xfffffff1, 0xf);
        cfg.velocityY = 0.003f * (f32)(s32)randomGetRange(5, 0x14);
        cfg.velocityZ = 0.002f * gPartfxFrameAnimPhase0 * (f32)(s32)randomGetRange(0xfffffff1, 0xf);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0, 10) + 0.003f;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0xf;
        cfg.behaviorFlags = 0x588008;
        cfg.renderFlags = 0x10000;
        cfg.textureId = 0x23b;
        cfg.quadVertex3Pad06 = 4;
        break;
    case 0x4:
        cfg.velocityY = 0.004f * (f32)(s32)randomGetRange(10, 0x14);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0, 10) + 0.006f;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xcd;
        cfg.linkGroup = 6;
        cfg.behaviorFlags = 0xa100200;
        cfg.textureId = 0x47;
        break;
    case 0x3:
        if (spawnParams == NULL)
        {
            return -1;
        }
        cfg.startPosY = 0.3f * (f32)(s32)randomGetRange(0x14, 0x3c);
        cfg.scale = 0.15f;
        cfg.lifetimeFrames = 0x23;
        cfg.initialAlpha = 0x96;
        cfg.linkGroup = 0x14;
        cfg.behaviorFlags = 0x9100110;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = spawnParams->unk4;
        break;
    case 0x5:

        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = 0.18f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosY = 0.18f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosZ = 0.18f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityY = 0.025f * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.scale = 0.00035f * (f32)(s32)randomGetRange(100, 0x96);
        cfg.lifetimeFrames = randomGetRange(0x32, 0x50);
        cfg.linkGroup = randomGetRange(10, 0x1e);
        cfg.behaviorFlags = 0x100218;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = spawnParams->unk4;
        if (cfg.textureId == 0x4c)
        {
            cfg.colorWord0 = 0x6400;
            cfg.colorWord1 = 0x3200;
            cfg.colorWord2 = 0xa000;
            cfg.overrideColor0 = 500;
            cfg.overrideColor1 = 0;
            cfg.overrideColor2 = 1000;
            cfg.renderFlags |= 0x20;
        }
        break;
    case 0x7:
        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = 0.18f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosY = 0.18f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosZ = 0.18f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityX = 0.035f * (f32)(s32)randomGetRange(0xffffffd8, 0x28);
        cfg.velocityY = 0.035f * (f32)(s32)randomGetRange(10, 0x28);
        cfg.velocityZ = 0.035f * (f32)(s32)randomGetRange(0xffffffd8, 0x28);
        cfg.scale = 0.002f;
        cfg.lifetimeFrames = randomGetRange(0x14, 0x32);
        cfg.linkGroup = 0x1e;
        cfg.behaviorFlags = 0x511;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = spawnParams->unk4;
        break;
    case 0x7b:
        cfg.startPosY = 120.0f + (f32)(s32)randomGetRange(0, 10);
        cfg.velocityY = -0.67f;
        cfg.scale = 0.2f;
        cfg.lifetimeFrames = 0x50;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100208;
        cfg.textureId = 0x91;
        break;
    case 0x7f:

        cfg.scale = 0.032f;
        cfg.lifetimeFrames = 100;
        cfg.initialAlpha = 0x37;
        cfg.behaviorFlags = 0x400100;
        switch (cfg.sourceVecZ)
        {
        case 0:
            cfg.textureId = 0x15e;
            break;
        case 1:
            cfg.textureId = 0x15f;
            break;
        case 2:
            cfg.textureId = 0x15d;
            break;
        default:
            cfg.textureId = 0x15e;
            break;
        }
        cfg.sourceVecZ = 0;
        break;
    case 0x7c:

        cfg.velocityX = 0.03 * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.velocityZ = 0.03 * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.scale = 0.0016f;
        cfg.lifetimeFrames = 300;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x41001c;
        cfg.textureId = 0xc13;
        break;
    case 0x7d:
        cfg.startPosY = 0.0f;
        cfg.scale = 0.002f;
        cfg.lifetimeFrames = 0x14;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x32;
        cfg.behaviorFlags = 0x400100;
        cfg.textureId = 0xc13;
        break;
    case 0x7e:
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x400100;
        cfg.velocityX = 0.06f * (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.velocityZ = 0.06f * (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.velocityY = 0.006f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.00013f * (f32)(s32)randomGetRange(0x28, 0x50);
        switch (cfg.sourceVecZ)
        {
        case 0:
            cfg.textureId = 0xdd;
            break;
        case 1:
            cfg.textureId = 0x160;
            break;
        case 2:
            cfg.textureId = 0xdf;
            break;
        default:
            cfg.textureId = 0xdf;
            break;
        }
        cfg.sourceVecZ = 0;
        break;
    case 0x3e7:

        cfg.lifetimeFrames = 300;
        cfg.behaviorFlags = 0x80400500;
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.velocityZ = 0.03f * (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.00013f * (f32)(s32)randomGetRange(0x28, 0x50);
        switch (cfg.sourceVecZ)
        {
        case 0:
            cfg.textureId = 0xdd;
            break;
        case 1:
            cfg.textureId = 0x160;
            break;
        case 2:
            cfg.textureId = 0xdf;
            break;
        default:
            cfg.textureId = 0xdf;
            break;
        }
        cfg.sourceVecZ = 0;
        break;
    case 0x80:
        cfg.scale = 0.004f;
        cfg.lifetimeFrames = 2;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x32;
        cfg.behaviorFlags = 0x400110;
        cfg.textureId = 0xdf;
        break;
    case 0x81:

        *state.startPos = (f32)(s32)randomGetRange(0xffffff1a, 0xe6);
        cfg.startPosY = (f32)(s32)randomGetRange(0xffffffce, 0xfa);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xffffff1a, 0xe6);
        cfg.scale = 0.0025f;
        cfg.lifetimeFrames = 200;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000108;
        cfg.textureId = 0x165;
        break;
    case 0x82:
        *state.startPos = (f32)(s32)randomGetRange(0xffffff60, 0xa0);
        cfg.startPosY = (f32)(s32)randomGetRange(0xffffffce, 0xfa);
        *state.startPos = (f32)(s32)randomGetRange(0xffffff60, 0xa0);
        cfg.scale = 0.0025f;
        cfg.lifetimeFrames = 200;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000108;
        cfg.textureId = 0x166;
        break;
    case 0x83:

        *state.startPos = (f32)(s32)randomGetRange(0xffffff60, 0xa0);
        cfg.startPosY = (f32)(s32)randomGetRange(0xffffffce, 0xfa);
        *state.startPos = (f32)(s32)randomGetRange(0xffffff60, 0xa0);
        cfg.scale = 0.0025f;
        cfg.lifetimeFrames = 200;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000108;
        cfg.textureId = 0x167;
        break;
    case 0x71:
        *state.startPos = (f32)(s32)randomGetRange(0xfffffffe, 2);
        cfg.startPosY = 20.0f;
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffff0, 0x10);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(0xfffffffd, 0xffffffff);
        cfg.scale = 0.00025f * (f32)(s32)randomGetRange(1, 3);
        cfg.lifetimeFrames = 100;
        cfg.initialAlpha = 0x7d;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x80000100;
        cfg.textureId = 0x2c;
        break;
    case 0x6d:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = spawnParams->scale;
        cfg.lifetimeFrames = 1;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0x19;
        if (spawnParams->unk4 != 0)
        {
            cfg.initialAlpha = 0x7d;
        }
        cfg.behaviorFlags = 0xc0012;
        cfg.textureId = 0x77;
        break;
    case 0x6a:
    {
        f32 positionScale = 1.0f;

        *state.startPos = positionScale * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.startPosY = 0.0f;
        cfg.startPosZ = positionScale * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.velocityX = 0.0f;
        cfg.velocityY = 0.15f * (f32)(s32)randomGetRange(1, 3);
        cfg.velocityZ = 0.0f;
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x78;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x5f;
        break;
    }
    case 0x66:
        cfg.linkGroup = 0x20;
        cfg.scale = 0.016f;
        cfg.lifetimeFrames = 0x50;
        cfg.quadVertex3Pad06 = 0x67;
        cfg.behaviorFlags = 0x400000;
        cfg.textureId = 0x156;
        break;
    case 0x67:

        cfg.scale = 0.016f;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = randomGetRange(0, 2) + 0x156;
        break;
    case 0x68:
        cfg.velocityX = 0.032f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.velocityY = 0.032f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.velocityZ = 0.032f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.scale = 0.00188f;
        cfg.lifetimeFrames = 0x69;
        cfg.behaviorFlags = 0x480200;
        cfg.textureId = 0x156;
        break;
    case 0x65:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0;
        cfg.scale = 0.005565f;
        cfg.lifetimeFrames = 100;
        cfg.initialAlpha = 0xff;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x30;
        break;
    case 0x72:

        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(1, 4);
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x3c);
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x4000802;
        cfg.linkGroup = 0;
        cfg.textureId = 0xde;
        cfg.initialAlpha = randomGetRange(0x96, 0xfa);
        break;
    case 0x73:
        cfg.scale = 0.00097f * (f32)(s32)randomGetRange(4, 5);
        cfg.scale *= 0.5f;
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x28);
        cfg.behaviorFlags = 0x0;
        cfg.renderFlags = 2;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdf;
        break;
    case 0x55:
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x78;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x20;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x56;
        break;
    case 0x59:

        cfg.velocityX = 2.0f - (f32)(s32)randomGetRange(0, 4);
        cfg.velocityY = 2.0f - (f32)(s32)randomGetRange(0, 4);
        cfg.velocityZ = 2.0f - (f32)(s32)randomGetRange(0, 4);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(1, 0x28);
        cfg.lifetimeFrames = 0x28;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x2b;
        break;
    case 0x51:

        cfg.scale = 0.001f;
        cfg.lifetimeFrames = 10;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x2b;
        break;
    case 0x50:
        cfg.scale = 0.004f;
        cfg.lifetimeFrames = 10;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x2b;
        break;
    case 0x4d:
        cfg.startPosY = 2000.0f;
        cfg.scale = 0.04f;
        cfg.lifetimeFrames = 400;
        cfg.linkGroup = 0;
        cfg.quadVertex3Pad06 = 0x4e;
        cfg.behaviorFlags = 0x20100;
        cfg.textureId = 0xdf;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        cfg.sourceVecZ = 100 - randomGetRange(0, 200);
        cfg.sourceVecY = 100 - randomGetRange(0, 200);
        cfg.sourceVecX = 100 - randomGetRange(0, 200);
        break;
    case 0x4e:

        cfg.velocityX = 0.6f * (f32)(s32)(1 - randomGetRange(0, 2));
        cfg.velocityZ = 0.6f * (f32)(s32)(1U - randomGetRange(0, 2));
        cfg.scale = 0.008f;
        cfg.lifetimeFrames = 0x4b;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x7b;
        break;
    case 0x4a:
        cfg.startPosY = 40.0f;
        cfg.scale = 0.012f;
        cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.quadVertex3Pad06 = 0x4b;
        cfg.behaviorFlags = 0x70000;
        cfg.textureId = randomGetRange(0, 3) + 0xdd;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 30.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        cfg.sourceVecZ = 0;
        cfg.sourceVecY = 500 - randomGetRange(0, 1000);
        cfg.sourceVecX = 500 - randomGetRange(0, 1000);
        break;
    case 0x49:
        cfg.startPosY = 20.0f;
        cfg.scale = 0.5f;
        cfg.lifetimeFrames = 0xe;
        cfg.initialAlpha = 0;
        cfg.behaviorFlags = 0x110210;
        cfg.textureId = 0x31;
        break;
    case 0x47:
        *state.startPos = 2.0f - (f32)(s32)randomGetRange(0, 4);
        cfg.startPosY = 2.0f - (f32)(s32)randomGetRange(0, 4);
        cfg.startPosZ = 2.0f - (f32)(s32)randomGetRange(0, 4);
        cfg.scale = 0.015f;
        cfg.lifetimeFrames = randomGetRange(4, 0xe);
        cfg.behaviorFlags = 0x110100;
        cfg.textureId = 0xc22;
        break;
    case 0x42:

        *state.startPos = 2.0f - (f32)(s32)randomGetRange(0, 4);
        cfg.startPosY = 2.0f - (f32)(s32)randomGetRange(0, 4);
        cfg.startPosZ = 2.0f - (f32)(s32)randomGetRange(0, 4);
        cfg.scale = 0.002f;
        cfg.lifetimeFrames = 1;
        cfg.behaviorFlags = 0x70800;
        cfg.textureId = randomGetRange(0, 1) + 0xdd;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        cfg.sourceVecZ = 500 - randomGetRange(0, 1000);
        cfg.sourceVecY = 500 - randomGetRange(0, 1000);
        cfg.sourceVecX = 500 - randomGetRange(0, 1000);
        break;
    case 0x40:

        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x28);
        cfg.velocityX = 0.4f * (f32)(s32)(1U - randomGetRange(0, 2));
        cfg.velocityY = 0.4f * (f32)(s32)randomGetRange(1, 3);
        cfg.velocityZ = 0.4f * (f32)(s32)(1 - randomGetRange(0, 2));
        cfg.scale = 0.004f;
        cfg.lifetimeFrames = 0x96;
        cfg.behaviorFlags = 0x108;
        cfg.textureId = 0x5c;
        break;
    case 0x41:
        for (i = 0; i < 0x1e; i++)
        {
            state.effectId = (int)(u32)state.effectId;
            cfg.startPosY = -10.0f;
            cfg.velocityX = 1.6f * (f32)(s32)(2 - randomGetRange(0, 4));
            cfg.velocityY = 0.4f * (f32)(s32)randomGetRange(1, 2);
            cfg.velocityZ = 1.6f * (f32)(s32)(2U - randomGetRange(0, 4));
            cfg.scale = 0.003f;
            cfg.lifetimeFrames = 0x3c;
            cfg.behaviorFlags = 0x108;
            cfg.textureId = 0x5c;
            if ((cfg.behaviorFlags & 1) != 0)
            {
                if (cfg.attachedSource != NULL)
                {
                    cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.localPosX;
                    cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.localPosY;
                    cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.localPosZ;
                }
                else
                {
                    cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
                    cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
                    cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
                }
            }
            (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        }
        break;
    case 0x3d:
    case 0x3e:
    case 0x3f:
    case 0x43:
    case 0x44:
    case 0x4f:
        cfg.behaviorFlags = 0x20100100;
        cfg.lifetimeFrames = 400;
        if (state.effectId == 0x3d)
        {
            *state.startPos = 10.0f - (f32)(s32)randomGetRange(0, 0x14);
            cfg.startPosY = 35.0f;
            cfg.startPosZ = 10.0f - (f32)(s32)randomGetRange(0, 0x14);
            cfg.scale = 0.06f * (f32)(s32)randomGetRange(1, 3);
            cfg.renderFlags |= 0x1000000LL;
        }
        else if (state.effectId == 0x3e)
        {
            *state.startPos = 10.0f - (f32)(s32)randomGetRange(0, 0x14);
            cfg.startPosY = 220.0f;
            cfg.startPosZ = 10.0f - (f32)(s32)randomGetRange(0, 0x14);
            cfg.scale = 0.04f * (f32)(s32)randomGetRange(1, 3);
            cfg.renderFlags |= 0x1000000LL;
        }
        else if (state.effectId == 0x3f)
        {
            *state.startPos = 0.0f;
            cfg.startPosY = -18.0f;
            cfg.startPosZ = 0.0f;
            cfg.lifetimeFrames = 100;
            cfg.scale = 0.04f * (f32)(s32)randomGetRange(1, 3);
            cfg.renderFlags |= 0x1000000LL;
        }
        else if (state.effectId == 0x43)
        {
            *state.startPos = 110.0f;
            cfg.startPosY = 60.0f;
            cfg.startPosZ = -20.0f + (f32)(s32)randomGetRange(0, 0x78);
            cfg.scale = 0.01f * (f32)(s32)randomGetRange(1, 8);
            cfg.behaviorFlags = cfg.behaviorFlags | 8;
            cfg.renderFlags |= 0x1000000LL;
        }
        else if (state.effectId == 0x44)
        {
            *state.startPos = 110.0f;
            cfg.startPosY = 85.0f;
            cfg.startPosZ = (f32)(s32)randomGetRange(0, 0x78);
            cfg.velocityY = -0.26f;
            cfg.scale = 0.01f * (f32)(s32)randomGetRange(1, 8);
            cfg.renderFlags |= 0x1000000LL;
        }
        cfg.linkGroup = 0x20;
        cfg.textureId = 0x5f;
        cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
        if ((cfg.behaviorFlags & 1) != 0)
        {
            if (cfg.attachedSource != NULL)
            {
                *state.startPos = *state.startPos + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
            else
            {
                *state.startPos = *state.startPos + cfg.sourcePosY;
                cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
                cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
            }
        }
        if (state.effectId == 0x3e || state.effectId == 0x3f)
        {
            cfg.behaviorFlags |= 0x8000000LL;
        }
        break;
    case 0x48:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.startPosY = 0.0f;
        cfg.velocityY = 0.2f * (f32)(s32)randomGetRange(1, 10);
        rot.a = 0.0f;
        rot.b = 0.0f;
        rot.c = 0.0f;
        rot.w = 0.5f;
        rot.rz = 2000 - randomGetRange(0, 4000);
        rot.ry = 2000 - randomGetRange(0, 4000);
        rot.rx = 2000 - randomGetRange(0, 4000);
        vecRotateZXY(&rot.rotation.x, cfg.velocity);
        cfg.scale = 0.0036f;
        cfg.lifetimeFrames = 0x50;
        cfg.linkGroup = 8;
        cfg.behaviorFlags = 0x100;
        cfg.textureId = 0xdd;
        break;
    case 0x38:
        srand(0x4233d);
        for (i = 0; i < 0x28; i++)
        {
            state.effectId = (int)(u32)state.effectId;
            cfg.startPosY = 35.0f;
            cfg.velocityX = 0.01f * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
            cfg.velocityZ = 0.01f * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
            cfg.scale = 0.0025f;
            cfg.lifetimeFrames = (s32)(33.0f * (f32)(s32)randomGetRange(1, 4));
            cfg.behaviorFlags = 0x100011;
            cfg.textureId = 0x30;
            if (cfg.behaviorFlags & 1)
            {
                if (cfg.attachedSource != NULL)
                {
                    *state.startPos += ((GameObject*)cfg.attachedSource)->anim.localPosX;
                    cfg.startPosY += + ((GameObject*)cfg.attachedSource)->anim.localPosY;
                    cfg.startPosZ += ((GameObject*)cfg.attachedSource)->anim.localPosZ;
                }
                else
                {
                    *state.startPos += cfg.sourcePosY;
                    cfg.startPosY += + cfg.sourcePosZ;
                    cfg.startPosZ += + cfg.sourcePosW;
                }
            }
            (*gExpgfxInterface)->spawnEffect(&cfg, 0, state.effectId, 0);
        }
        break;
    case 0x35:
        *state.startPos = 0.14f * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
        cfg.startPosY = 44.0f;
        cfg.startPosZ = 0.14f * (f32)(s32)(0x1eU - randomGetRange(0, 0x3c));
        cfg.velocityY = 0.0045f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.00002f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400001;
        cfg.textureId = 0x47;
        break;
    case 0x3a:

        *state.startPos = 0.14f * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
        cfg.startPosY = 10.0f;
        cfg.startPosZ = 0.14f * (f32)(s32)(0x1eU - randomGetRange(0, 0x3c));
        cfg.velocityY = 0.0045f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.00002f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xb4;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400200;
        cfg.textureId = 0x47;
        break;
    case 0x3b:
        *state.startPos = 0.04f * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
        cfg.startPosY = 20.0f;
        cfg.startPosZ = 0.04f * (f32)(s32)(0x1eU - randomGetRange(0, 0x3c));
        cfg.velocityY = 0.0045f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.00002f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400201;
        cfg.textureId = 0x47;
        break;
    case 0x53:
        *state.startPos = 0.14f * (f32)(s32)(0x1e - randomGetRange(0, 0x3c));
        cfg.startPosZ = 0.14f * (f32)(s32)(0x1eU - randomGetRange(0, 0x3c));
        cfg.velocityY = 0.0015f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.00002f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0xd2;
        cfg.behaviorFlags = 0x80000201;
        cfg.textureId = randomGetRange(0, 3) + 0xdd;
        break;
    case 0x2e:

        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100210;
        cfg.textureId = 0x5e;
        break;
    case 0x78:
        cfg.startPosY = (f32)(s32)randomGetRange(0, 100);
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x30;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100210;
        cfg.textureId = 0x5e;
        break;
    case 0x3e6:
        *state.startPos = (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.velocityY = 0.07f * (f32)(s32)randomGetRange(4, 10);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x15e;
        cfg.quadVertex3Pad06 = 0x85;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80400201;
        cfg.textureId = 0xdf;
        break;
    case 0x77:
        *state.startPos = (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x28);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.velocityX = 0.0025f * (f32)(s32)randomGetRange(0xffffffd8, 0x28);
        cfg.velocityY = 0.0045f * (f32)(s32)randomGetRange(0, 0x50);
        cfg.velocityZ = 0.0025f * (f32)(s32)randomGetRange(0xffffffd8, 0x28);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0x96;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x400101;
        cfg.textureId = 0xdf;
        break;
    case 0x7a:
        *state.startPos = (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.startPosY = (f32)(s32)randomGetRange(0, 0x23);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffffc, 4);
        cfg.velocityX = 0.0025f * (f32)(s32)randomGetRange(0xffffffd8, 0x28);
        cfg.velocityZ = 0.0025f * (f32)(s32)randomGetRange(0xffffffd8, 0x28);
        cfg.velocityY = 0.0025f * (f32)(s32)randomGetRange(0, 0x50);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0;
        cfg.behaviorFlags = 0xc80404;
        cfg.textureId = 0xdf;
        break;
    case 0x76:

        cfg.scale = 0.0125f * (f32)(s32)randomGetRange(1, 8);
        cfg.lifetimeFrames = randomGetRange(0, 0x32) + 0x26;
        cfg.initialAlpha = 0xff;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.behaviorFlags = 0x6100110;
        cfg.textureId = 0x159;
        break;
    case 0x2f:
        cfg.scale = 0.05f;
        cfg.lifetimeFrames = 0x32;
        cfg.linkGroup = 0x20;
        cfg.behaviorFlags = 0x400010;
        cfg.textureId = 0x71;
        break;
    case 0x34:

        cfg.scale = 0.05f;
        cfg.lifetimeFrames = 0x1e;
        cfg.linkGroup = 0x20;
        cfg.behaviorFlags = 0x400210;
        cfg.textureId = 0x71;
        break;
    case 0x30:
        cfg.scale = 1.0f;
        cfg.lifetimeFrames = 0x14;
        cfg.behaviorFlags = 0x400010;
        cfg.textureId = 0x7c;
        break;
    case 0x39:
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.startPosZ = -400.0f;
        }
        else
        {
            cfg.startPosZ = 200.0f;
        }
        cfg.scale = 0.55f * (f32)(s32)randomGetRange(1, 4);
        cfg.lifetimeFrames = randomGetRange(0, 0x18) + 0x18;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100;
        cfg.textureId = 0x33;
        break;
    case 0x79:

        if ((int)randomGetRange(0, 1) != 0)
        {
            *state.startPos = -18.0f;
        }
        else
        {
            *state.startPos = 18.0f;
        }
        cfg.startPosY = (f32)(s32)randomGetRange(10, 0x3c);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffffd, 3);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(1, 0x14);
        cfg.scale = 0.006f * (f32)(s32)randomGetRange(1, 7);
        cfg.lifetimeFrames = randomGetRange(0, 0xf) + 0xf;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x100100;
        cfg.textureId = 0x156;
        break;
    case 0x75:
        cfg.scale = 0.4f;
        cfg.lifetimeFrames = 0x62;
        cfg.initialAlpha = 0xff;
        cfg.textureSetupFlags = 0xa9;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x8100210;
        cfg.textureId = 0x159;
        break;
    case 0x32:
        cfg.scale = 0.035f;
        cfg.lifetimeFrames = 0x96;
        cfg.behaviorFlags = 0x400012;
        cfg.textureId = 0x7c;
        break;
    case 0x33:
        cfg.startPosY = 35.0f;
        cfg.scale = 0.008f;
        cfg.lifetimeFrames = 0x55;
        cfg.behaviorFlags = 0x400012;
        cfg.textureId = 0x7c;
        break;
    case 0x69:
        cfg.scale = 0.12f;
        cfg.lifetimeFrames = 0x44;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x60;
        break;
    case 0x2:

        *state.startPos = 0.4f * (f32)(s32)randomGetRange(0xffffffec, 0x14);
        cfg.startPosY = 0.4f * (f32)(s32)randomGetRange(0xffffffec, 0x14);
        cfg.startPosZ = 0.4f * (f32)(s32)randomGetRange(0xffffffec, 0x14);
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0, 0x1e) + 0.08f;
        cfg.lifetimeFrames = randomGetRange(0, 8) + 8;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100100;
        cfg.textureId = 0x33;
        break;
    case 0x2a:
        *state.startPos = 0.1f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(0xffffffe2, 0x1e);
        cfg.scale = 0.0003f * (f32)(s32)randomGetRange(0, 10) + 0.008f;
        cfg.lifetimeFrames = randomGetRange(0x14, 0x32);
        cfg.initialAlpha = 0x9b;
        cfg.linkGroup = 0xe;
        cfg.behaviorFlags = 0x100110;
        if (extraArgs != NULL)
        {
            cfg.textureId = 0x78;
        }
        else
        {
            cfg.textureId = 0x88;
        }
        break;
    case 0x37:

        cfg.scale = 0.025f;
        cfg.lifetimeFrames = 0x14;
        cfg.textureSetupFlags = 0x9a;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x87;
        break;
    case 0x2b: {
        f32 rotX;
        f32 rotY;
        f32 rotZ;

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.velocityX = 0.05f;
        rotX = (f32)(s32)randomGetRange(0, 0xfffe);
        rotY = (f32)(s32)randomGetRange(0, 0xfffe);
        rotZ = (f32)(s32)randomGetRange(0, 0xfffe);
        rot.a = 0.0f;
        rot.b = 0.0f;
        rot.c = 0.0f;
        rot.w = 1.0f;
        rot.rz = rotZ;
        rot.ry = rotY;
        rot.rx = rotX;
        vecRotateZXY(&rot.rotation.x, cfg.velocity);
        cfg.scale = 0.0005f;
        cfg.lifetimeFrames = 0x32;
        cfg.textureSetupFlags = 0;
        cfg.behaviorFlags = 0x100;
        cfg.textureId = 0x30;
        break;
    }
    case 0x2c:
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 10;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80211;
        cfg.textureId = 0x3ff;
        break;
    case 0x28:

        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x46;
        cfg.behaviorFlags = 0xb100200;
        cfg.textureId = 0x74;
        break;
    case 0x31:

        cfg.scale = 0.033f;
        cfg.lifetimeFrames = 0x46;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0xb100200;
        cfg.textureId = 0x74;
        break;
    case 0x2d:
        cfg.startPosY = 35.0f;
        cfg.velocityX = 0.01f * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
        cfg.velocityZ = 0.01f * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.scale = 0.0025f;
        cfg.lifetimeFrames = (s32)(33.0f * (f32)(s32)randomGetRange(1, 4));
        cfg.behaviorFlags = 0x100000;
        cfg.textureId = 0x30;
        break;
    case 0x25:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams == NULL)
        {
            return -1;
        }
        *state.startPos = spawnParams->posX + (f32)(s32)randomGetRange(0, 6);
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ + (f32)(s32)randomGetRange(0, 6);
        cfg.velocityY = 0.012f * (f32)(s32)randomGetRange(0, 10);
        cfg.scale = 0.003f * (f32)(s32)randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x24;
        cfg.initialAlpha = 0x41;
        cfg.behaviorFlags = 0x100112;
        cfg.textureId = 0x61;
        break;
    case 0x36:
        if (extraArgs == NULL)
        {
            return -1;
        }
        cfg.startPosZ = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosX = 0.0f;
        cfg.scale = 0.002f;
        cfg.lifetimeFrames = 0x20;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x20;
        cfg.behaviorFlags = 0x1100201;
        cfg.textureId = 0x249;
        break;
    case 0x26:
        *state.startPos = (f32)(s32)randomGetRange(0xffffffff, 1);
        if (extraArgs != NULL)
        {
            *state.startPos = *state.startPos + extraArgs[1];
        }
        cfg.startPosY = 0.0f;
        cfg.startPosZ = (f32)(s32)randomGetRange(0xffffffff, 1);
        cfg.velocityY = 0.05f;
        cfg.scale = 0.005f;
        if (extraArgs != NULL)
        {
            cfg.lifetimeFrames = (s32)*extraArgs;
        }
        else
        {
            cfg.lifetimeFrames = 0x78;
        }
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80100201;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 99;
        rot.a = 0.0f;
        rot.b = 0.0f;
        rot.c = 0.0f;
        rot.w = 1.0f;
        rot.rz = 0;
        rot.ry = 0;
        rot.rx = ((GameObject*)sourceObj)->anim.rotX;
        vecRotateZXY(&rot.rotation.x, state.startPos);
        break;
    case 0xc:
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x8a;
        cfg.behaviorFlags = 0x10000;
        cfg.textureId = 0x30;
        break;
    case 0xd:

        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x8a;
        cfg.behaviorFlags = 0x10000;
        cfg.textureId = 0x30;
        break;
    case 0xe:
        cfg.startPosY = 20.0f;
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x8a;
        cfg.behaviorFlags = 0x10002;
        cfg.textureId = 0x30;
        break;
    case 0x0:

        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 6;
        cfg.textureSetupFlags = 0;
        cfg.behaviorFlags = 0x10;
        cfg.textureId = 0x87;
        break;
    case 0xf:

        cfg.startPosX = 8.0f;
        cfg.startPosY = 40.0f;
        cfg.startPosZ = 5.0f;
        cfg.velocityX = 0.025f * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
        cfg.velocityZ = 0.025f * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = (s32)(33.0f * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x110214;
        cfg.textureId = 0x30;
        break;
    case 0x11:
        cfg.velocityX = 0.025f * (f32)(s32)(0x50 - randomGetRange(0, 0xa0));
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(0, 0x50);
        cfg.velocityZ = 0.025f * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = (s32)(33.0f * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x1110214;
        cfg.textureId = 0x33;
        break;
    case 0x19:

        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        cfg.scale = 0.001f;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x211;
        cfg.textureId = 0x30;
        break;
    case 0x1a:
        cfg.velocityX = 0.02f * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0, 0x3c);
        cfg.velocityZ = 0.02f * (f32)(s32)(10U - randomGetRange(0, 0x14));
        cfg.scale = 0.0005f * (f32)(s32)randomGetRange(0, 4);
        cfg.lifetimeFrames = (s32)(14.0f * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x1000211;
        cfg.textureId = 0x30;
        break;
    case 0x1b:

        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0, 0x3c);
        cfg.scale = 0.0005f * (f32)(s32)randomGetRange(0, 4);
        cfg.lifetimeFrames = (s32)(78.0f * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.linkGroup = 5;
        cfg.behaviorFlags = 0x1000211;
        cfg.textureId = 0x30;
        break;
    case 0x20:
        cfg.startPosY = 50.0f;
        cfg.scale = 0.008f;
        cfg.lifetimeFrames = 200;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x12;
        cfg.textureId = 0x22d;
        break;
    case 0x21:
        *state.startPos = (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.startPosZ = (f32)(s32)(10U - randomGetRange(0, 0x14));
        cfg.velocityX = 0.6f;
        cfg.velocityY = 3.0f;
        cfg.velocityZ = 0.6f;
        cfg.scale = 0.008f;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x201;
        cfg.textureId = 0x321;
        break;
    case 0x22:

        cfg.startPosZ = 30.0f;
        cfg.scale = 0.001f;
        cfg.lifetimeFrames = 0x178e;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x14;
        cfg.textureId = 0x30;
        break;
    case 0x23:
        cfg.startPosY = 10.0f;
        cfg.scale = 0.019f;
        cfg.lifetimeFrames = 0x69;
        cfg.behaviorFlags = 0x400010;
        cfg.textureId = 0x4b;
        break;
    case 0x24:
        cfg.scale = 0.019f;
        cfg.lifetimeFrames = 0x5f;
        cfg.behaviorFlags = 0x400212;
        cfg.textureId = 0x4b;
        break;
    case 0x1c:
        *state.startPos = (f32)(s32)randomGetRange(0xffffff38, 200);
        cfg.startPosY = 300.0f;
        cfg.startPosZ = (f32)(s32)randomGetRange(0xffffff38, 200);
        cfg.velocityX = 0.06f * (f32)(s32)(10U - randomGetRange(0, 0x14));
        cfg.velocityZ = 0.06f * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.velocityY = 0.08f * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.scale = 0.0011f;
        cfg.lifetimeFrames = 0x104;
        cfg.behaviorFlags = 0x1000202;
        cfg.quadVertex3Pad06 = 0x1e;
        *state.startPos = 0.0f;
        cfg.startPosY = 100.0f;
        cfg.startPosZ = 0.0f;
        cfg.velocityZ = 0.06f * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.scale = 0.0025f;
        cfg.lifetimeFrames = 0xa0;
        cfg.behaviorFlags = 0x1000204;
        cfg.behaviorFlags |= 0x10000000LL;
        cfg.textureId = 0x151;
        break;
    case 0x74:

        *state.startPos = (f32)(s32)randomGetRange(0xffffffb0, 0x50);
        cfg.startPosY = 0.0f;
        cfg.startPosZ = (f32)(s32)randomGetRange(0xffffffb0, 0x50);
        cfg.velocityY = 0.1f * (f32)(s32)randomGetRange(1, 4);
        cfg.scale = 0.0022f;
        cfg.lifetimeFrames = 0x140;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1000204;
        cfg.textureId = 0x151;
        break;
    case 0x1d:

        cfg.startPosY = 48.0f;
        cfg.startPosZ = -110.0f;
        cfg.velocityX = 0.08f * (f32)(s32)(10 - randomGetRange(0, 0x14));
        cfg.velocityY = 0.08f * (f32)(s32)(10U - randomGetRange(0, 0x14));
        cfg.scale = 0.0088f;
        cfg.lifetimeFrames = 0x78;
        cfg.behaviorFlags = 0x204;
        cfg.textureId = 0x1f0;
        break;
    case 0x1e:
        cfg.scale = 0.003f * (f32)(s32)randomGetRange(1, 4);
        cfg.lifetimeFrames = 0x5a;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x56;
        cfg.linkGroup = 0;
        break;
    case 0x1f:

        cfg.scale = 0.02f * (f32)(s32)randomGetRange(2, 4);
        cfg.lifetimeFrames = 200;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x56;
        break;
    case 0x54:

        *state.startPos = (f32)(s32)(5 - randomGetRange(0, 10));
        cfg.startPosZ = (f32)(s32)(5U - randomGetRange(0, 10));
        cfg.scale = 0.004f * (f32)(s32)randomGetRange(2, 0xc);
        cfg.lifetimeFrames = 0x78;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x56;
        break;
    case 0x27:
        cfg.startPosY = 10.0f;
        cfg.scale = 0.04f * (f32)(s32)randomGetRange(1, 2);
        cfg.lifetimeFrames = 200;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x6b;
        break;
    case 0x13:
        cfg.scale = 2.5f;
        cfg.lifetimeFrames = 0xd05;
        cfg.initialAlpha = 0;
        cfg.behaviorFlags = 0x11;
        cfg.textureId = 0x30;
        break;
    case 0x14:

        cfg.scale = 0.5f;
        cfg.lifetimeFrames = 0xd;
        cfg.behaviorFlags = 0x110212;
        cfg.textureId = 0x33;
        break;
    case 0x12:

        cfg.startPosY = 40.0f;
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0x14d;
        cfg.behaviorFlags = 0x10012;
        cfg.textureId = 0x33;
        break;
    case 0x10:
        cfg.startPosY = (f32)(s32)(0x14 - randomGetRange(0, 0x28));
        cfg.velocityX = 0.025f * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.velocityZ = 0.025f * (f32)(s32)(0x50U - randomGetRange(0, 0xa0));
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = (s32)(6.0f * (f32)(s32)(randomGetRange(0, 3) + 1U));
        cfg.behaviorFlags = 0x110204;
        cfg.textureId = 0x30;
        break;
    case 0x6:
        cfg.scale = 0.04f;
        cfg.lifetimeFrames = 0x12;
        cfg.behaviorFlags = 0x300200;
        cfg.textureId = 0x33;
        break;
    case 0x8:

        cfg.startPosY = 35.0f;
        cfg.scale = 0.06f;
        cfg.lifetimeFrames = 0x30;
        cfg.initialAlpha = 200;
        cfg.behaviorFlags = 0x300002;
        cfg.textureId = 0x2c;
        break;
    case 0x9:
        cfg.startPosY = 35.0f;
        cfg.startPosZ = 50.0f;
        cfg.scale = 0.06f;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 200;
        cfg.behaviorFlags = 0x300000;
        cfg.textureId = 0x2c;
        break;
    case 0xa:
        cfg.scale = 0.06f;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 200;
        cfg.behaviorFlags = 0x300000;
        cfg.textureId = 0x2c;
        break;
    case 0x6b:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (extraArgs == NULL)
        {
            return -1;
        }
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityX = *extraArgs;
        cfg.velocityY = extraArgs[1];
        cfg.velocityZ = extraArgs[2];
        cfg.scale = 0.001f;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = (u8)spawnParams->scale;
        cfg.linkGroup = 10;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0xc13;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourcePosX = 1.0f;
        cfg.sourceVecZ = 0;
        cfg.sourceVecY = 0;
        cfg.sourceVecX = spawnParams->rotX;
        break;
    case 0x6c:
        cfg.scale = 0.002f;
        cfg.lifetimeFrames = 1;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x11;
        cfg.renderFlags = 2;
        cfg.textureId = 0xdd;
        break;
    case 0x56:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        *state.startPos = (f32)(s32)randomGetRange(0xfffffffa, 6);
        cfg.startPosZ = (f32)(s32)randomGetRange(0xfffffffa, 6);
        cfg.velocityX = spawnParams->scale * (0.2f * (f32)(s32)randomGetRange(0xfffffffe, 2));
        cfg.velocityY = spawnParams->scale * (0.1f * (f32)(s32)randomGetRange(0, 4));
        cfg.velocityZ = spawnParams->scale * (0.2f * (f32)(s32)randomGetRange(0xfffffffe, 2));
        cfg.scale = 0.012f * spawnParams->scale;
        cfg.lifetimeFrames = 0x18;
        cfg.behaviorFlags = 0x1080000;
        cfg.renderFlags = 0x1000000;
        cfg.initialAlpha = 0xa5;
        if (extraArgs != NULL)
        {
            cfg.overrideColor0 = (u32)((u8*)extraArgs)[0] << 8;
            cfg.colorWord0 = (u16)cfg.overrideColor0;
            cfg.overrideColor1 = (u32)((u8*)extraArgs)[1] << 8;
            cfg.colorWord1 = (u16)cfg.overrideColor1;
            cfg.overrideColor2 = (u32)((u8*)extraArgs)[2] << 8;
            cfg.colorWord2 = (u16)cfg.overrideColor2;
            cfg.renderFlags |= 0x20;
        }
        cfg.textureId = 0x60;
        break;
    case 0x57:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.startPosY = (f32)(s32)randomGetRange(0, 10);
        cfg.velocityX = spawnParams->scale * (0.003f * (f32)(s32)randomGetRange(0xffffff9c, 100));
        cfg.velocityY = spawnParams->scale * (0.003f * (f32)(s32)randomGetRange(200, 400));
        cfg.velocityZ = spawnParams->scale * (0.003f * (f32)(s32)randomGetRange(0xffffff9c, 100));
        cfg.scale = spawnParams->scale * (0.0001f * (f32)(s32)randomGetRange(8, 0xb));
        cfg.initialAlpha = 0xbe;
        cfg.lifetimeFrames = (s32)(75.0f * spawnParams->scale);
        cfg.behaviorFlags = 0x1200000;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x77;
        if (extraArgs != NULL)
        {
            cfg.overrideColor0 = (u32)((u8*)extraArgs)[0] << 8;
            cfg.colorWord0 = (u16)cfg.overrideColor0;
            cfg.overrideColor1 = (u32)((u8*)extraArgs)[1] << 8;
            cfg.colorWord1 = (u16)cfg.overrideColor1;
            cfg.overrideColor2 = (u32)((u8*)extraArgs)[2] << 8;
            cfg.colorWord2 = (u16)cfg.overrideColor2;
            cfg.renderFlags |= 0x20;
        }
        break;
    case 0x58:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.velocityX = spawnParams->scale * (0.02f * (f32)(s32)randomGetRange(0xffffff9c, 100));
        cfg.velocityY = spawnParams->scale * (0.02f * (f32)(s32)randomGetRange(10, 200));
        cfg.velocityZ = spawnParams->scale * (0.02f * (f32)(s32)randomGetRange(0xffffff9c, 100));
        cfg.scale = spawnParams->scale * (0.0001f * (f32)(s32)randomGetRange(8, 0xb));
        cfg.lifetimeFrames = 0x4b;
        cfg.behaviorFlags = 0x1080000;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x77;
        if (extraArgs != NULL)
        {
            cfg.overrideColor0 = (u32)((u8*)extraArgs)[0] << 8;
            cfg.colorWord0 = (u16)cfg.overrideColor0;
            cfg.overrideColor1 = (u32)((u8*)extraArgs)[1] << 8;
            cfg.colorWord1 = (u16)cfg.overrideColor1;
            cfg.overrideColor2 = (u32)((u8*)extraArgs)[2] << 8;
            cfg.colorWord2 = (u16)cfg.overrideColor2;
            cfg.renderFlags |= 0x20;
        }
        break;
    case 0x323: {
        int lifetime;
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        *state.startPos = 0.101457f * (f32)(s32)randomGetRange(0xffffffea, 0x15) + *state.startPos;
        cfg.startPosY = 0.106482f * (f32)(s32)randomGetRange(0xffffffe9, 0x16) + cfg.startPosY;
        cfg.startPosZ = 0.109351f * (f32)(s32)randomGetRange(0xffffffe9, 0x19) + cfg.startPosZ;
        cfg.scale = 0.00251f * (f32)(s32)randomGetRange(1, 6);
        lifetime = randomGetRange(7, 0xf) + 5;
        cfg.lifetimeFrames = lifetime;
        cfg.textureId = 0xc9a;
        cfg.behaviorFlags = 0x100210;
        cfg.renderFlags = 0x4000800;
        if (extraArgs != NULL)
        {
            u32 variantU = *(u8*)extraArgs;
            if (variantU == '\x01')
            {
                cfg.overrideColor0 = 0x2898;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0x6574;
                cfg.colorWord1 = 0x9f9;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags |= 0x20;
            }
            else if (variantU == '\x02')
            {
                cfg.overrideColor0 = 0xff65;
                cfg.overrideColor1 = 0xd23c;
                cfg.overrideColor2 = 0x7fff;
                cfg.colorWord0 = 0xffc4;
                cfg.colorWord1 = 0xdc81;
                cfg.colorWord2 = 0x2603;
                cfg.renderFlags |= 0x20;
                cfg.scale *= 1.2f;
                cfg.lifetimeFrames = lifetime + 7;
            }
            else if (variantU == '\x03')
            {
                cfg.overrideColor0 = 0xfebe;
                cfg.overrideColor1 = 0x5cb2;
                cfg.overrideColor2 = 0xfd01;
                cfg.colorWord0 = 0xfd2c;
                cfg.colorWord1 = 0x8e5;
                cfg.colorWord2 = 0x1f5;
                cfg.renderFlags |= 0x20;
                cfg.scale *= 1.7f;
                cfg.lifetimeFrames = lifetime + 0x14;
            }
            else if (variantU == '\x04')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.renderFlags |= 0x20;
                cfg.scale *= 1.7f;
            }
            else if (variantU == '\x05')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0;
                cfg.renderFlags |= 0x20;
                cfg.scale *= 1.7f;
            }
            else if (variantU == '\x06')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0x7fff;
                cfg.colorWord2 = 0;
                cfg.renderFlags |= 0x20;
                cfg.scale *= 1.7f;
            }
            else if (variantU == '\a')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.renderFlags |= 0x20;
                cfg.scale *= 1.7f;
            }
            else if (variantU == '\b')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags |= 0x20;
                cfg.scale *= 1.7f;
            }
        }
        break;
    }
    case 0x325:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.startPosZ = -46.0f;
        rot.a = 0.0f;
        rot.b = 0.0f;
        rot.c = 0.0f;
        rot.w = 1.0f;
        rot.rz = randomGetRange(0xffff8001, 0x7fff);
        rot.ry = randomGetRange(0xffff8001, 0x7fff);
        rot.rx = randomGetRange(0xffff8001, 0x7fff);
        vecRotateZXY(&rot.rotation.x, state.startPos);
        cfg.velocityX = -(*state.startPos / 30.0f);
        cfg.velocityY = -(cfg.startPosY / 30.0f);
        cfg.velocityZ = -(cfg.startPosZ / 30.0f);
        cfg.scale = 0.000002f * (f32)(s32)randomGetRange(0x9e, 0x240);
        cfg.lifetimeFrames = randomGetRange(7, 0x12) + 0xc;
        cfg.textureId = 0xc98;
        cfg.behaviorFlags = 0x480110;
        if (extraArgs != NULL)
        {
            u32 variantU = *(u8*)extraArgs;
            if (variantU == '\x01')
            {
                cfg.overrideColor0 = 0x2898;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0x6574;
                cfg.colorWord1 = 0x9f9;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            else if (variantU == '\x02')
            {
                cfg.overrideColor0 = 0xff65;
                cfg.overrideColor1 = 0xd23c;
                cfg.overrideColor2 = 0x7fff;
                cfg.colorWord0 = 0xffc4;
                cfg.colorWord1 = 0xdc81;
                cfg.colorWord2 = 0x2603;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale *= 1.2f;
            }
            else if (variantU == '\x03')
            {
                cfg.overrideColor0 = 0xfebe;
                cfg.overrideColor1 = 0x5cb2;
                cfg.overrideColor2 = 0xfd01;
                cfg.colorWord0 = 0xfd2c;
                cfg.colorWord1 = 0x8e5;
                cfg.colorWord2 = 0x1f5;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale *= 1.1f;
            }
        }
        break;
    case 0x326:
        randomGetRange(1, 1);
        cfg.velocityX = 0.0f;
        randomGetRange(1, 1);
        cfg.velocityY = 0.0f;
        randomGetRange(1, 1);
        cfg.velocityZ = 0.0f;
        randomGetRange(1, 1);
        *state.startPos = 0.0f;
        randomGetRange(1, 1);
        cfg.startPosY = 0.0f;
        randomGetRange(1, 1);
        cfg.startPosZ = 0.0f;
        cfg.scale = 0.001232f * (f32)(s32)randomGetRange(10, 0x1e);
        cfg.lifetimeFrames = randomGetRange(1, 1) + 0x17;
        cfg.textureId = 0xc99;
        cfg.behaviorFlags = 0x180210;
        cfg.initialAlpha = 0x7d;
        if (extraArgs != NULL)
        {
            u32 variantU = *(u8*)extraArgs;
            if (variantU == '\x01')
            {
                cfg.overrideColor0 = 0x2898;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0x6574;
                cfg.colorWord1 = 0x9f9;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale *= 0.7f;
            }
            else if (variantU == '\x02')
            {
                cfg.overrideColor0 = 0xff65;
                cfg.overrideColor1 = 0xd23c;
                cfg.overrideColor2 = 0x7fff;
                cfg.colorWord0 = 0xffc4;
                cfg.colorWord1 = 0xdc81;
                cfg.colorWord2 = 0x2603;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            else if (variantU == '\x03')
            {
                cfg.overrideColor0 = 0xfebe;
                cfg.overrideColor1 = 0x5cb2;
                cfg.overrideColor2 = 0xfd01;
                cfg.colorWord0 = 0xfd2c;
                cfg.colorWord1 = 0x8e5;
                cfg.colorWord2 = 0x1f5;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale *= 1.4f;
            }
            else if (variantU == '\x04')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale *= 1.7f;
            }
            else if (variantU == '\x05')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale *= 1.7f;
            }
            else if (variantU == '\x06')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0x7fff;
                cfg.colorWord2 = 0;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale *= 1.7f;
            }
            else if (variantU == '\a')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale *= 1.7f;
            }
            else if (variantU == '\b')
            {
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0xffff;
                cfg.renderFlags = cfg.renderFlags | 0x20;
                cfg.scale *= 1.7f;
            }
        }
        break;
    case 0x328:

        cfg.velocityX = 0.002f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.velocityZ = 0.002f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.lifetimeFrames = randomGetRange(4, 0xd);
        cfg.behaviorFlags = 0x180210;
        cfg.renderFlags = 0x4000800;
        cfg.scale = 0.0075f;
        cfg.textureId = 0xc9d;
        break;
    case 0x3de:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        if (spawnParams != NULL)
        {
            *state.startPos = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            *state.startPos = 0.1f * (f32)(s32)randomGetRange(0xfffffff6, 10);
            cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0xfffffff6, 10);
            cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(0xfffffff6, 10);
        }
        cfg.velocityX = 0.0f;
        cfg.velocityY = 0.2f;
        cfg.velocityZ = 0.0f;
        cfg.scale = 0.015f;
        cfg.lifetimeFrames = 0x96;
        cfg.linkGroup = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080209;
        cfg.renderFlags = 0x1000020;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xa000;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xc000;
        break;
    case 0x3df:

        *state.startPos = 0.1f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(0xffffff9c, 100);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(8, 10);
        if ((int)randomGetRange(0, 0x28) != 0)
        {
            cfg.scale = 0.001f * (f32)(s32)randomGetRange(8, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x5a, 0x78);
        }
        else
        {
            cfg.scale = 0.001f * (f32)(s32)randomGetRange(0x15, 0x29);
            cfg.lifetimeFrames = 0x1cc;
        }
        cfg.behaviorFlags = (u32)lbl_80380209;
        cfg.renderFlags = 0x5000820;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x7f;
        cfg.overrideColor0 = 0x62c0;
        cfg.overrideColor1 = 0xd310;
        cfg.overrideColor2 = 0x2800;
        cfg.colorWord0 = 0x44c0;
        cfg.colorWord1 = 0xd310;
        cfg.colorWord2 = 0xb00;
        break;
    case 0x320:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.velocityX = 0.05f * (f32)(s32)randomGetRange(0xfffffffe, 2);
        cfg.velocityY = 0.07f * (f32)(s32)randomGetRange(2, 5);
        cfg.velocityZ = -0.1f * (f32)(s32)randomGetRange(1, 3);
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.03f;
        cfg.lifetimeFrames = 0x28;
        cfg.renderFlags = 0x5000000;
        cfg.behaviorFlags = 0x180208;
        cfg.textureId = 0xc8f;
        break;
    case 0x321:
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.velocityY = 0.1f * (f32)(s32)randomGetRange(0, 4);
        cfg.velocityZ = -0.15f * (f32)(s32)randomGetRange(2, 4);
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 100;
        cfg.behaviorFlags = 0x1180200;
        cfg.renderFlags = 0x5000000;
        cfg.textureId = 0xc90;
        break;
    case 0x322:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.015f;
        cfg.lifetimeFrames = 0x50;
        cfg.behaviorFlags = 0x180200;
        cfg.renderFlags = 0x5000000;
        cfg.textureId = 0xc90;
        cfg.initialAlpha = 0xa5;
        break;
    case 0x351:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.velocityZ = -0.5f;
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.0002f * (f32)(s32)randomGetRange(0x32, 100);
        cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
        cfg.behaviorFlags = 0x8100200;
        cfg.renderFlags = 0x5000000;
        cfg.textureId = 0xc8f;
        break;
    case 0x51d:

        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
            spawnParams = &gPartfxDefaultSpawnParams;
        }
        cfg.sourceVecX = 700;
        cfg.textureId = 0xc09;
        *state.startPos = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(10, 0x14);
        cfg.lifetimeFrames = 0xaa;
        cfg.behaviorFlags = 0xa0104;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourceVecY = 0;
        cfg.sourceVecZ = 0;
        cfg.sourcePosX = 1.0f;
        break;
    case 0x55a:
    {
        if (spawnParams == NULL)
        {
            gPartfxDefaultSpawnParams.posX = 0.0f;
            gPartfxDefaultSpawnParams.posY = 0.0f;
            gPartfxDefaultSpawnParams.posZ = 0.0f;
            gPartfxDefaultSpawnParams.scale = 1.0f;
            gPartfxDefaultSpawnParams.unk0 = 0;
            gPartfxDefaultSpawnParams.unk2 = 0;
            gPartfxDefaultSpawnParams.unk4 = 0;
            gPartfxDefaultSpawnParams.unk6 = 0;
        }
        cfg.velocityX = 0.004f * (f32)(s32)randomGetRange(0xffffffd8, 0x28);
        cfg.velocityY = 0.002f * (f32)(s32)randomGetRange(10, 0x50);
        cfg.velocityZ = 0.004f * (f32)(s32)randomGetRange(0xffffffd8, 0x28);
        cfg.scale = 0.00015f * (f32)(s32)randomGetRange(5, 0x19);
        cfg.lifetimeFrames = randomGetRange(0x122, 0x15e);
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)randomGetRange(0xe6, 800);
        cfg.sourcePosZ = (f32)(s32)randomGetRange(0xe6, 800);
        cfg.sourcePosW = (f32)(s32)randomGetRange(0xe6, 800);
        cfg.renderFlags = 0x1000020;
        cfg.behaviorFlags = 0x86000008;
        cfg.overrideColor0 = randomGetRange(0, 0xfff) + 0xf000;
        cfg.colorWord0 = (u16)cfg.overrideColor0;
        cfg.overrideColor1 = 0xe000;
        cfg.colorWord1 = (u16)cfg.overrideColor1;
        cfg.overrideColor2 = 0xe000;
        cfg.colorWord2 = (u16)cfg.overrideColor2;
        cfg.textureId = 0x567;
        break;
    }
    case 0x564:
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x32, 100);
        cfg.lifetimeFrames = 0x2d;
        cfg.behaviorFlags = 0x80580210;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0f;
        break;
    case 0x565:

        cfg.scale = 1.0f;
        cfg.lifetimeFrames = 0x14;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x210;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0x5b1;
        break;
    case 0x324:
        break;
    case 0xb:
    case 0x327:
    case 0x52e:
    case 0x555:
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if ((cfg.behaviorFlags & 1) != 0 && (cfg.behaviorFlags & 2) != 0)
    {
        cfg.behaviorFlags ^= 2LL;
    }
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
            if (cfg.attachedSource != NULL)
            {
                cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
        }
    }
    return (*gExpgfxInterface)->spawnEffect(&cfg, 0xffffffff, state.effectId, 0);
}

/* Tick global effect phases and expire the 20 cached particle resource
 * slots. */
void partfx_updateFrameState(void)
{
    gPartfxFrameAnimPhase0 = gPartfxFrameAnimPhase0 + 0.001f * timeDelta;
    if (gPartfxFrameAnimPhase0 > 1.0f)
    {
        gPartfxFrameAnimPhase0 = 0.1f;
    }
    gPartfxFrameAnimPhase1 = gPartfxFrameAnimPhase1 + 0.001f * timeDelta;
    if (gPartfxFrameAnimPhase1 > 1.0f)
    {
        gPartfxFrameAnimPhase1 = 0.3f;
    }
    gPartfxOscAngle0 = gPartfxOscAngle0 + framesThisStep * 100;
    if (gPartfxOscAngle0 > 0x7fff)
    {
        gPartfxOscAngle0 = 0;
    }
    gPartfxOscSine0 = mathSinf(3.1415927f * (f32)(s16)gPartfxOscAngle0 / 32768.0f);
    gPartfxOscAngle1 = gPartfxOscAngle1 + framesThisStep * 0x32;
    if (gPartfxOscAngle1 > 0x7fff)
    {
        gPartfxOscAngle1 = 0;
    }
    gPartfxOscSine1 = mathSinf(3.1415927f * (f32)(s16)gPartfxOscAngle1 / 32768.0f);
    if (gPartfxResourceTimeouts[0] != 0 && (gPartfxResourceTimeouts[0] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule00 != NULL)
            Resource_Release(gPartfxResourceModule00);
        gPartfxResourceModule00 = NULL;
        gPartfxResourceTimeouts[0] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[1] != 0 && (gPartfxResourceTimeouts[1] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule01 != NULL)
            Resource_Release(gPartfxResourceModule01);
        gPartfxResourceModule01 = NULL;
        gPartfxResourceTimeouts[1] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[2] != 0 && (gPartfxResourceTimeouts[2] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule02 != NULL)
            Resource_Release(gPartfxResourceModule02);
        gPartfxResourceModule02 = NULL;
        gPartfxResourceTimeouts[2] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[3] != 0 && (gPartfxResourceTimeouts[3] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule03 != NULL)
            Resource_Release(gPartfxResourceModule03);
        gPartfxResourceModule03 = NULL;
        gPartfxResourceTimeouts[3] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[4] != 0 && (gPartfxResourceTimeouts[4] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule04 != NULL)
            Resource_Release(gPartfxResourceModule04);
        gPartfxResourceModule04 = NULL;
        gPartfxResourceTimeouts[4] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[5] != 0 && (gPartfxResourceTimeouts[5] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule05 != NULL)
            Resource_Release(gPartfxResourceModule05);
        gPartfxResourceModule05 = NULL;
        gPartfxResourceTimeouts[5] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[16] != 0 && (gPartfxResourceTimeouts[16] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule16 != NULL)
            Resource_Release(gPartfxResourceModule16);
        gPartfxResourceModule16 = NULL;
        gPartfxResourceTimeouts[16] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[6] != 0 && (gPartfxResourceTimeouts[6] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule06 != NULL)
            Resource_Release(gPartfxResourceModule06);
        gPartfxResourceModule06 = NULL;
        gPartfxResourceTimeouts[6] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[7] != 0 && (gPartfxResourceTimeouts[7] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule07 != NULL)
            Resource_Release(gPartfxResourceModule07);
        gPartfxResourceModule07 = NULL;
        gPartfxResourceTimeouts[7] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[8] != 0 && (gPartfxResourceTimeouts[8] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule08 != NULL)
            Resource_Release(gPartfxResourceModule08);
        gPartfxResourceModule08 = NULL;
        gPartfxResourceTimeouts[8] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[9] != 0 && (gPartfxResourceTimeouts[9] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule09 != NULL)
            Resource_Release(gPartfxResourceModule09);
        gPartfxResourceModule09 = NULL;
        gPartfxResourceTimeouts[9] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[10] != 0 && (gPartfxResourceTimeouts[10] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule10 != NULL)
            Resource_Release(gPartfxResourceModule10);
        gPartfxResourceModule10 = NULL;
        gPartfxResourceTimeouts[10] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[11] != 0 && (gPartfxResourceTimeouts[11] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule11 != NULL)
            Resource_Release(gPartfxResourceModule11);
        gPartfxResourceModule11 = NULL;
        gPartfxResourceTimeouts[11] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[12] != 0 && (gPartfxResourceTimeouts[12] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule12 != NULL)
            Resource_Release(gPartfxResourceModule12);
        gPartfxResourceModule12 = NULL;
        gPartfxResourceTimeouts[12] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[13] != 0 && (gPartfxResourceTimeouts[13] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule13 != NULL)
            Resource_Release(gPartfxResourceModule13);
        gPartfxResourceModule13 = NULL;
        gPartfxResourceTimeouts[13] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[14] != 0 && (gPartfxResourceTimeouts[14] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule14 != NULL)
            Resource_Release(gPartfxResourceModule14);
        gPartfxResourceModule14 = NULL;
        gPartfxResourceTimeouts[14] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[15] != 0 && (gPartfxResourceTimeouts[15] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule15 != NULL)
            Resource_Release(gPartfxResourceModule15);
        gPartfxResourceModule15 = NULL;
        gPartfxResourceTimeouts[15] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[17] != 0 && (gPartfxResourceTimeouts[17] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule17 != NULL)
            Resource_Release(gPartfxResourceModule17);
        gPartfxResourceModule17 = NULL;
        gPartfxResourceTimeouts[17] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[18] != 0 && (gPartfxResourceTimeouts[18] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule18 != NULL)
            Resource_Release(gPartfxResourceModule18);
        gPartfxResourceModule18 = NULL;
        gPartfxResourceTimeouts[18] = 0;
        gPartfxCachedResourceCount -= 1;
    }
    if (gPartfxResourceTimeouts[19] != 0 && (gPartfxResourceTimeouts[19] -= framesThisStep) <= 0)
    {
        if (gPartfxResourceModule19 != NULL)
            Resource_Release(gPartfxResourceModule19);
        gPartfxResourceModule19 = NULL;
        gPartfxResourceTimeouts[19] = 0;
        gPartfxCachedResourceCount -= 1;
    }
}

void partfx_onMapSetup(void)
{
}

/* Clear the 20-slot effect-id table and free all 20 cached particle
 * resources. */
void partfx_release(void)
{
    s16* p;
    int i;
    i = 0x14;
    p = gPartfxResourceTimeouts + 0x14;
    while ((s8)i != 0)
    {
        p = p - 1;
        i = i - 1;
        *p = 0;
    }
    if (gPartfxResourceModule00 != NULL)
        Resource_Release(gPartfxResourceModule00);
    gPartfxResourceModule00 = NULL;
    if (gPartfxResourceModule01 != NULL)
        Resource_Release(gPartfxResourceModule01);
    gPartfxResourceModule01 = NULL;
    if (gPartfxResourceModule02 != NULL)
        Resource_Release(gPartfxResourceModule02);
    gPartfxResourceModule02 = NULL;
    if (gPartfxResourceModule03 != NULL)
        Resource_Release(gPartfxResourceModule03);
    gPartfxResourceModule03 = NULL;
    if (gPartfxResourceModule04 != NULL)
        Resource_Release(gPartfxResourceModule04);
    gPartfxResourceModule04 = NULL;
    if (gPartfxResourceModule05 != NULL)
        Resource_Release(gPartfxResourceModule05);
    gPartfxResourceModule05 = NULL;
    if (gPartfxResourceModule16 != NULL)
        Resource_Release(gPartfxResourceModule16);
    gPartfxResourceModule16 = NULL;
    if (gPartfxResourceModule06 != NULL)
        Resource_Release(gPartfxResourceModule06);
    gPartfxResourceModule06 = NULL;
    if (gPartfxResourceModule07 != NULL)
        Resource_Release(gPartfxResourceModule07);
    gPartfxResourceModule07 = NULL;
    if (gPartfxResourceModule08 != NULL)
        Resource_Release(gPartfxResourceModule08);
    gPartfxResourceModule08 = NULL;
    if (gPartfxResourceModule09 != NULL)
        Resource_Release(gPartfxResourceModule09);
    gPartfxResourceModule09 = NULL;
    if (gPartfxResourceModule10 != NULL)
        Resource_Release(gPartfxResourceModule10);
    gPartfxResourceModule10 = NULL;
    if (gPartfxResourceModule11 != NULL)
        Resource_Release(gPartfxResourceModule11);
    gPartfxResourceModule11 = NULL;
    if (gPartfxResourceModule12 != NULL)
        Resource_Release(gPartfxResourceModule12);
    gPartfxResourceModule12 = NULL;
    if (gPartfxResourceModule13 != NULL)
        Resource_Release(gPartfxResourceModule13);
    gPartfxResourceModule13 = NULL;
    if (gPartfxResourceModule14 != NULL)
        Resource_Release(gPartfxResourceModule14);
    gPartfxResourceModule14 = NULL;
    if (gPartfxResourceModule15 != NULL)
        Resource_Release(gPartfxResourceModule15);
    gPartfxResourceModule15 = NULL;
    if (gPartfxResourceModule17 != NULL)
        Resource_Release(gPartfxResourceModule17);
    gPartfxResourceModule17 = NULL;
    if (gPartfxResourceModule18 != NULL)
        Resource_Release(gPartfxResourceModule18);
    gPartfxResourceModule18 = NULL;
    if (gPartfxResourceModule19 != NULL)
        Resource_Release(gPartfxResourceModule19);
    gPartfxResourceModule19 = NULL;
    gPartfxCachedResourceCount = 0;
}

void partfx_initialise(void)
{
    s16* p;
    int i;
    i = 0x14;
    p = gPartfxResourceTimeouts + 0x14;
    while ((s8)i != 0)
    {
        p = p - 1;
        i = i - 1;
        *p = 0;
    }
    gPartfxCachedResourceCount = 0;
}
