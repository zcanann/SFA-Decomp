/*
 * effect19 (DLL 0x2C) - one of the dim_partfx particle-effect DLLs.
 * Exposes the standard effect vtable entry points (func03_nop / func04 /
 * func05 / release / initialise) registered through gExpgfxInterface.
 *
 * Effect19_func04 builds a PartFxSpawn request from a switch over the
 * effect id (only id 0x76c is handled here) and hands it to
 * gExpgfxInterface->spawnEffect. Effect19_func05 advances this DLL's
 * animated scroll/oscillator globals once per game step.
 *
 * Field names on PartFxSpawn are inherited from the consumer-side
 * ExpgfxSpawnConfig (include/main/expgfx_internal.h), the 0x64-byte spawn
 * request consumed by gExpgfxInterface->spawnEffect (expgfx_addremove).
 */
#include "main/dll/partfxspawn_struct.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
#include "main/frame_timing.h"
#include "main/dll/dll_002C_effect19.h"

extern f32 gEffect19ScrollPhase2;
extern f32 gEffect19ScrollPhase3;
extern s32 gEffect19Osc0Angle;
extern s32 gEffect19Osc1Angle;
extern f32 gEffect19Osc1Value;
extern f32 gEffect19Osc0Value;
extern f32 gEffect19ScrollPhase0;
extern f32 gEffect19ScrollPhase1;

int Effect19_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                    f32* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    gEffect19ScrollPhase0 += 0.001f;
    if (gEffect19ScrollPhase0 > 1.0f)
        gEffect19ScrollPhase0 = 0.1f;
    gEffect19ScrollPhase1 += 0.0003f;
    if (gEffect19ScrollPhase1 > 1.0f)
        gEffect19ScrollPhase1 = 0.3f;
    if (sourceObj == NULL)
    {
        spawnResult = -1;
    }
    else
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            if (spawnParams == NULL)
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
        case 0x76c:
            cfg.velocityX = 0.002f * (f32)(s32)randomGetRange(0x1e, 0x64);
            if (spawnParams->posX > 0.0f)
                cfg.velocityX = -cfg.velocityX;
            cfg.velocityY = 0.001f * (f32)(s32)randomGetRange(0, 0x64) + 0.1f;
            cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange((s32)extraArgs[0], extraArgs[1]);
            cfg.startPosX = 5.0f;
            if (spawnParams->posX > 0.0f)
                cfg.startPosX = -5.0f;
            cfg.scale = 3e-05f * (f32)(s32)randomGetRange(-0x64, 0x64) + extraArgs[2];
            cfg.lifetimeFrames = 0x23;
            cfg.behaviorFlags = 0x80108;
            cfg.textureId = 0x60;
            cfg.initialAlpha = 0xc4;
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
            else if (cfg.attachedSource != NULL)
            {
                cfg.startPosX = cfg.startPosX + ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY = cfg.startPosY + ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ = cfg.startPosZ + ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
        }
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    }
    return spawnResult;
}

void Effect19_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect19ScrollPhase2 + (step = 0.001f * timeDelta);
    gEffect19ScrollPhase2 = sum;
    if (sum > 1.0f)
        gEffect19ScrollPhase2 = 0.1f;
    sum = gEffect19ScrollPhase3 + step;
    gEffect19ScrollPhase3 = sum;
    if (sum > 1.0f)
        gEffect19ScrollPhase3 = 0.3f;
    gEffect19Osc0Angle = gEffect19Osc0Angle + framesThisStep * 0x64;
    if (gEffect19Osc0Angle > 0x7fff)
        gEffect19Osc0Angle = 0;
    gEffect19Osc0Value = mathSinf(3.1415927f * (f32)(s16)gEffect19Osc0Angle / 32768.0f);
    gEffect19Osc1Angle = gEffect19Osc1Angle + framesThisStep * 0x32;
    if (gEffect19Osc1Angle > 0x7fff)
        gEffect19Osc1Angle = 0;
    gEffect19Osc1Value = mathSinf(3.1415927f * (f32)(s16)gEffect19Osc1Angle / 32768.0f);
}

void Effect19_func03_nop(void)
{
}

void Effect19_release(void)
{
}

void Effect19_initialise(void)
{
}
