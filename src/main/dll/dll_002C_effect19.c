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
#include "main/game_object.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
extern f32 timeDelta;
extern u8 framesThisStep;
extern float mathSinf(float x);
extern f32 gEffect19ScrollPhase2;
extern f32 gEffect19ScrollPhase3;
extern f32 lbl_803E02D8;
extern f32 lbl_803E02DC;
extern f32 lbl_803E02E8;
extern s32 gEffect19Osc0Angle;
extern s32 gEffect19Osc1Angle;
extern f32 gEffect19Osc1Value;
extern f32 gEffect19Osc0Value;
extern f32 gEffect19Pi;
extern f32 gEffect19SineAngleScale;
extern f32 gEffect19ScrollPhase0;
extern f32 gEffect19ScrollPhase1;
extern f32 lbl_803E02E4;
extern f32 lbl_803E02EC;
extern f32 lbl_803E02F0;
extern f32 lbl_803E02F4;
extern f32 lbl_803E02F8;
extern f32 lbl_803E02FC;

int Effect19_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                    u8 modelId, f32* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    gEffect19ScrollPhase0 = gEffect19ScrollPhase0 + lbl_803E02D8;
    if (gEffect19ScrollPhase0 > 1.0f) gEffect19ScrollPhase0 = lbl_803E02DC;
    gEffect19ScrollPhase1 = gEffect19ScrollPhase1 + lbl_803E02E4;
    if (gEffect19ScrollPhase1 > 1.0f) gEffect19ScrollPhase1 = lbl_803E02E8;
    if (sourceObj == NULL)
    {
        spawnResult = -1;
    }
    else
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            if (spawnParams == NULL) return -1;
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
        cfg.startPosX = lbl_803E02EC;
        cfg.startPosY = lbl_803E02EC;
        cfg.startPosZ = lbl_803E02EC;
        cfg.velocityX = lbl_803E02EC;
        cfg.velocityY = lbl_803E02EC;
        cfg.velocityZ = lbl_803E02EC;
        cfg.scale = lbl_803E02EC;
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
            cfg.velocityX = lbl_803E02F0 * (f32)(s32)
            randomGetRange(0x1e, 0x64);
            if (spawnParams->posX > lbl_803E02EC) cfg.velocityX = -cfg.velocityX;
            cfg.velocityY = lbl_803E02D8 * (f32)(s32)
            randomGetRange(0, 0x64) + lbl_803E02DC;
            cfg.startPosZ = lbl_803E02DC *
                (f32)(s32)
            randomGetRange((s32)extraArgs[0], extraArgs[1]);
            cfg.startPosX = lbl_803E02F4;
            if (spawnParams->posX > lbl_803E02EC) cfg.startPosX = lbl_803E02F8;
            cfg.scale = lbl_803E02FC * (f32)(s32)
            randomGetRange(-0x64, 0x64) + extraArgs[2];
            cfg.lifetimeFrames = 0x23;
            cfg.behaviorFlags = 0x80108;
            cfg.textureId = 0x60;
            cfg.initialAlpha = 0xc4;
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
    sum = gEffect19ScrollPhase2 + (step = lbl_803E02D8 * timeDelta);
    gEffect19ScrollPhase2 = sum;
    if (sum > 1.0f) gEffect19ScrollPhase2 = lbl_803E02DC;
    sum = gEffect19ScrollPhase3 + step;
    gEffect19ScrollPhase3 = sum;
    if (sum > 1.0f) gEffect19ScrollPhase3 = lbl_803E02E8;
    gEffect19Osc0Angle = gEffect19Osc0Angle + framesThisStep * 0x64;
    if (gEffect19Osc0Angle > 0x7fff) gEffect19Osc0Angle = 0;
    gEffect19Osc0Value = mathSinf(gEffect19Pi * (f32)(s16)gEffect19Osc0Angle / gEffect19SineAngleScale);
    gEffect19Osc1Angle = gEffect19Osc1Angle + framesThisStep * 0x32;
    if (gEffect19Osc1Angle > 0x7fff) gEffect19Osc1Angle = 0;
    gEffect19Osc1Value = mathSinf(gEffect19Pi * (f32)(s16)gEffect19Osc1Angle / gEffect19SineAngleScale);
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
