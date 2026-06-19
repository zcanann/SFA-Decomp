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
#include "main/dll_000A_expgfx.h"

extern int randomGetRange(int lo, int hi);

extern f32 timeDelta;
extern u8 framesThisStep;
extern float mathSinf(float x);

extern f32 lbl_803DB878;
extern f32 lbl_803DB87C;
extern f32 lbl_803E02D8;
extern f32 lbl_803E02DC;
extern f32 lbl_803E02E8;
extern s32 lbl_803DD3F0;
extern s32 lbl_803DD3F4;
extern f32 lbl_803DD3F8;
extern f32 lbl_803DD3FC;
extern f32 lbl_803E0308;
extern f32 lbl_803E030C;

extern f32 lbl_803DB870;
extern f32 lbl_803DB874;
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

    lbl_803DB870 = lbl_803DB870 + lbl_803E02D8;
    if (lbl_803DB870 > 1.0f) lbl_803DB870 = lbl_803E02DC;
    lbl_803DB874 = lbl_803DB874 + lbl_803E02E4;
    if (lbl_803DB874 > 1.0f) lbl_803DB874 = lbl_803E02E8;
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
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
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
    sum = lbl_803DB878 + (step = lbl_803E02D8 * timeDelta);
    lbl_803DB878 = sum;
    if (sum > 1.0f) lbl_803DB878 = lbl_803E02DC;
    sum = lbl_803DB87C + step;
    lbl_803DB87C = sum;
    if (sum > 1.0f) lbl_803DB87C = lbl_803E02E8;
    lbl_803DD3F0 = lbl_803DD3F0 + framesThisStep * 0x64;
    if (lbl_803DD3F0 > 0x7fff) lbl_803DD3F0 = 0;
    lbl_803DD3FC = mathSinf(lbl_803E0308 * (f32)(s16)lbl_803DD3F0 / lbl_803E030C);
    lbl_803DD3F4 = lbl_803DD3F4 + framesThisStep * 0x32;
    if (lbl_803DD3F4 > 0x7fff) lbl_803DD3F4 = 0;
    lbl_803DD3F8 = mathSinf(lbl_803E0308 * (f32)(s16)lbl_803DD3F4 / lbl_803E030C);
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
