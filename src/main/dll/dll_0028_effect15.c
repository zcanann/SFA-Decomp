/*
 * effect15 (DLL 0x28) - a particle/effect spawn table.
 *
 * Effect15_func04 is the sole worker: given an effectId in 0x3e8..0x3fc it
 * fills an EffectSpawnConfig (PartFxSpawn) - randomised position/velocity/
 * scale/lifetime, texture id, behaviour + render flags - and submits it via
 * gExpgfxInterface->spawnEffect. spawnFlags bit 0x200000 selects the
 * caller-supplied PartFxSpawnParams source transform; behaviourFlags bit 0
 * then offsets the start position by the attached source's world position
 * (object fields +0x18/+0x1c/+0x20). The remaining entry points are empty
 * DLL lifecycle stubs.
 */
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/waterfxcfg_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dll_0028_effect15.h"

WaterfxCfg gEffect15DefaultSpawnParams;

ObjectDescriptor6 lbl_80310F38 = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect15_initialise,
    (ObjectDescriptorCallback)Effect15_release,
    0,
    (ObjectDescriptorCallback)Effect15_func03_nop,
    (ObjectDescriptorCallback)Effect15_func04,
    (ObjectDescriptorCallback)Effect15_func05_nop,
};

int Effect15_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                    f32* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

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
    switch (effectId)
    {
    case 0x3e8:
        cfg.scale = 0.000015f * (f32)(s32)randomGetRange(0x5a, 0x64);
        cfg.velocityX = 0.005f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.velocityY = 0.0f;
        cfg.velocityZ = 0.005f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.lifetimeFrames = 0x28;
        cfg.behaviorFlags |= 0x80218LL;
        cfg.renderFlags = 0x20;
        switch (randomGetRange(0, 2))
        {
        case 0:
            cfg.textureId = 0x156;
            break;
        case 1:
            cfg.textureId = 0x157;
            break;
        case 2:
            cfg.textureId = 0xc0e;
            break;
        default:
            cfg.textureId = 0x156;
            break;
        }
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xd6d8;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0x7530;
        cfg.overrideColor2 = 0xffff;
        cfg.initialAlpha = 0xff;
        break;
    case 0x3e9:
        if (spawnParams == 0)
        {
            gEffect15DefaultSpawnParams.posX = 0.0f;
            gEffect15DefaultSpawnParams.posY = 0.0f;
            gEffect15DefaultSpawnParams.posZ = 0.0f;
            gEffect15DefaultSpawnParams.scale = 1.0f;
            gEffect15DefaultSpawnParams.rotX = 0;
            gEffect15DefaultSpawnParams.rotY = 0;
            gEffect15DefaultSpawnParams.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect15DefaultSpawnParams;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = 0.05f;
        cfg.behaviorFlags |= 0x180110LL;
        cfg.renderFlags = 0x20;
        cfg.lifetimeFrames = 0x12;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x159;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xc350;
        cfg.overrideColor2 = 0xffff;
        break;
    case 0x3ea:
        if (spawnParams == 0)
        {
            gEffect15DefaultSpawnParams.posX = 0.0f;
            gEffect15DefaultSpawnParams.posY = 0.0f;
            gEffect15DefaultSpawnParams.posZ = 0.0f;
            gEffect15DefaultSpawnParams.scale = 1.0f;
            gEffect15DefaultSpawnParams.rotX = 0;
            gEffect15DefaultSpawnParams.rotY = 0;
            gEffect15DefaultSpawnParams.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect15DefaultSpawnParams;
        }
        cfg.startPosX = (f32)(s32)randomGetRange(-0x64, 0x64) / 50.0f;
        cfg.startPosY = (f32)(s32)(-randomGetRange(0x64, 0x96)) / 100.0f;
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x64, 0x64) / 50.0f;
        cfg.behaviorFlags |= 0x80208LL;
        cfg.renderFlags = 0x10000;
        cfg.velocityX = 0.001f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityZ = 0.001f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.initialAlpha = 0xff;
        cfg.lifetimeFrames = 0x3c;
        cfg.textureId = 0x7b;
        cfg.scale =
            spawnParams->scale * (0.0003f * (0.01f * (f32)(s32)randomGetRange(0x32, 0x64))) + 0.001f;
        break;
    case 0x3eb:
        cfg.velocityX = 0.04f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(-5, 5);
        cfg.velocityZ = 0.04f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.startPosX = 0.0f;
        cfg.startPosY = (f32)(s32)randomGetRange(-6, 2);
        cfg.startPosZ = 0.0f;
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x80080208;
        cfg.textureId = 0x60;
        cfg.colorWord0 = 0x7f00;
        cfg.colorWord1 = 0x6400;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0x5a00;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x3ec:
        return -1;
    case 0x3ed:
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.velocityZ = 0.02f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x80210;
        cfg.renderFlags = 0x8000800;
        cfg.textureId = 0x79;
        break;
    case 0x3ee:
        cfg.startPosX = cfg.startPosX + (f32)(s32)randomGetRange(-0xa, 0xa) / 3.0f;
        cfg.startPosY = cfg.startPosY + (f32)(s32)randomGetRange(-0x1e, 0) / 10.0f;
        cfg.startPosZ = cfg.startPosZ + (f32)(s32)randomGetRange(-0xa, 0xa) / 3.0f;
        cfg.velocityX = 0.001f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.0022f * (f32)(s32)(-randomGetRange(0x28, 0x64));
        cfg.velocityZ = 0.001f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(0xf, 0x16);
        cfg.lifetimeFrames = 0x258;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0xc10;
        cfg.initialAlpha = randomGetRange(0x96, 0xfa);
        break;
    case 0x3ef:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x4b0, 0x4b0) / 100.0f;
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x4b0, 0x4b0) / 100.0f;
        cfg.velocityY = 0.0022f * (f32)(s32)randomGetRange(0x1e, 0x46);
        cfg.scale = 0.00012f * (f32)(s32)randomGetRange(0, 0x14) + 0.002f;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x33;
        cfg.initialAlpha = 0xb4;
        cfg.renderFlags = 0x8100800;
        break;
    case 0x3f0:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x3e8, 0x3e8) / 100.0f;
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x3e8, 0x3e8) / 100.0f;
        cfg.velocityY = 0.0021f * (f32)(s32)randomGetRange(0x1e, 0x46);
        cfg.scale = 0.00012f * (f32)(s32)randomGetRange(0, 0x14) + 0.0015f;
        cfg.lifetimeFrames = 0xfa;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x33;
        cfg.renderFlags = 0x8000800;
        cfg.initialAlpha = 0xb4;
        break;
    case 0x3f1:
        cfg.startPosX = 0.0f;
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.0f;
        cfg.behaviorFlags = 0x80800;
        cfg.textureId = 0x76;
        cfg.initialAlpha = 0xd2;
        cfg.scale = 0.0075f;
        cfg.lifetimeFrames = 0x64;
        break;
    case 0x3f2:
        if (extraArgs == 0)
            return 0;
        if (spawnParams == 0)
        {
            gEffect15DefaultSpawnParams.posX = 0.0f;
            gEffect15DefaultSpawnParams.posY = 0.0f;
            gEffect15DefaultSpawnParams.posZ = 0.0f;
            gEffect15DefaultSpawnParams.scale = 1.0f;
            gEffect15DefaultSpawnParams.rotX = 0;
            gEffect15DefaultSpawnParams.rotY = 0;
            gEffect15DefaultSpawnParams.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect15DefaultSpawnParams;
        }
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        if (extraArgs != 0)
        {
            cfg.velocityX = extraArgs[0];
            cfg.velocityY = 0.03f * (f32)(s32)randomGetRange(0, 0x14);
            cfg.velocityZ = extraArgs[1];
        }
        cfg.scale = 2.0f * (0.0002f * (f32)(s32)randomGetRange(0, 0xa) + 0.000945f);
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x81088000;
        cfg.textureId = 0x23c;
        break;
    case 0x3f3:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x32, 0x32) / 100.0f;
        cfg.startPosY = (f32)(s32)randomGetRange(-0x32, 0x32) / 100.0f;
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x32, 0x32) / 100.0f;
        cfg.velocityX = 0.005f * (f32)(s32)randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0)
            cfg.velocityX = -cfg.velocityX;
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0)
            cfg.velocityY = -cfg.velocityY;
        cfg.velocityZ = 0.005f * (f32)(s32)randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0)
            cfg.velocityZ = -cfg.velocityZ;
        cfg.scale = 0.00012f * (f32)(s32)randomGetRange(0, 0xa) + 0.001f;
        cfg.lifetimeFrames = 0x46;
        cfg.behaviorFlags = 0x80208;
        cfg.textureId = 0x76;
        cfg.initialAlpha = 0xb4;
        cfg.renderFlags = 0x100000;
        break;
    case 0x3f4:
    case 0x3f5:
    case 0x3f6:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = cfg.startPosX - ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
        }
        if ((int)randomGetRange(0, 0x28) == 0)
            cfg.scale = 0.0003f;
        else
            cfg.scale = 0.0015f;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        switch (effectId - 0x3f4)
        {
        case 0:
            cfg.textureId = 0x156;
            break;
        case 1:
            cfg.textureId = 0x157;
            break;
        case 2:
            cfg.textureId = 0xc0e;
            break;
        default:
            cfg.textureId = 0x156;
            break;
        }
        break;
    case 0x3f7:
    case 0x3f8:
    case 0x3f9:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = cfg.startPosX - ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            cfg.velocityZ = 0.3f;
        }
        cfg.scale = 0.0015f;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480210;
        cfg.renderFlags = 0x100000;
        switch (effectId - 0x3f7)
        {
        case 0:
            cfg.textureId = 0x4fb;
            break;
        case 1:
            cfg.textureId = 0x4fc;
            break;
        case 2:
            cfg.textureId = 0x4fd;
            break;
        default:
            cfg.textureId = 0x4fb;
            break;
        }
        break;
    case 0x3fa:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = cfg.startPosX - ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            cfg.velocityZ = 0.01f;
        }
        cfg.scale = 0.0015f;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480210;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0x4fb;
        break;
    case 0x3fb:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = cfg.startPosX - ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            cfg.scale = spawnParams->scale;
        }
        cfg.lifetimeFrames = 5;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80800;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5ea;
        break;
    case 0x3fc:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = cfg.startPosX - ((GameObject*)cfg.attachedSource)->anim.worldPosX;
            cfg.startPosY = cfg.startPosY - ((GameObject*)cfg.attachedSource)->anim.worldPosY;
            cfg.startPosZ = cfg.startPosZ - ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            cfg.scale = spawnParams->scale;
        }
        cfg.lifetimeFrames = 5;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80800;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5eb;
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
    return spawnResult;
}

void Effect15_func05_nop(void)
{
}

void Effect15_func03_nop(void)
{
}

void Effect15_release(void)
{
}

void Effect15_initialise(void)
{
}
