#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/waterfxcfg_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/waterfx_interface.h"
#include "main/audio/sfx.h"
#include "main/dll/dll_0026_effect13.h"

WaterfxCfg gEffect13DefaultSplashParams;

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

int Effect13_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId)
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
    case 0x44c:
        cfg.velocityX = 0.025f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x6e;
        cfg.behaviorFlags = 0x8a100208;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x400;
        cfg.overrideColor1 = 0xea60;
        cfg.overrideColor2 = 0x1000;
        break;
    case 0x44d:
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.08f;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x0a100100;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0x400;
        cfg.colorWord1 = 0xea60;
        cfg.colorWord2 = 0x1000;
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = 0xc350;
        cfg.overrideColor2 = 0;
        break;
    case 0x44e:
        cfg.startPosY = 610.0f;
        cfg.scale = 0.0023f;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11000004;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x44f;
        break;
    case 0x44f:
        if (spawnParams == 0)
        {
            gEffect13DefaultSplashParams.posX = 0.0f;
            gEffect13DefaultSplashParams.posY = 0.0f;
            gEffect13DefaultSplashParams.posZ = 0.0f;
            gEffect13DefaultSplashParams.scale = 1.0f;
            gEffect13DefaultSplashParams.rotX = 0;
            gEffect13DefaultSplashParams.rotY = 0;
            gEffect13DefaultSplashParams.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect13DefaultSplashParams;
        }
        (*gWaterfxInterface)
            ->spawnSplashBurst(NULL, spawnParams->posX, spawnParams->posY, spawnParams->posZ, 4.0f);
        Sfx_PlayFromObject((int)sourceObj, SFXTRIG_blkscrp6);
        cfg.lifetimeFrames = 1;
        cfg.scale = 0.0001f;
        cfg.behaviorFlags = 0x0a000001;
        cfg.textureId = 0x56;
        break;
    case 0x450:
        cfg.startPosY = 110.0f;
        cfg.scale = 0.0023f;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11000004;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x451;
        break;
    case 0x451:
        Sfx_PlayFromObject((int)sourceObj, SFXTRIG_blkscrp6);
        cfg.lifetimeFrames = 0x64;
        cfg.scale = 0.0003f * (f32)(s32)cfg.lifetimeFrames;
        cfg.behaviorFlags = 0x0a100201;
        cfg.textureId = 0x56;
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

void Effect13_func05_nop(void)
{
}

void Effect13_func03_nop(void)
{
}

void Effect13_release(void)
{
}

void Effect13_initialise(void)
{
}

ObjectDescriptor6 lbl_80310FB8 = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect13_initialise,
    (ObjectDescriptorCallback)Effect13_release,
    0,
    (ObjectDescriptorCallback)Effect13_func03_nop,
    (ObjectDescriptorCallback)Effect13_func04,
    (ObjectDescriptorCallback)Effect13_func05_nop,
};
