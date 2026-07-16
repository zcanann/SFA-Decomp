/*
 * effect3 (DLL 0x1C) - a particle-effect spawner object.
 *
 * The live entry point is Effect3_func04: a spawn dispatcher keyed on
 * effectId (0x1F4..0x20E). For each id it fills a PartFxSpawn request -
 * texture, lifetime, scale, start position, velocity, color, behavior and
 * render flags, mostly randomized via randomGetRange - then hands it to
 * gExpgfxInterface->spawnEffect. Behavior-flag bit 0 means "offset start
 * position by the attached source"; spawnFlags bit 0x200000 selects an
 * explicit PartFxSpawnParams source over the attached object.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/dll_001C_effect3.h"

PartFxSpawnParams lbl_8039C350;
ObjectDescriptor6 lbl_80310808 = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect3_initialise,
    (ObjectDescriptorCallback)Effect3_release,
    0,
    (ObjectDescriptorCallback)Effect3_func03_nop,
    (ObjectDescriptorCallback)Effect3_func04,
    (ObjectDescriptorCallback)Effect3_func05_nop,
};

static inline PartFxSpawnParams* Effect3_getDefaultSpawnParams(void)
{
    lbl_8039C350.posX = 0.0f;
    lbl_8039C350.posY = 0.0f;
    lbl_8039C350.posZ = 0.0f;
    lbl_8039C350.scale = 1.0f;
    lbl_8039C350.rotX = 0;
    lbl_8039C350.rotY = 0;
    lbl_8039C350.rotZ = 0;
    return &lbl_8039C350;
}

int Effect3_func04(s16* sourceObj, int effectId, PartFxSpawnParams* spawnParamsIn, u32 spawnFlags, u8 modelId,
                   f32* extraArgs)
{
    PartFxSpawnParams* spawnParams = spawnParamsIn;
    int spawnResult;
    PartFxSpawn cfg;

    if (sourceObj == 0)
        return -1;
    if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0)
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
    case 0x1f4:
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        cfg.startPosX = 0.1f * (f32)randomGetRange(-0x14, -0xa);
        cfg.startPosY = 0.1f * (f32)randomGetRange(-0xa, 0xa);
        cfg.startPosZ = 0.1f * (f32)randomGetRange(-0xa, 0);
        if (spawnParams != 0)
        {
            cfg.startPosX += spawnParams->posX;
            cfg.startPosY += spawnParams->posY;
            cfg.startPosZ += spawnParams->posZ;
        }
        cfg.scale = 0.0007f * (f32)randomGetRange(0xd, 0x14);
        cfg.lifetimeFrames = 0x19;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80200;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0x184;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f5:
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        cfg.startPosX = 0.1f * (f32)randomGetRange(-0x14, -0xa);
        cfg.startPosY = 0.1f * (f32)randomGetRange(-0xa, 0xa);
        cfg.startPosZ = 0.1f * (f32)randomGetRange(-0xa, 0);
        if (spawnParams != 0)
        {
            cfg.startPosX += spawnParams->posX;
            cfg.startPosY += spawnParams->posY;
            cfg.startPosZ += spawnParams->posZ;
        }
        cfg.scale = 0.003f * (f32)randomGetRange(1, 4);
        cfg.lifetimeFrames = 0x19;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80200;
        cfg.textureId = 0x184;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f6:
        cfg.scale = 0.00022f * (f32)randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0x40;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x80;
        cfg.textureId = 0x16d;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f7:
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        if (spawnParams != 0)
            cfg.startPosY = spawnParams->posY;
        cfg.scale = 0.03f;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x46;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x80110;
        cfg.textureId = 0xc13;
        cfg.linkGroup = 0x20;
        break;
    case 0x1f8:
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        if (spawnParams != 0)
        {
            cfg.scale = 0.03f * spawnParams->scale;
        }
        else
        {
            cfg.scale = 0.03f;
        }
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x46;
        cfg.initialAlpha = 0x64;
        cfg.behaviorFlags |= 0x80100LL;
        cfg.textureId = 0xc79;
        cfg.linkGroup = 0;
        cfg.colorWord0 = 0xe600;
        cfg.colorWord1 = 0x8800;
        cfg.colorWord2 = 0xa100;
        cfg.overrideColor0 = 0xe600;
        cfg.overrideColor1 = 0x8800;
        cfg.overrideColor2 = 0xa100;
        cfg.renderFlags = 0x20;
        break;
    case 0x1fb:
        cfg.scale = 0.035f;
        cfg.lifetimeFrames = 0x10;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100114;
        cfg.textureId = 0x17c;
        break;
    case 0x1fc:
        cfg.scale = 0.03f;
        cfg.lifetimeFrames = 0x44;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x4c;
        break;
    case 0x1fd:
        cfg.startPosX = 0.0f;
        cfg.startPosY = (f32)randomGetRange(-3, 3);
        cfg.startPosZ = (f32)randomGetRange(-3, 3);
        cfg.velocityX = 0.002f * (f32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.002f * (f32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = 0.002f * (f32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xc8;
        cfg.behaviorFlags = 0x140101;
        if ((int)randomGetRange(0, 1) != 0)
        {
            cfg.textureId = 0x33;
        }
        else
        {
            cfg.textureId = 0xc7e;
        }
        break;
    case 0x1fe:
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        if (extraArgs == 0)
            return -1;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        if (extraArgs != 0)
        {
            cfg.velocityX = extraArgs[0];
            cfg.velocityY = 0.03f * (f32)randomGetRange(0, 0x14);
            cfg.velocityZ = extraArgs[1];
        }
        cfg.scale = 0.0002f * (f32)randomGetRange(0, 0xa) + 0.000945f;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x81088000;
        cfg.behaviorFlags = 0x1000000;
        cfg.textureId = 0x23c;
        break;
    case 0x1ff:
        cfg.startPosY = 410.0f;
        cfg.scale = 0.003f;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11000004;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x200;
        break;
    case 0x200:
        Sfx_PlayFromObject((u32)sourceObj, SFXTRIG_blkscrp6);
        cfg.lifetimeFrames = 0x64;
        cfg.scale = 0.0003f * cfg.lifetimeFrames;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x56;
        break;
    case 0x201:
        cfg.startPosX = (f32)randomGetRange(-0x64, 0x64) / 20.0f;
        cfg.startPosY = (f32)randomGetRange(-0x32, 0x32) / 10.0f;
        cfg.startPosZ = (f32)randomGetRange(-0x64, 0x64) / 20.0f;
        cfg.velocityY = 0.03f * (f32)randomGetRange(1, 5);
        cfg.scale = 0.001f;
        cfg.lifetimeFrames = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x63;
        break;
    case 0x202:
        cfg.velocityY = 0.1f * (f32)randomGetRange(0x96, 0xc8) / 100.0f;
        cfg.scale = 0.0004f * ((f32)randomGetRange(0x32, 0x64) / 100.0f) + 0.00025f;
        cfg.lifetimeFrames = (s32)(spawnParams->scale / cfg.velocityY);
        if (cfg.lifetimeFrames < 0xa)
            cfg.lifetimeFrames = 0xa;
        if (cfg.lifetimeFrames > 0x78)
            cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x201;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = 0xc9f;
        cfg.initialAlpha = 0x60;
        break;
    case 0x203:
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        cfg.startPosY = spawnParams->posY;
        cfg.velocityY = 0.005f;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = (f32)randomGetRange((s16)(s32)-spawnParams->posZ, (s16)(s32)spawnParams->posZ);
            break;
        case 1:
            cfg.startPosX = -spawnParams->posX;
            cfg.startPosZ = (f32)randomGetRange((s16)(s32)-spawnParams->posZ, (s16)(s32)spawnParams->posZ);
            break;
        case 2:
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = (f32)randomGetRange((s16)(s32)-spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        case 3:
            cfg.startPosZ = -spawnParams->posZ;
            cfg.startPosX = (f32)randomGetRange((s16)(s32)-spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        }
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x184;
        cfg.initialAlpha = 0xc4;
        break;
    case 0x204:
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        cfg.startPosY = spawnParams->posY;
        cfg.velocityY = 0.005f;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = (f32)randomGetRange((s16)(s32)-spawnParams->posZ, (s16)(s32)spawnParams->posZ);
            break;
        case 1:
            cfg.startPosX = -spawnParams->posX;
            cfg.startPosZ = (f32)randomGetRange((s16)(s32)-spawnParams->posZ, (s16)(s32)spawnParams->posZ);
            break;
        case 2:
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = (f32)randomGetRange((s16)(s32)-spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        case 3:
            cfg.startPosZ = -spawnParams->posZ;
            cfg.startPosX = (f32)randomGetRange((s16)(s32)-spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        }
        cfg.velocityY = 0.0045f * (f32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.00002f * (f32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400110;
        cfg.textureId = 0x47;
        break;
    case 0x205:
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        cfg.startPosY = spawnParams->posY;
        cfg.velocityY = 0.005f;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = (f32)randomGetRange((s16)(s32)-spawnParams->posZ, (s16)(s32)spawnParams->posZ);
            break;
        case 1:
            cfg.startPosX = -spawnParams->posX;
            cfg.startPosZ = (f32)randomGetRange((s16)(s32)-spawnParams->posZ, (s16)(s32)spawnParams->posZ);
            break;
        case 2:
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = (f32)randomGetRange((s16)(s32)-spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        case 3:
            cfg.startPosZ = -spawnParams->posZ;
            cfg.startPosX = (f32)randomGetRange((s16)(s32)-spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        }
        cfg.velocityY = 0.0045f * (f32)randomGetRange(0x28, 0x50);
        cfg.scale = 0.0002f * (f32)randomGetRange(0x1e, 0x32);
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0x9b;
        cfg.renderFlags = 0x20;
        cfg.behaviorFlags = 0x180210;
        cfg.colorWord0 = randomGetRange(0, 0x7530) + 0x63bf;
        cfg.colorWord1 = cfg.colorWord0 / (int)randomGetRange(1, 3);
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = randomGetRange(0, 0x2710);
        cfg.overrideColor1 = (int)cfg.overrideColor0 / (int)randomGetRange(1, 3);
        cfg.overrideColor2 = 0;
        cfg.textureId = 0x60;
        break;
    case 0x206:
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        cfg.startPosY = spawnParams->posY - 12.0f;
        cfg.velocityY = 0.005f;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = (f32)randomGetRange((s16)(s32)-spawnParams->posZ, (s16)(s32)spawnParams->posZ);
            break;
        case 1:
            cfg.startPosX = -spawnParams->posX;
            cfg.startPosZ = (f32)randomGetRange((s16)(s32)-spawnParams->posZ, (s16)(s32)spawnParams->posZ);
            break;
        case 2:
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = (f32)randomGetRange((s16)(s32)-spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        case 3:
            cfg.startPosZ = -spawnParams->posZ;
            cfg.startPosX = (f32)randomGetRange((s16)(s32)-spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        }
        cfg.velocityY = 0.0025f * (f32)randomGetRange(0x50, 0x64);
        cfg.scale = 0.0004f * (f32)randomGetRange(0x1e, 0x32);
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080110;
        cfg.textureId = 0x60;
        break;
    case 0x208:
        cfg.startPosX = 0.1f * (f32)randomGetRange(-0xbb8, 0xbb8);
        cfg.startPosY = 200.0f;
        cfg.startPosZ = 0.1f * (f32)randomGetRange(-0xbb8, 0xbb8);
        cfg.velocityY = -0.003f * (f32)randomGetRange(0x190, 0x258);
        cfg.velocityX = 0.0003f * (f32)randomGetRange(-0x64, 0x64);
        cfg.velocityZ = 0.0003f * (f32)randomGetRange(-0x64, 0x64);
        cfg.scale = 0.0001f * (f32)randomGetRange(0, 0xa) + 0.0035f;
        cfg.lifetimeFrames = 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080000;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0xe7;
        break;
    case 0x209:
        cfg.startPosY = (f32)randomGetRange(1, 5);
        cfg.velocityY = 0.04f * (f32)randomGetRange(0xa, 0x14);
        cfg.scale = 2.0f * (0.0002f * (f32)randomGetRange(0, 0xa) + 0.0004245f);
        cfg.lifetimeFrames = randomGetRange(0x73, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xc0d;
        break;
    case 0x20a:
    {
        f32 speed;
        f32 horizSpeed;
        if (spawnParams == 0)
            spawnParams = Effect3_getDefaultSpawnParams();
        cfg.startPosX = (f32)randomGetRange(-5, 5);
        cfg.startPosY = (f32)randomGetRange(1, 5);
        cfg.startPosZ = (f32)randomGetRange(-5, 5);
        speed = 0.003f * (f32)randomGetRange(0, 0x258) + 2.3f;
        cfg.velocityY = 0.001f * (f32)randomGetRange(0, 0xc8) + 1.0f;
        cfg.velocityX = mathSinf(3.1415927f * (f32)*sourceObj / 32768.0f);
        cfg.velocityZ = mathCosf(3.1415927f * (f32)*sourceObj / 32768.0f);
        horizSpeed = speed * (0.015f * (f32)randomGetRange(0, 0x14)) + 0.1f;
        cfg.velocityX *= horizSpeed;
        cfg.velocityZ *= horizSpeed;
        cfg.velocityY *= speed;
        cfg.scale = 0.00006f * (f32)randomGetRange(0, 0xa) + 0.0048f;
        cfg.lifetimeFrames = randomGetRange(0xb4, 0xc8);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x3000120;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0xc0a;
        cfg.quadVertex3Pad06 = 0x20b;
    }
    break;
    case 0x20b:
        cfg.velocityY = 0.002f * (f32)randomGetRange(2, 0x14);
        cfg.scale = 0.008445f;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = randomGetRange(0, 0xc350) + 0x3caf;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        break;
    case 0x20c:
        cfg.startPosX = (f32)randomGetRange(-0x37, 0x37);
        cfg.startPosY = (f32)randomGetRange(0xa, 0xf);
        cfg.startPosZ = (f32)randomGetRange(-0x37, 0x37);
        cfg.velocityX = 0.01f * (f32)randomGetRange(-8, 8);
        cfg.velocityY = 0.1f * (f32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.01f * (f32)randomGetRange(-8, 8);
        cfg.scale = 0.0002f * (f32)randomGetRange(0, 0xa) + 0.0028945f;
        cfg.lifetimeFrames = randomGetRange(0x78, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x20b;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x1001100;
        cfg.textureId = 0xc0a;
        break;
    case 0x20d:
        cfg.velocityX = 0.007f * (f32)randomGetRange(-0x32, 0x32);
        cfg.velocityY = 0.0017f * (f32)randomGetRange(-0xa, 0xa);
        cfg.velocityZ = 0.007f * (f32)randomGetRange(-0x32, 0x32);
        cfg.startPosY = 0.1f * (f32)randomGetRange(0, 0x190);
        cfg.scale = 0.0003f * (f32)randomGetRange(0xf, 0x19);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0x4a0104;
        cfg.renderFlags = 0x40008;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourceVecX = 0x46;
        cfg.sourceVecY = 0;
        cfg.sourceVecZ = 0;
        cfg.sourcePosX = 1.0f;
        cfg.textureId = 0xe0;
        break;
    case 0x20e:
        cfg.startPosY = 200.0f;
        cfg.scale = 0.002f;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11800004;
        cfg.initialAlpha = 0xa0;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x200;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags |= spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0))
        cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0)
        {
            cfg.startPosX += cfg.sourcePosY;
            cfg.startPosY += cfg.sourcePosZ;
            cfg.startPosZ += cfg.sourcePosW;
        }
        else
        {
            if (cfg.attachedSource != 0)
            {
                cfg.startPosX += ((GameObject*)cfg.attachedSource)->anim.worldPosX;
                cfg.startPosY += ((GameObject*)cfg.attachedSource)->anim.worldPosY;
                cfg.startPosZ += ((GameObject*)cfg.attachedSource)->anim.worldPosZ;
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}
void Effect3_func05_nop(void)
{
}

void Effect3_func03_nop(void)
{
}

void Effect3_release(void)
{
}

void Effect3_initialise(void)
{
}
