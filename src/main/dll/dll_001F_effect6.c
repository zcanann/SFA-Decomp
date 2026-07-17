/*
 * effect6 (DLL 0x1F) - a particle-effect object DLL.
 *
 * The two functions this TU actually owns are Effect6_func04 and
 * Effect6_func05. Effect6_func04 is the preset spawner: given an
 * effectId in 0x422..0x42d it fills a PartFxSpawn request (texture,
 * lifetime, randomised start position / velocity / scale, colour and
 * behaviour flags) and dispatches it through
 * gExpgfxInterface->spawnEffect; effects with the world-space-attach
 * behaviour bit have their start position offset by the source object's
 * world position. Effect6_func05 advances this DLL's per-frame animation
 * globals (two texcoord-scroll phases that wrap at 1.0, and two sine
 * oscillators driven from frame-stepped angle accumulators).
 *
 * The remaining modgfx and projgfx code is shared engine reference that
 * lives canonically in modgfx.c; only the two Effect6 symbols above
 * are compared against the target object.
 */
#include "main/dll/partfx_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/dll/modgfx.h"
#include "main/dll/dll_001F_effect6.h"

f32 gEffect6Osc0Value;
f32 gEffect6Osc1Value;
int gEffect6Osc1Angle;
int gEffect6Osc0Angle;

f32 gEffect6ScrollPhase0 = 0.1f;
f32 gEffect6ScrollPhase1 = 0.3f;
f32 gEffect6ScrollPhase2 = 0.1f;
f32 gEffect6ScrollPhase3 = 0.3f;

extern f32 gEffect6ScrollPhase2;
extern f32 gEffect6ScrollPhase3;
extern int gEffect6Osc0Angle;
extern int gEffect6Osc1Angle;
extern f32 gEffect6Osc1Value;
extern f32 gEffect6Osc0Value;
extern f32 gEffect6ScrollPhase0;
extern f32 gEffect6ScrollPhase1;

ObjectDescriptor6 lbl_80310A20 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)Effect6_initialise,
    (ObjectDescriptorCallback)Effect6_release,
    NULL,
    (ObjectDescriptorCallback)Effect6_func03_nop,
    (ObjectDescriptorCallback)Effect6_func04,
    (ObjectDescriptorCallback)Effect6_func05,
};


#pragma peephole off
#pragma scheduling off
/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */
int Effect6_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   u16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    gEffect6ScrollPhase0 += 0.001f;
    if (gEffect6ScrollPhase0 > 1.0f)
        gEffect6ScrollPhase0 = 0.1f;
    gEffect6ScrollPhase1 += 0.0003f;
    if (gEffect6ScrollPhase1 > 1.0f)
        gEffect6ScrollPhase1 = 0.3f;
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
    case 0x422:
        if (extraArgs == 0)
            return 0;
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = randomGetRange(0xa, 0xd);
        cfg.initialAlpha = (u8)*extraArgs;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x64;
        cfg.linkGroup = 0x1e;
        break;
    case 0x423:
        cfg.startPosX = 0.3f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosY = 0.3f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosZ = 0.3f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.001f * (f32)(s32)randomGetRange(5, 0xb);
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80110;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x424:
        cfg.startPosX = 0.3f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosY = 0.3f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosZ = 0.3f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityX = 0.1f * (f32)(s32)randomGetRange(-5, 5);
        cfg.velocityY = 0.1f * (f32)(s32)randomGetRange(3, 0xa);
        cfg.velocityZ = 0.1f * (f32)(s32)randomGetRange(-5, 5);
        cfg.scale = 0.0005f * (f32)(s32)randomGetRange(5, 0xb);
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x1480200;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x425:
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(8, 0xa);
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
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x1000020;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x7f;
        cfg.colorWord2 = 0x3fff;
        cfg.colorWord1 = 0x3fff;
        cfg.colorWord0 = 0x3fff;
        cfg.overrideColor2 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        break;
    case 0x426:
        cfg.velocityX = 0.05f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(8, 0x14);
        cfg.velocityZ = 0.05f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.003f;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x3000200;
        cfg.renderFlags = 0x200020;
        cfg.textureId = 0x33;
        cfg.initialAlpha = 0xff;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = cfg.overrideColor2 = randomGetRange(0, 0x8000);
        break;
    case 0x427:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x64, 0x64) / 20.0f;
        cfg.startPosY = (f32)(s32)randomGetRange(-0x32, 0x32) / 10.0f;
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x64, 0x64) / 20.0f;
        cfg.velocityY = 0.035f * (f32)(s32)randomGetRange(1, 4);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0, 0xa) + 0.0015f;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x33;
        break;
    case 0x42b:
        if (extraArgs == 0)
            return 0;
        cfg.scale = 0.013f;
        cfg.lifetimeFrames = randomGetRange(0xa, 0xd);
        cfg.initialAlpha = (u8)*extraArgs;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0xc7e;
        cfg.linkGroup = 0x1e;
        break;
    case 0x42c:
        cfg.velocityX = 0.025f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x6e;
        cfg.behaviorFlags = 0x8A100208;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x400;
        cfg.overrideColor1 = 0xEA60;
        cfg.overrideColor2 = 0x1000;
        break;
    case 0x42d:
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0xA100100;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0x400;
        cfg.colorWord1 = 0xEA60;
        cfg.colorWord2 = 0x1000;
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = 0xC350;
        cfg.overrideColor2 = 0;
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

void Effect6_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect6ScrollPhase2 + (step = 0.001f * timeDelta);
    gEffect6ScrollPhase2 = sum;
    if (sum > 1.0f)
    {
        gEffect6ScrollPhase2 = 0.1f;
    }
    sum = gEffect6ScrollPhase3 + step;
    gEffect6ScrollPhase3 = sum;
    if (sum > 1.0f)
    {
        gEffect6ScrollPhase3 = 0.3f;
    }
    gEffect6Osc0Angle = gEffect6Osc0Angle + framesThisStep * 0x64;
    if (gEffect6Osc0Angle > 0x7fff)
    {
        gEffect6Osc0Angle = 0;
    }
    gEffect6Osc0Value = mathSinf(3.1415927f * (f32)(s16)gEffect6Osc0Angle / 32768.0f);
    gEffect6Osc1Angle = gEffect6Osc1Angle + framesThisStep * 0x32;
    if (gEffect6Osc1Angle > 0x7fff)
    {
        gEffect6Osc1Angle = 0;
    }
    gEffect6Osc1Value = mathSinf(3.1415927f * (f32)(s16)gEffect6Osc1Angle / 32768.0f);
}

#pragma peephole reset
#pragma scheduling reset
void Effect6_func03_nop(void)
{
}

void Effect6_release(void)
{
}

void Effect6_initialise(void)
{
}

