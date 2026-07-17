/*
 * effect9 (DLL 0x22) - particle / model-graphics effects support DLL.
 *
 * Three subsystems share this object:
 *  - modgfx: per-vertex animation of an active model effect. Double-buffered
 *    vertex tables (active/inactive) drive texcoord scrolling, RGB/alpha/scale
 *    blends and rotation/position stepping over a frame countdown
 *    (modgfx_* functions). modgfx_alloc/releaseExpgfxPools own the expgfx slot
 *    pools (EXPGFX_POOL_COUNT) and the active-effect registry
 *    (MODGFX_ACTIVE_EFFECT_COUNT entries).
 *  - projgfx: an ObjectDescriptor11 (projgfx_funcs) whose callbacks are mostly
 *    no-ops; the spawner-side lives in projgfx_spawnPresetEffect, a switch over
 *    preset effect ids 0x422-0x42d (decimal 1058-1069) that fills an
 *    ExpgfxSpawnConfig (random
 *    velocity/scale/lifetime/color per preset) and hands it to
 *    gExpgfxInterface->spawnEffect.
 *  - Effect9: preset-effect spawner (Effect9_func04, switch over effectId-949)
 *    plus a per-frame animation tick (Effect9_func05).
 */
#include "main/dll/partfx_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/frame_timing.h"
#include "main/object_descriptor.h"
#include "main/vecmath.h"
#include "main/dll/modgfx.h"
#include "main/dll/dll_0022_effect9.h"

f32 gEffect9SineFast;
f32 gEffect9SineSlow;
int gEffect9SineAngleSlow;
int gEffect9SineAngleFast;

f32 gEffect9PhaseA = 0.1f;
f32 gEffect9PhaseB = 0.3f;
f32 gEffect9PhaseC = 0.1f;
f32 gEffect9PhaseD = 0.3f;

extern FxNode9 lbl_8039C398;

ObjectDescriptor6 lbl_80310BD8 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)Effect9_initialise,
    (ObjectDescriptorCallback)Effect9_release,
    0,
    (ObjectDescriptorCallback)Effect9_func03_nop,
    (ObjectDescriptorCallback)Effect9_func04,
    (ObjectDescriptorCallback)Effect9_func05,
};

/*
 * FILL9 installs a zeroed default PartFxSpawnParams (lbl_8039C398) and points
 * spawnParams at it. It is only reached when spawnParams == 0, so the
 * immediately-following `if (spawnParams != 0)` is the non-null path (default
 * just installed) - not a contradiction.
 */
#define FILL9()                                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        lbl_8039C398.posX = 0.0f;                                                                                      \
        lbl_8039C398.posY = 0.0f;                                                                                      \
        lbl_8039C398.posZ = 0.0f;                                                                                      \
        lbl_8039C398.scale = 1.0f;                                                                                     \
        lbl_8039C398.unk0 = 0;                                                                                         \
        lbl_8039C398.unk2 = 0;                                                                                         \
        lbl_8039C398.unk4 = 0;                                                                                         \
        spawnParams = (PartFxSpawnParams*)&lbl_8039C398;                                                               \
    } while (0)

#pragma scheduling off
#pragma peephole off
int Effect9_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    gEffect9PhaseA += 0.001f;
    if (gEffect9PhaseA > 1.0f)
        gEffect9PhaseA = 0.1f;
    gEffect9PhaseB += 0.0003f;
    if (gEffect9PhaseB > 1.0f)
        gEffect9PhaseB = 0.3f;
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
    switch ((u32)effectId)
    {
    case 950:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = 0.0f;
            cfg.startPosZ = 0.0f;
        }
        cfg.startPosY = 0.0f;
        cfg.velocityY = 0.008f * (f32)(s32)randomGetRange(0xf, 0x23);
        cfg.scale = 0.00155f * (f32)(s32)randomGetRange(6, 0xa);
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80180100;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0x63bf;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xb1df;
        cfg.renderFlags = 0x20;
        break;
    case 949:
        cfg.startPosX = (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosY = 50.0f + (f32)(s32)randomGetRange(0x1e, 0x64);
        cfg.velocityX = 0.002f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityZ = 0.002f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.000001f * (f32)(s32)randomGetRange(0, 0x32);
        cfg.scale = 0.00005f * (f32)(s32)randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x81008000;
        cfg.quadVertex3Pad06 = 0x284;
        cfg.textureId = 0x208;
        break;
    case 955:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.scale = 0.003f;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8000201;
        cfg.textureId = 0x62;
        break;
    case 954:
        if (spawnParams == 0)
            FILL9();
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityY = 0.035f * (f32)(s32)randomGetRange(1, 4);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0, 0xa) + 0.0015f;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x63;
        break;
    case 972:
        cfg.velocityX = 0.005f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0x1e, 0x32);
        cfg.velocityZ = 0.005f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.startPosX = 0.5f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosY = 0.5f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosZ = 0.5f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x1e;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0xa5;
        cfg.behaviorFlags = 0x180108;
        cfg.scale = 0.0006f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.textureId = 0x167;
        break;
    case 971:
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x1180100;
        cfg.textureId = 0x2b;
        break;
    case 970:
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0x1e, 0x32);
        cfg.velocityZ = 0.02f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0, 0x64) + 0.01f;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x46);
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x1180100;
        cfg.textureId = 0x2b;
        break;
    case 967:
        if (spawnParams != 0)
            cfg.startPosY = spawnParams->posY;
        cfg.scale = spawnParams != 0 ? 0.03f * spawnParams->scale : 0.11f;
        cfg.lifetimeFrames = 0xf;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x80210;
        cfg.textureId = 0x4f9;
        cfg.linkGroup = 0x20;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = 0xff00;
        cfg.overrideColor1 = 0xff00;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x2000020;
        break;
    case 962:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = 0.0f;
            cfg.startPosZ = 0.0f;
        }
        cfg.startPosY = 0.0f;
        cfg.scale = 0.00155f * (f32)(s32)randomGetRange(6, 0x14);
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80180108;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0x63bf;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xb1df;
        cfg.renderFlags = 0x20;
        break;
    case 960:
    case 961:
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = spawnParams->posZ;
        }
        else
        {
            cfg.startPosX = 0.0f;
            cfg.startPosZ = 0.0f;
        }
        cfg.velocityZ = -0.005f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityX = -0.005f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0, 0x28);
        cfg.initialAlpha = 0xff;
        cfg.scale = 0.0053f;
        cfg.lifetimeFrames = 0x8c;
        cfg.behaviorFlags = 0x81000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x26d;
        if ((int)randomGetRange(0, 3) == 3)
        {
            cfg.scale = 0.013f * (f32)(s32)randomGetRange(1, 4);
            cfg.behaviorFlags |= 0x100100LL;
            cfg.textureId = 0x2b;
            cfg.initialAlpha = 0x9b;
            effectId = 0x3c1;
        }
        break;
    case 966:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.velocityX = spawnParams->posX;
            cfg.velocityY = spawnParams->posY;
            cfg.velocityZ = spawnParams->posZ;
        }
        else
        {
            cfg.velocityX = 0.001f * (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(5, 0x64);
            cfg.velocityZ = 0.001f * (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x258, 0x258);
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosX = 0.0f;
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x28;
        cfg.behaviorFlags = 0x1080006;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xa0;
        break;
    case 965:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100201;
        cfg.textureId = 0x60;
        break;
    case 964:
        if (spawnParams == 0)
            FILL9();
        cfg.lifetimeFrames = (s32)(50.0f * spawnParams->scale + 20.0f);
        cfg.scale = 0.0008f * (f32)(s32)cfg.lifetimeFrames;
        cfg.behaviorFlags = 0xe100200;
        cfg.textureId = 0x57;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.sourcePosY = 0.0f;
        cfg.sourcePosZ = 0.0f;
        cfg.sourcePosW = 0.0f;
        cfg.sourceVecX = spawnParams->rotX;
        cfg.sourceVecY = 0;
        cfg.sourceVecZ = 0;
        break;
    case 963:
        if (spawnParams == 0)
            FILL9();
        if (spawnParams != 0)
        {
            cfg.velocityX = spawnParams->posX;
            cfg.velocityY = spawnParams->posY;
            cfg.velocityZ = spawnParams->posZ;
        }
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.scale = 0.01f;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x1080006;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xa0;
        break;
    case 969:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = 0.03f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.05f * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.velocityZ = 0.03f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosX = spawnParams != 0 ? spawnParams->posX : 0.0f;
        cfg.startPosY = spawnParams != 0 ? spawnParams->posY : 0.0f;
        cfg.startPosZ = spawnParams != 0 ? spawnParams->posZ : 0.0f;
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(-0x32, 0x32) + cfg.startPosY;
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x32, 0x32) + cfg.startPosX;
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x32, 0x32) + cfg.startPosZ;
        cfg.scale = 0.02f;
        cfg.lifetimeFrames = 0x14;
        cfg.behaviorFlags = 0x1080006;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xa0;
        break;
    case 958:
        cfg.velocityY = 0.0035f * (f32)(s32)randomGetRange(1, 4);
        cfg.scale = 0.0001f * (f32)(s32)randomGetRange(0, 0x3c) + 0.0035f;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80100201;
        cfg.textureId = 0x63;
        break;
    case 957:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(0x14, 0x1e);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x96, 0x96);
        cfg.startPosZ = spawnParams != 0 ? spawnParams->posZ : 0.0f;
        cfg.startPosY = spawnParams != 0 ? spawnParams->posY : -2.0f;
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x32, -0xa) + cfg.startPosZ;
        cfg.scale = 0.007f;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x108000e;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xbe;
        break;
    case 956:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = 0.005f * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.velocityZ = 0.001f * (f32)(s32)randomGetRange(0, 0x12c);
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xc8, 0xc8);
        cfg.scale = 0.003f * (f32)(s32)randomGetRange(4, 8);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x180108;
        cfg.textureId = 0x2b;
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
#undef FILL9

void Effect9_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect9PhaseC + (step = 0.001f * timeDelta);
    gEffect9PhaseC = sum;
    if (sum > 1.0f)
    {
        gEffect9PhaseC = 0.1f;
    }
    sum = gEffect9PhaseD + step;
    gEffect9PhaseD = sum;
    if (sum > 1.0f)
    {
        gEffect9PhaseD = 0.3f;
    }
    gEffect9SineAngleFast = gEffect9SineAngleFast + framesThisStep * 0x64;
    if (gEffect9SineAngleFast > 0x7fff)
    {
        gEffect9SineAngleFast = 0;
    }
    gEffect9SineFast = mathSinf(3.1415927f * (f32)(s16)gEffect9SineAngleFast / 32768.0f);
    gEffect9SineAngleSlow = gEffect9SineAngleSlow + framesThisStep * 0x32;
    if (gEffect9SineAngleSlow > 0x7fff)
    {
        gEffect9SineAngleSlow = 0;
    }
    gEffect9SineSlow = mathSinf(3.1415927f * (f32)(s16)gEffect9SineAngleSlow / 32768.0f);
}

void Effect9_func03_nop(void)
{
}

void Effect9_release(void)
{
}

void Effect9_initialise(void)
{
}
