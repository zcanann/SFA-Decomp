/*
 * effect7 (DLL 0x20) - a particle/effect spawner DLL exposing the
 * projgfx_funcs ObjectDescriptor. Effect7_func04 is the spawn entry
 * point: given an effectId (0x84..0xab range) it fills a PartFxSpawn
 * request - velocities, start positions, scale and lifetime randomised
 * per effect via randomGetRange - and submits it through
 * gExpgfxInterface->spawnEffect. Effect7_func05 advances per-frame the
 * shared scroll/sine animation globals used by the effects. Most other
 * fns here (the modgfx and projgfx families) are drift duplicates of
 * dll_000C_projgfx.c.
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
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/dll/modgfx.h"
#include "main/maketex_random_api.h"
#include "main/dll/dll_0020_effect7.h"

f32 gEffect7SinValueA;
f32 gEffect7SinValueB;
int gEffect7SinAngleB;
int gEffect7SinAngleA;

f32 gEffect7ScrollPhaseA = 0.1f;
f32 gEffect7ScrollPhaseB = 0.3f;
f32 gEffect7TexScrollPhaseA = 0.1f;
f32 gEffect7TexScrollPhaseB = 0.3f;

extern FxNode9 lbl_8039C368;

ObjectDescriptor6 lbl_80310A78 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_6_SLOTS,
    (ObjectDescriptorCallback)Effect7_initialise,
    (ObjectDescriptorCallback)Effect7_release,
    0,
    (ObjectDescriptorCallback)Effect7_func03_nop,
    (ObjectDescriptorCallback)Effect7_func04,
    (ObjectDescriptorCallback)Effect7_func05,
};


#define FILL368()                                                                                                      \
    do                                                                                                                 \
    {                                                                                                                  \
        lbl_8039C368.posX = 0.0f;                                                                              \
        lbl_8039C368.posY = 0.0f;                                                                              \
        lbl_8039C368.posZ = 0.0f;                                                                              \
        lbl_8039C368.scale = 1.0f;                                                                             \
        lbl_8039C368.unk0 = 0;                                                                                         \
        lbl_8039C368.unk2 = 0;                                                                                         \
        lbl_8039C368.unk4 = 0;                                                                                         \
        spawnParams = (PartFxSpawnParams*)&lbl_8039C368;                                                               \
    } while (0)

int Effect7_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags, u8 modelId,
                   s16* extraArgs)
{
    int spawnResult;
    void* player;
    PartFxSpawn cfg;

    player = Obj_GetPlayerObject();
    gEffect7ScrollPhaseA += 0.001f;
    if (gEffect7ScrollPhaseA > 1.0f)
        gEffect7ScrollPhaseA = 0.1f;
    gEffect7ScrollPhaseB += 0.0003f;
    if (gEffect7ScrollPhaseB > 1.0f)
        gEffect7ScrollPhaseB = 0.3f;
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
    case 0xae:
        cfg.velocityX = 0.0004f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = -0.0025f * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.velocityY = 0.0004f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.scale = 0.00007f * (f32)(s32)randomGetRange(0x1e, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x88;
        break;
    case 0xaf:
        cfg.velocityX = 0.0024f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = -0.0025f * (f32)(s32)randomGetRange(0x1e, 0x28);
        cfg.velocityY = 0.0024f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.scale = 0.0000042f * (f32)(s32)randomGetRange(0x3c, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x400000;
        cfg.renderFlags = 8;
        cfg.textureId = 0xe4;
        break;
    case 0xad:
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = 0.09f * (f32)(s32)randomGetRange(6, 0x16);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.scale = 0.0042f;
        cfg.lifetimeFrames = 0x91;
        cfg.initialAlpha = 0xff;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = (u16)(randomGetRange(0, 0x2710) + 0x3caf);
        cfg.colorWord2 = 0x3caf;
        cfg.overrideColor0 = 0xf52f;
        cfg.overrideColor1 = 0xf52f;
        cfg.overrideColor2 = 0xf52f;
        cfg.behaviorFlags = 0x3000020;
        cfg.renderFlags = 0x2600020;
        cfg.textureId = 0xe4;
        break;
    case 0xac:
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.startPosY = 0.0f;
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.velocityX = 0.01f * (f32)(s32)randomGetRange(-8, 8);
        cfg.velocityY = 0.03f * (f32)(s32)randomGetRange(9, 0xc);
        cfg.velocityZ = 0.01f * (f32)(s32)randomGetRange(-8, 8);
        cfg.scale = 0.002f * (f32)(s32)randomGetRange(0xa, 0xf);
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x5f;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x60;
        cfg.colorWord0 = 0x3caf;
        cfg.colorWord1 = 0x3caf;
        cfg.colorWord2 = 0x3caf;
        cfg.overrideColor0 = 0xa70f;
        cfg.overrideColor1 = 0xa70f;
        cfg.overrideColor2 = 0xa70f;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80180100;
        cfg.renderFlags = 0x20;
        break;
    case 0x84:
        cfg.velocityX = 0.015f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.01f * (f32)(s32)randomGetRange(4, 0xa);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = 0.0005f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1400211;
        cfg.textureId = 0xdf;
        break;
    case 0x85:
        if (extraArgs == 0)
            return 0;
        cfg.startPosX = ((GameObject*)player)->anim.worldPosX;
        cfg.startPosY = ((GameObject*)player)->anim.worldPosY;
        cfg.startPosZ = ((GameObject*)player)->anim.worldPosZ;
        cfg.scale = 4.55f;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x110;
        cfg.textureId = spawnParams->unk4 + 0x170;
        break;
    case 0x8a:
        cfg.startPosX = -750.0f;
        cfg.startPosY = (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityX = 6.0f;
        cfg.scale = 0.0015f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x10e;
        cfg.linkGroup = 0x10;
        cfg.initialAlpha = 0xf;
        cfg.behaviorFlags = 0x2000011;
        cfg.textureId = 0x5f;
        break;
    case 0x8b:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x78, 0x78);
        cfg.startPosY = (f32)(s32)randomGetRange(-0x78, 0x78);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x78, 0x78);
        cfg.velocityX = 0.035f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.035f * (f32)(s32)randomGetRange(4, 0xa);
        cfg.velocityZ = 0.035f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = 0.00055f * (f32)(s32)randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x378;
        cfg.behaviorFlags = 0x80000119;
        cfg.textureId = 0x125;
        break;
    case 0x8e:
        cfg.velocityX = 0.005f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.005f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityZ = 0.005f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = 0.005f;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100110;
        cfg.textureId = 0x30;
        break;
    case 0x8f:
        cfg.startPosX = (f32)(s32)randomGetRange(-6, 6);
        cfg.startPosY = (f32)(s32)randomGetRange(-6, 6);
        cfg.startPosZ = (f32)(s32)randomGetRange(-6, 6);
        cfg.velocityX = 0.025f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.025f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityZ = 0.025f * (f32)(s32)randomGetRange(-0x28, 0x28);
        if ((int)randomGetRange(0, 0xc) == 0)
        {
            cfg.scale = 0.00155f * (f32)(s32)randomGetRange(0xf, 0x1e);
            cfg.initialAlpha = 0x5f;
        }
        else
        {
            cfg.scale = 0.000115f * (f32)(s32)randomGetRange(0xf, 0x1e);
            cfg.initialAlpha = 0xff;
        }
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x400108;
        cfg.textureId = 0x33;
        break;
    case 0x9a:
        cfg.startPosX = 100.0f;
        cfg.startPosY = 135.0f + (f32)(s32)randomGetRange(-0x42, 0x42);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x42, 0x42);
        cfg.scale = 0.01f * (f32)(s32)randomGetRange(1, 0xa);
        cfg.lifetimeFrames = randomGetRange(0x50, 0x78);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x125;
        cfg.linkGroup = 5;
        break;
    case 0x9b:
        cfg.startPosX = (f32)(s32)randomGetRange(-0x42, 0x42);
        cfg.startPosY = 135.0f - (f32)(s32)randomGetRange(0, 0x42);
        cfg.startPosZ = (f32)(s32)randomGetRange(-0x60, 0x60);
        cfg.velocityY = 0.055f * (f32)(s32)randomGetRange(0, 0x28);
        cfg.scale = 0.006f * (f32)(s32)randomGetRange(0xa, 0x28);
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x125;
        break;
    case 0x9c:
        cfg.velocityX = 0.055f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityY = 0.055f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.velocityZ = 0.055f * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.scale = 0.0035f;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x110;
        cfg.textureId = 0xdd;
        break;
    case 0x9f:
        cfg.velocityX = 0.02f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.02f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityZ = 0.02f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = 0.006f;
        cfg.lifetimeFrames = randomGetRange(0x23, 0x4b);
        cfg.behaviorFlags = 0x81480000;
        cfg.renderFlags = 0x410800;
        cfg.textureId = 0x167;
        break;
    case 0xa0:
        if (spawnParams == 0)
            FILL368();
        cfg.startPosX = 0.1f * (f32)(s32)randomGetRange(-0x14, -0xa);
        cfg.startPosY = 0.1f * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.startPosZ = 0.1f * (f32)(s32)randomGetRange(-0xa, 0);
        cfg.initialAlpha = 0xff;
        if (spawnParams != 0)
        {
            cfg.startPosX = cfg.startPosX + spawnParams->posX;
            cfg.startPosY = cfg.startPosY + spawnParams->posY;
            cfg.startPosZ = cfg.startPosZ + spawnParams->posZ;
            if (1.0f == spawnParams->scale)
            {
                cfg.initialAlpha = 0xff;
            }
            else
            {
                cfg.initialAlpha = (u8)(s32)(255.0f * spawnParams->scale);
            }
        }
        cfg.scale = 0.00018f * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x2d;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x125;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0xa1:
        cfg.velocityY = 0.0002f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityX = 0.012f * (f32)(s32)randomGetRange(0x64, 0x96);
        cfg.startPosZ = 10.0f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.startPosY = 10.0f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = 0.0016f * (f32)(s32)randomGetRange(0x32, 0xc8);
        cfg.lifetimeFrames = 0x96;
        cfg.textureId = 0xc10;
        cfg.behaviorFlags = (u32)randomChanceOneIn;
        cfg.renderFlags = 0x4020020;
        cfg.initialAlpha = randomGetRange(0x7f, 0xff);
        cfg.colorWord0 = cfg.overrideColor0 = 0xa70f;
        cfg.colorWord1 = cfg.overrideColor1 = 0xa70f;
        cfg.colorWord2 = cfg.overrideColor2 = 0xc350;
        break;
    case 0xa3:
        if (spawnParams == 0)
            break;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityZ = 0.07f * (f32)(s32)randomGetRange(0x64, 0x78);
        cfg.scale = 0.0006f * (f32)(s32)randomGetRange(0x3c, 0x50);
        {
            int t = randomGetRange(0, 5);
            t += spawnParams->unk6;
            cfg.lifetimeFrames = t + 7;
        }
        cfg.textureId = 0x185;
        cfg.behaviorFlags = 0xc0080004;
        cfg.renderFlags = 0x4420800;
        break;
    case 0xa7:
        cfg.velocityX = 0.017f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityY = 0.017f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.velocityZ = 0.017f * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.scale = 0.0005f * (f32)(s32)randomGetRange(0x23, 0x32);
        cfg.lifetimeFrames = randomGetRange(0xa, 0x28) + 0xa;
        cfg.textureId = 0xc13;
        cfg.behaviorFlags = 0x81080010;
        cfg.renderFlags = 0x482800;
        break;
    case 0xa8:
        cfg.scale = 0.1f;
        cfg.lifetimeFrames = 0xe;
        cfg.behaviorFlags = 0x480100;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0x5fd;
        cfg.initialAlpha = 0x64;
        break;
    case 0xa9:
        if (spawnParams != 0)
        {
            cfg.scale = spawnParams->scale * (0.0005f * (f32)(s32)randomGetRange(0x4b, 0x64));
        }
        else
        {
            cfg.scale = 0.0005f * (f32)(s32)randomGetRange(0x4b, 0x64);
        }
        cfg.lifetimeFrames = 1;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0xc7e;
        cfg.initialAlpha = 0x96;
        break;
    case 0xaa:
        cfg.scale = 0.0008f * (f32)(s32)randomGetRange(0x96, 0xc8);
        cfg.lifetimeFrames = randomGetRange(0xf, 0x19);
        cfg.textureId = 0x185;
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x4000000;
        cfg.initialAlpha = 0x96;
        break;
    case 0xab:
        cfg.scale = 0.0008f * (f32)(s32)randomGetRange(0x64, 0x96);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x2d);
        cfg.textureId = 0x185;
        cfg.behaviorFlags = 0x80180210;
        cfg.renderFlags = 0x4000800;
        break;
    case 0x8c:
    case 0x8d:
    case 0x9d:
    case 0x9e:
    case 0xa5:
    case 0xa6:
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
#undef FILL368

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

void Effect7_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect7TexScrollPhaseA + (step = 0.001f * timeDelta);
    gEffect7TexScrollPhaseA = sum;
    if (sum > 1.0f)
    {
        gEffect7TexScrollPhaseA = 0.1f;
    }
    sum = gEffect7TexScrollPhaseB + step;
    gEffect7TexScrollPhaseB = sum;
    if (sum > 1.0f)
    {
        gEffect7TexScrollPhaseB = 0.3f;
    }
    gEffect7SinAngleA = gEffect7SinAngleA + framesThisStep * 0x64;
    if (gEffect7SinAngleA > 0x7fff)
    {
        gEffect7SinAngleA = 0;
    }
    gEffect7SinValueA = mathSinf(3.1415927f * (f32)(s16)gEffect7SinAngleA / 32768.0f);
    gEffect7SinAngleB = gEffect7SinAngleB + framesThisStep * 0x32;
    if (gEffect7SinAngleB > 0x7fff)
    {
        gEffect7SinAngleB = 0;
    }
    gEffect7SinValueB = mathSinf(3.1415927f * (f32)(s16)gEffect7SinAngleB / 32768.0f);
}

void Effect7_func03_nop(void)
{
}

void Effect7_release(void)
{
}



void Effect7_initialise(void)
{
}
