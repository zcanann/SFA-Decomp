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
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/dll/DR/dr_shared.h"

void Effect9_func03_nop(void)
{
}

void Effect9_release(void)
{
}

void Effect9_initialise(void)
{
}

ObjectDescriptor11 projgfx_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
    projgfx_initialise,
    (ObjectDescriptorCallback)projgfx_release_doUnsupported,
    0,
    projgfx_onMapSetup,
    (ObjectDescriptorCallback)projgfx_func04_ret_m1,
    (ObjectDescriptorCallback)projgfx_func05_nop,
    (ObjectDescriptorCallback)projgfx_func06_nop,
    (ObjectDescriptorCallback)projgfx_func07_nop,
    (ObjectDescriptorCallback)projgfx_getObjectTypeId,
    (ObjectDescriptorCallback)projgfx_setzscale_doUnsupported,
    (ObjectDescriptorCallback)projgfx_rayhit_doUnsupported,
};

char sProjgfxRayhitDoNoLongerSupported[] = "<projgfx rayhit Do>No Longer supported \n";
static u8 sProjgfxStringPad0[] = {0, 0, 0};
char sProjgfxSetzscaleDoNoLongerSupported[] = "<projgfx setzscale  Do>No Longer supported \n";
static u8 sProjgfxStringPad1[] = {0, 0, 0};
char sProjgfxReleaseDoNoLongerSupported[] = "<projgfx release Do>No Longer supported \n";
static u8 sProjgfxStringPad2[] = {0, 0, 0, 0, 0, 0};


extern f32 gEffect9PhaseC;
extern f32 gEffect9PhaseD;
extern int gEffect9SineAngleFast;
extern int gEffect9SineAngleSlow;
extern f32 gEffect9SineSlow;
extern f32 gEffect9SineFast;
extern f32 lbl_803DFE28;
extern f32 lbl_803DFE2C;
extern f32 lbl_803DFE38;
extern f32 gEffect9Pi;
extern f32 gEffect9SineAngleScale;
extern FxNode9 lbl_8039C398;
extern f32 gEffect9PhaseA;
extern f32 gEffect9PhaseB;
extern f32 lbl_803DFE34;
extern f32 lbl_803DFE40;
extern f32 lbl_803DFE44;
extern f32 lbl_803DFE48;
extern f32 lbl_803DFE4C;
extern f32 lbl_803DFE50;
extern f32 lbl_803DFE54;
extern f32 lbl_803DFE58;
extern f32 lbl_803DFE5C;
extern f32 lbl_803DFE60;
extern f32 lbl_803DFE64;
extern f32 lbl_803DFE68;
extern f32 lbl_803DFE6C;
extern f32 lbl_803DFE70;
extern f32 lbl_803DFE74;
extern f32 lbl_803DFE78;
extern f32 lbl_803DFE7C;
extern f32 lbl_803DFE80;
extern f32 lbl_803DFE84;
extern f32 lbl_803DFE88;
extern f32 lbl_803DFE8C;
extern f32 lbl_803DFE90;
extern f32 lbl_803DFE94;
extern f32 lbl_803DFE98;
extern f32 lbl_803DFE9C;
extern f32 lbl_803DFEA0;
extern f32 lbl_803DFEA4;

/*
 * FILL9 installs a zeroed default PartFxSpawnParams (lbl_8039C398) and points
 * spawnParams at it. It is only reached when spawnParams == 0, so the
 * immediately-following `if (spawnParams != 0)` is the non-null path (default
 * just installed) - not a contradiction.
 */
#define FILL9() do {                            \
    lbl_8039C398.posX = 0.0f;             \
    lbl_8039C398.posY = 0.0f;            \
    lbl_8039C398.posZ = 0.0f;            \
    lbl_8039C398.scale = 1.0f;             \
    lbl_8039C398.unk0 = 0;                         \
    lbl_8039C398.unk2 = 0;                         \
    lbl_8039C398.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C398;             \
  } while (0)

#pragma scheduling off
#pragma peephole off
int Effect9_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    gEffect9PhaseA = gEffect9PhaseA + lbl_803DFE28;
    if (gEffect9PhaseA > 1.0f) gEffect9PhaseA = lbl_803DFE2C;
    gEffect9PhaseB = gEffect9PhaseB + lbl_803DFE34;
    if (gEffect9PhaseB > 1.0f) gEffect9PhaseB = lbl_803DFE38;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
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
        cfg.velocityY = lbl_803DFE40 * (f32)(s32)
        randomGetRange(0xf, 0x23);
        cfg.scale = lbl_803DFE44 * (f32)(s32)
        randomGetRange(6, 0xa);
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
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFE48 + (f32)(s32)
        randomGetRange(0x1e, 0x64);
        cfg.velocityX = lbl_803DFE4C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFE4C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFE50 * (f32)(s32)
        randomGetRange(0, 0x32);
        cfg.scale = lbl_803DFE54 * (f32)(s32)
        randomGetRange(0x14, 0x50);
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
        cfg.scale = lbl_803DFE58;
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
        cfg.velocityY = lbl_803DFE5C * (f32)(s32)
        randomGetRange(1, 4);
        cfg.scale = lbl_803DFE64 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFE60;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x63;
        break;
    case 972:
        cfg.velocityX = lbl_803DFE68 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803DFE68 * (f32)(s32)
        randomGetRange(0x1e, 0x32);
        cfg.velocityZ = lbl_803DFE68 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosX = lbl_803DFE6C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803DFE6C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFE6C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.lifetimeFrames = randomGetRange(0, 0x14) + 0x1e;
        cfg.linkGroup = 0;
        cfg.initialAlpha = 0xa5;
        cfg.behaviorFlags = 0x180108;
        cfg.scale = lbl_803DFE70 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.textureId = 0x167;
        break;
    case 971:
        cfg.scale = lbl_803DFE74;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x1180100;
        cfg.textureId = 0x2b;
        break;
    case 970:
        cfg.velocityX = lbl_803DFE78 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803DFE78 * (f32)(s32)
        randomGetRange(0x1e, 0x32);
        cfg.velocityZ = lbl_803DFE78 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803DFE64 * (f32)(s32)
        randomGetRange(0, 0x64) + lbl_803DFE74;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x46);
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x1180100;
        cfg.textureId = 0x2b;
        break;
    case 967:
        if (spawnParams != 0) cfg.startPosY = spawnParams->posY;
        cfg.scale = spawnParams != 0 ? lbl_803DFE7C * spawnParams->scale : lbl_803DFE80;
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
        cfg.scale = lbl_803DFE44 * (f32)(s32)
        randomGetRange(6, 0x14);
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
        cfg.velocityZ = lbl_803DFE84 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityX = lbl_803DFE84 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFE68 * (f32)(s32)
        randomGetRange(0, 0x28);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803DFE88;
        cfg.lifetimeFrames = 0x8c;
        cfg.behaviorFlags = 0x81000000;
        cfg.renderFlags = 0x200000;
        cfg.textureId = 0x26d;
        if ((int)randomGetRange(0, 3) == 3)
        {
            cfg.scale = lbl_803DFE8C * (f32)(s32)
            randomGetRange(1, 4);
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
            cfg.velocityX = lbl_803DFE28 * (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.velocityY = lbl_803DFE74 * (f32)(s32)
            randomGetRange(5, 0x64);
            cfg.velocityZ = lbl_803DFE28 * (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.startPosY = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x258, 0x258);
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosX = 0.0f;
        cfg.scale = lbl_803DFE78;
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
        cfg.scale = lbl_803DFE78;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x8100201;
        cfg.textureId = 0x60;
        break;
    case 964:
        if (spawnParams == 0)
            FILL9();
        cfg.lifetimeFrames = (s32)(lbl_803DFE48 * spawnParams->scale + lbl_803DFE90);
        cfg.scale = lbl_803DFE94 * (f32)(s32)
        cfg.lifetimeFrames;
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
        cfg.startPosY = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DFE74;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x1080006;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xa0;
        break;
    case 969:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = lbl_803DFE7C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFE98 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityZ = lbl_803DFE7C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosX = spawnParams != 0 ? spawnParams->posX : 0.0f;
        cfg.startPosY = spawnParams != 0 ? spawnParams->posY : 0.0f;
        cfg.startPosZ = spawnParams != 0 ? spawnParams->posZ : 0.0f;
        cfg.startPosY = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x32, 0x32) + cfg.startPosY;
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x32, 0x32) + cfg.startPosX;
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x32, 0x32) + cfg.startPosZ;
        cfg.scale = lbl_803DFE78;
        cfg.lifetimeFrames = 0x14;
        cfg.behaviorFlags = 0x1080006;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xa0;
        break;
    case 958:
        cfg.velocityY = lbl_803DFE9C * (f32)(s32)
        randomGetRange(1, 4);
        cfg.scale = lbl_803DFE64 * (f32)(s32)
        randomGetRange(0, 0x3c) + lbl_803DFE9C;
        cfg.lifetimeFrames = 0xa0;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80100201;
        cfg.textureId = 0x63;
        break;
    case 957:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = lbl_803DFE74 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFE78 * (f32)(s32)
        randomGetRange(0x14, 0x1e);
        cfg.velocityZ = lbl_803DFE74 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x96, 0x96);
        cfg.startPosZ = spawnParams != 0 ? spawnParams->posZ : 0.0f;
        cfg.startPosY = spawnParams != 0 ? spawnParams->posY : lbl_803DFEA0;
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0x32, -0xa) + cfg.startPosZ;
        cfg.scale = lbl_803DFEA4;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x108000e;
        cfg.textureId = 0x60;
        cfg.initialAlpha = 0xbe;
        break;
    case 956:
        if (spawnParams == 0)
            FILL9();
        cfg.velocityX = lbl_803DFE68 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFE68 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFE28 * (f32)(s32)
        randomGetRange(0, 0x12c);
        cfg.startPosX = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.startPosZ = lbl_803DFE2C * (f32)(s32)
        randomGetRange(-0xc8, 0xc8);
        cfg.scale = lbl_803DFE58 * (f32)(s32)
        randomGetRange(4, 8);
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
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
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
    sum = gEffect9PhaseC + (step = lbl_803DFE28 * timeDelta);
    gEffect9PhaseC = sum;
    if (sum > 1.0f)
    {
        gEffect9PhaseC = lbl_803DFE2C;
    }
    sum = gEffect9PhaseD + step;
    gEffect9PhaseD = sum;
    if (sum > 1.0f)
    {
        gEffect9PhaseD = lbl_803DFE38;
    }
    gEffect9SineAngleFast = gEffect9SineAngleFast + framesThisStep * 0x64;
    if (gEffect9SineAngleFast > 0x7fff)
    {
        gEffect9SineAngleFast = 0;
    }
    gEffect9SineFast = mathSinf(gEffect9Pi * (f32)(s16)gEffect9SineAngleFast / gEffect9SineAngleScale);
    gEffect9SineAngleSlow = gEffect9SineAngleSlow + framesThisStep * 0x32;
    if (gEffect9SineAngleSlow > 0x7fff)
    {
        gEffect9SineAngleSlow = 0;
    }
    gEffect9SineSlow = mathSinf(gEffect9Pi * (f32)(s16)gEffect9SineAngleSlow / gEffect9SineAngleScale);
}
