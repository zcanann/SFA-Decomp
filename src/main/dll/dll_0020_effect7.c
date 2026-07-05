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
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/dll/DR/dr_shared.h"

void Effect7_func03_nop(void)
{
}

void Effect7_release(void)
{
}

void Effect7_initialise(void)
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

extern f32 gEffect7TexScrollPhaseA;
extern f32 gEffect7TexScrollPhaseB;
extern int gEffect7SinAngleA;
extern int gEffect7SinAngleB;
extern f32 gEffect7SinValueB;
extern f32 gEffect7SinValueA;
extern f32 lbl_803DFCD8;
extern f32 lbl_803DFCDC;
extern f32 lbl_803DFCE0;
extern f32 lbl_803DFCE8;
extern f32 gEffect7Pi;
extern f32 gEffect7SinAngleScale;

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

#pragma scheduling off
#pragma peephole off
void Effect7_func05(void)
{
    f32 sum;
    f32 step;
    sum = gEffect7TexScrollPhaseA + (step = lbl_803DFCD8 * timeDelta);
    gEffect7TexScrollPhaseA = sum;
    if (sum > 1.0f)
    {
        gEffect7TexScrollPhaseA = lbl_803DFCDC;
    }
    sum = gEffect7TexScrollPhaseB + step;
    gEffect7TexScrollPhaseB = sum;
    if (sum > 1.0f)
    {
        gEffect7TexScrollPhaseB = lbl_803DFCE8;
    }
    gEffect7SinAngleA = gEffect7SinAngleA + framesThisStep * 0x64;
    if (gEffect7SinAngleA > 0x7fff)
    {
        gEffect7SinAngleA = 0;
    }
    gEffect7SinValueA = mathSinf(gEffect7Pi * (f32)(s16)gEffect7SinAngleA / gEffect7SinAngleScale);
    gEffect7SinAngleB = gEffect7SinAngleB + framesThisStep * 0x32;
    if (gEffect7SinAngleB > 0x7fff)
    {
        gEffect7SinAngleB = 0;
    }
    gEffect7SinValueB = mathSinf(gEffect7Pi * (f32)(s16)gEffect7SinAngleB / gEffect7SinAngleScale);
}

extern FxNode9 lbl_8039C368;
extern f32 gEffect7ScrollPhaseA;
extern f32 gEffect7ScrollPhaseB;
extern f32 lbl_803DFCEC;
extern f32 lbl_803DFCF0;
extern f32 lbl_803DFCF4;
extern f32 lbl_803DFCF8;
extern f32 lbl_803DFCFC;
extern f32 lbl_803DFD00;
extern f32 lbl_803DFD04;
extern f32 lbl_803DFD08;
extern f32 lbl_803DFD0C;
extern f32 lbl_803DFD10;
extern f32 lbl_803DFD14;
extern f32 lbl_803DFD18;
extern f32 lbl_803DFD1C;
extern f32 lbl_803DFD20;
extern f32 lbl_803DFD24;
extern f32 lbl_803DFD28;
extern f32 lbl_803DFD2C;
extern f32 lbl_803DFD30;
extern f32 lbl_803DFD34;
extern f32 lbl_803DFD38;
extern f32 lbl_803DFD3C;
extern f32 lbl_803DFD40;
extern f32 lbl_803DFD44;
extern f32 lbl_803DFD48;
extern f32 lbl_803DFD4C;
extern f32 lbl_803DFD50;
extern f32 lbl_803DFD54;
extern f32 lbl_803DFD58;
extern f32 lbl_803DFD5C;
extern f32 gEffect7AlphaMax;
extern f32 lbl_803DFD64;
extern f32 lbl_803DFD68;
extern f32 lbl_803DFD6C;
extern f32 lbl_803DFD70;
extern f32 lbl_803DFD74;
extern f32 lbl_803DFD78;
extern f32 lbl_803DFD7C;
extern f32 lbl_803DFD80;
extern f32 lbl_803DFD84;

#define FILL368() do {                          \
    lbl_8039C368.posX = lbl_803DFCEC;             \
    lbl_8039C368.posY = lbl_803DFCEC;             \
    lbl_8039C368.posZ = lbl_803DFCEC;             \
    lbl_8039C368.scale = lbl_803DFCE0;            \
    lbl_8039C368.unk0 = 0;                         \
    lbl_8039C368.unk2 = 0;                         \
    lbl_8039C368.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C368;             \
  } while (0)

int Effect7_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    void* player;
    PartFxSpawn cfg;

    player = Obj_GetPlayerObject();
    gEffect7ScrollPhaseA += 0.001f;
    if (gEffect7ScrollPhaseA > 1.0f) gEffect7ScrollPhaseA = 0.1f;
    gEffect7ScrollPhaseB += 0.0003f;
    if (gEffect7ScrollPhaseB > 1.0f) gEffect7ScrollPhaseB = 0.3f;
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
    cfg.startPosX = lbl_803DFCEC;
    cfg.startPosY = lbl_803DFCEC;
    cfg.startPosZ = lbl_803DFCEC;
    cfg.velocityX = lbl_803DFCEC;
    cfg.velocityY = lbl_803DFCEC;
    cfg.velocityZ = lbl_803DFCEC;
    cfg.scale = lbl_803DFCEC;
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
        cfg.velocityX = lbl_803DFCF0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = lbl_803DFCF4 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityY = lbl_803DFCF0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.scale = lbl_803DFCF8 * (f32)(s32)
        randomGetRange(0x1e, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x88;
        break;
    case 0xaf:
        cfg.velocityX = lbl_803DFCFC * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = lbl_803DFCF4 * (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityY = lbl_803DFCFC * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.scale = lbl_803DFD00 * (f32)(s32)
        randomGetRange(0x3c, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x400000;
        cfg.renderFlags = 8;
        cfg.textureId = 0xe4;
        break;
    case 0xad:
        cfg.velocityX = lbl_803DFD04 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803DFD08 * (f32)(s32)
        randomGetRange(6, 0x16);
        cfg.velocityZ = lbl_803DFD04 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosX = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosY = lbl_803DFCEC;
        cfg.startPosZ = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803DFD0C;
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
        cfg.startPosX = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosY = lbl_803DFCEC;
        cfg.startPosZ = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityX = lbl_803DFD04 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DFD10 * (f32)(s32)
        randomGetRange(9, 0xc);
        cfg.velocityZ = lbl_803DFD04 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.scale = lbl_803DFD14 * (f32)(s32)
        randomGetRange(0xa, 0xf);
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
        cfg.velocityX = lbl_803DFD18 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD04 * (f32)(s32)
        randomGetRange(4, 0xa);
        cfg.velocityZ = lbl_803DFD1C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFD20 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1400211;
        cfg.textureId = 0xdf;
        break;
    case 0x85:
        if (extraArgs == 0) return 0;
        cfg.startPosX = ((GameObject*)player)->anim.worldPosX;
        cfg.startPosY = ((GameObject*)player)->anim.worldPosY;
        cfg.startPosZ = ((GameObject*)player)->anim.worldPosZ;
        cfg.scale = lbl_803DFD24;
        cfg.lifetimeFrames = 0x28;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x110;
        cfg.textureId = spawnParams->unk4 + 0x170;
        break;
    case 0x8a:
        cfg.startPosX = lbl_803DFD28;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityX = lbl_803DFD2C;
        cfg.scale = lbl_803DFD30 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x10e;
        cfg.linkGroup = 0x10;
        cfg.initialAlpha = 0xf;
        cfg.behaviorFlags = 0x2000011;
        cfg.textureId = 0x5f;
        break;
    case 0x8b:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x78, 0x78);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x78, 0x78);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x78, 0x78);
        cfg.velocityX = lbl_803DFD34 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD34 * (f32)(s32)
        randomGetRange(4, 0xa);
        cfg.velocityZ = lbl_803DFD34 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFD38 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x378;
        cfg.behaviorFlags = 0x80000119;
        cfg.textureId = 0x125;
        break;
    case 0x8e:
        cfg.velocityX = lbl_803DFD3C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD3C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DFD3C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFD3C;
        cfg.lifetimeFrames = 0x50;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100110;
        cfg.textureId = 0x30;
        break;
    case 0x8f:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-6, 6);
        cfg.velocityX = lbl_803DFD1C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD1C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DFD1C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        if ((int)randomGetRange(0, 0xc) == 0)
        {
            cfg.scale = lbl_803DFD40 * (f32)(s32)
            randomGetRange(0xf, 0x1e);
            cfg.initialAlpha = 0x5f;
        }
        else
        {
            cfg.scale = lbl_803DFD44 * (f32)(s32)
            randomGetRange(0xf, 0x1e);
            cfg.initialAlpha = 0xff;
        }
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x400108;
        cfg.textureId = 0x33;
        break;
    case 0x9a:
        cfg.startPosX = lbl_803DFD48;
        cfg.startPosY = lbl_803DFD4C + (f32)(s32)
        randomGetRange(-0x42, 0x42);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x42, 0x42);
        cfg.scale = lbl_803DFD04 * (f32)(s32)
        randomGetRange(1, 0xa);
        cfg.lifetimeFrames = randomGetRange(0x50, 0x78);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x125;
        cfg.linkGroup = 5;
        break;
    case 0x9b:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x42, 0x42);
        cfg.startPosY = lbl_803DFD4C - (f32)(s32)
        randomGetRange(0, 0x42);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x60, 0x60);
        cfg.velocityY = lbl_803DFD50 * (f32)(s32)
        randomGetRange(0, 0x28);
        cfg.scale = lbl_803DFD54 * (f32)(s32)
        randomGetRange(0xa, 0x28);
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100200;
        cfg.textureId = 0x125;
        break;
    case 0x9c:
        cfg.velocityX = lbl_803DFD50 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFD50 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DFD50 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFD58;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x110;
        cfg.textureId = 0xdd;
        break;
    case 0x9f:
        cfg.velocityX = lbl_803DFD5C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = lbl_803DFD5C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DFD5C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFD54;
        cfg.lifetimeFrames = randomGetRange(0x23, 0x4b);
        cfg.behaviorFlags = 0x81480000;
        cfg.renderFlags = 0x410800;
        cfg.textureId = 0x167;
        break;
    case 0xa0:
        if (spawnParams == 0)
            FILL368();
        cfg.startPosX = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0x14, -0xa);
        cfg.startPosY = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DFCDC * (f32)(s32)
        randomGetRange(-0xa, 0);
        cfg.initialAlpha = 0xff;
        if (spawnParams != 0)
        {
            cfg.startPosX = cfg.startPosX + spawnParams->posX;
            cfg.startPosY = cfg.startPosY + spawnParams->posY;
            cfg.startPosZ = cfg.startPosZ + spawnParams->posZ;
            if (lbl_803DFCE0 == spawnParams->scale)
            {
                cfg.initialAlpha = 0xff;
            }
            else
            {
                cfg.initialAlpha = (u8)(s32)(gEffect7AlphaMax * spawnParams->scale);
            }
        }
        cfg.scale = lbl_803DFD64 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x2d;
        cfg.behaviorFlags = 0x200;
        cfg.textureId = 0x125;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0xa1:
        cfg.velocityY = lbl_803DFD68 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityX = lbl_803DFD6C * (f32)(s32)
        randomGetRange(0x64, 0x96);
        cfg.startPosZ = lbl_803DFD70 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFD70 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFD74 * (f32)(s32)
        randomGetRange(0x32, 0xc8);
        cfg.lifetimeFrames = 0x96;
        cfg.textureId = 0xc10;
        cfg.behaviorFlags = (u32)randFn_80080100;
        cfg.renderFlags = 0x4020020;
        cfg.initialAlpha = randomGetRange(0x7f, 0xff);
        cfg.colorWord0 = cfg.overrideColor0 = 0xa70f;
        cfg.colorWord1 = cfg.overrideColor1 = 0xa70f;
        cfg.colorWord2 = cfg.overrideColor2 = 0xc350;
        break;
    case 0xa3:
        if (spawnParams == 0) break;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.velocityZ = lbl_803DFD78 * (f32)(s32)
        randomGetRange(0x64, 0x78);
        cfg.scale = lbl_803DFD7C * (f32)(s32)
        randomGetRange(0x3c, 0x50);
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
        cfg.velocityX = lbl_803DFD80 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityY = lbl_803DFD80 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DFD80 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFD20 * (f32)(s32)
        randomGetRange(0x23, 0x32);
        cfg.lifetimeFrames = randomGetRange(0xa, 0x28) + 0xa;
        cfg.textureId = 0xc13;
        cfg.behaviorFlags = 0x81080010;
        cfg.renderFlags = 0x482800;
        break;
    case 0xa8:
        cfg.scale = lbl_803DFCDC;
        cfg.lifetimeFrames = 0xe;
        cfg.behaviorFlags = 0x480100;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0x5fd;
        cfg.initialAlpha = 0x64;
        break;
    case 0xa9:
        if (spawnParams != 0)
        {
            cfg.scale = spawnParams->scale * (lbl_803DFD20 * (f32)(s32)
            randomGetRange(0x4b, 0x64)
            )
            ;
        }
        else
        {
            cfg.scale = lbl_803DFD20 * (f32)(s32)
            randomGetRange(0x4b, 0x64);
        }
        cfg.lifetimeFrames = 1;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0xc7e;
        cfg.initialAlpha = 0x96;
        break;
    case 0xaa:
        cfg.scale = lbl_803DFD84 * (f32)(s32)
        randomGetRange(0x96, 0xc8);
        cfg.lifetimeFrames = randomGetRange(0xf, 0x19);
        cfg.textureId = 0x185;
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x4000000;
        cfg.initialAlpha = 0x96;
        break;
    case 0xab:
        cfg.scale = lbl_803DFD84 * (f32)(s32)
        randomGetRange(0x64, 0x96);
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
#undef FILL368
