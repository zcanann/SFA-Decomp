#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/dll/DR/dr_shared.h"

void Effect8_func03_nop(void)
{
}

void Effect8_release(void)
{
}

void Effect8_initialise(void)
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

extern f32 lbl_803DB818;
extern f32 lbl_803DB81C;
extern int gModgfxSinePhaseA;
extern int gModgfxSinePhaseB;
extern f32 gModgfxSineWaveB;
extern f32 gModgfxSineWaveA;
extern f32 lbl_803DF878;
extern f32 lbl_803DFCE0;
extern f32 lbl_803DFD98;
extern f32 lbl_803DFD9C;
extern f32 lbl_803DFDA8;
extern f32 gModgfxPi;
extern f32 lbl_803DFE24;

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

#pragma scheduling off
#pragma peephole off
void Effect8_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB818 + (step = lbl_803DFD98 * timeDelta);
    lbl_803DB818 = sum;
    if (sum > 1.0f)
    {
        lbl_803DB818 = lbl_803DFD9C;
    }
    sum = lbl_803DB81C + step;
    lbl_803DB81C = sum;
    if (sum > 1.0f)
    {
        lbl_803DB81C = lbl_803DFDA8;
    }
    gModgfxSinePhaseA = gModgfxSinePhaseA + framesThisStep * 0x64;
    if (gModgfxSinePhaseA > 0x7fff)
    {
        gModgfxSinePhaseA = 0;
    }
    gModgfxSineWaveA = mathSinf(gModgfxPi * (f32)(s16)gModgfxSinePhaseA / lbl_803DFE24);
    gModgfxSinePhaseB = gModgfxSinePhaseB + framesThisStep * 0x32;
    if (gModgfxSinePhaseB > 0x7fff)
    {
        gModgfxSinePhaseB = 0;
    }
    gModgfxSineWaveB = mathSinf(gModgfxPi * (f32)(s16)gModgfxSinePhaseB / lbl_803DFE24);
}

extern FxNode9 lbl_8039C380;
extern f32 lbl_803DB810;
extern f32 lbl_803DB814;
extern f32 lbl_803DFDA4;
extern f32 lbl_803DFDB0;
extern f32 lbl_803DFDB4;
extern f32 lbl_803DFDB8;
extern f32 lbl_803DFDBC;
extern f32 lbl_803DFDC0;
extern f32 lbl_803DFDC4;
extern f32 lbl_803DFDC8;
extern f32 lbl_803DFDCC;
extern f32 lbl_803DFDD0;
extern f32 lbl_803DFDD4;
extern f32 lbl_803DFDD8;
extern f32 lbl_803DFDDC;
extern f32 lbl_803DFDE0;
extern f32 lbl_803DFDE4;
extern f32 lbl_803DFDE8;
extern f32 lbl_803DFDEC;
extern f32 lbl_803DFDF0;
extern f32 lbl_803DFDF4;
extern f32 lbl_803DFDF8;
extern f32 lbl_803DFDFC;
extern f32 lbl_803DFE00;
extern f32 lbl_803DFE04;
extern f32 lbl_803DFE08;
extern f32 lbl_803DFE0C;
extern f32 lbl_803DFE10;

#define FILL8() do {                            \
    lbl_8039C380.posX = 0.0f;             \
    lbl_8039C380.posY = 0.0f;            \
    lbl_8039C380.posZ = 0.0f;            \
    lbl_8039C380.scale = 1.0f;             \
    lbl_8039C380.unk0 = 0;                         \
    lbl_8039C380.unk2 = 0;                         \
    lbl_8039C380.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C380;             \
  } while (0)

int Effect8_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    lbl_803DB810 = lbl_803DB810 + lbl_803DFD98;
    if (lbl_803DB810 > 1.0f) lbl_803DB810 = lbl_803DFD9C;
    lbl_803DB814 = lbl_803DB814 + lbl_803DFDA4;
    if (lbl_803DB814 > 1.0f) lbl_803DB814 = lbl_803DFDA8;
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
    switch (effectId)
    {
    case 0x361:
        cfg.velocityX = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0xc8;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x62;
        break;
    case 0x362:
        cfg.velocityX = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0xc8;
        cfg.behaviorFlags = 0xa100100;
        cfg.textureId = 0x62;
        break;
    case 0x35f:
        cfg.startPosX = lbl_803DFDB4 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosZ = lbl_803DFDB4 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.startPosY = lbl_803DFDB4 * (f32)(s32)
        randomGetRange(-0xa, 0x78);
        cfg.velocityY = lbl_803DFDB8 * (f32)(s32)
        randomGetRange(2, 0x64);
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x3c;
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x180201;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0x9b00;
        cfg.overrideColor0 = 0x9600;
        cfg.overrideColor1 = 0x1400;
        cfg.overrideColor2 = 0x1400;
        cfg.renderFlags = 0x20;
        break;
    case 0x360:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosY = lbl_803DFDBC + (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityZ = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFDC4 * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.scale = lbl_803DFDC8 * (f32)(s32)
        randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x81008000;
        cfg.textureId = 0x208;
        break;
    case 0x357:
        if (spawnParams == 0)
            FILL8();
        if (spawnParams == 0) return -1;
        cfg.colorWord0 = (u16)((u8)spawnParams->unk4 << 8);
        cfg.colorWord1 = (u16)((u8)spawnParams->unk2 << 8);
        cfg.colorWord2 = (u16)((u8)spawnParams->unk0 << 8);
        cfg.overrideColor0 = 0xfe00;
        cfg.overrideColor1 = 0xfe00;
        cfg.overrideColor2 = 0xfe00;
        cfg.scale = lbl_803DFDCC;
        cfg.lifetimeFrames = 0x1e;
        cfg.initialAlpha = 0x78;
        cfg.behaviorFlags = 0x8000201;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x71;
        break;
    case 0x359:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosY = lbl_803DFDBC + (f32)(s32)
        randomGetRange(0x1e, 0x28);
        cfg.velocityX = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFDC4 * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.scale = lbl_803DFDC8 * (f32)(s32)
        randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x81008000;
        cfg.quadVertex3Pad06 = 0x284;
        cfg.textureId = 0x208;
        break;
    case 0x352:
        cfg.scale = lbl_803DFDD0;
        cfg.lifetimeFrames = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0xa100208;
        cfg.textureId = 0x91;
        break;
    case 0x353:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-2, 2);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-2, 2);
        cfg.velocityX = lbl_803DFDD4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DFDD4 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(0, 0x50);
        cfg.scale = lbl_803DFDD8 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x17c) + 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80400109;
        cfg.textureId = 0x47;
        break;
    case 0x354:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-4, 4);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-4, 4);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityX = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803DFDC4 * (f32)(s32)
        randomGetRange(0, 0x64);
        cfg.scale = lbl_803DFDC8 * (f32)(s32)
        randomGetRange(0x14, 0x50);
        cfg.lifetimeFrames = randomGetRange(0, 0x118) + 0xb4;
        cfg.initialAlpha = 0xfe;
        cfg.behaviorFlags = 0x1000001;
        cfg.quadVertex3Pad06 = 0x284;
        cfg.textureId = 0x208;
        break;
    case 0x355:
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x580101;
        cfg.textureId = 0x17c;
        break;
    case 0x356:
        cfg.scale = lbl_803DFDC4;
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.velocityY = lbl_803DFDDC * (f32)(s32)
        randomGetRange(0, 0x14);
        cfg.behaviorFlags = 0x80201;
        cfg.textureId = 0x62;
        break;
    case 0x35a:
        if (spawnParams == 0)
            FILL8();
        if (spawnParams == 0) return -1;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DFDB0 * (lbl_803DFDE0 * (f32)(s32)spawnParams->unk4);
        cfg.lifetimeFrames = 0x3c;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = spawnParams->unk4 << 8;
        cfg.overrideColor1 = spawnParams->unk4 << 8;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x60;
        cfg.initialAlpha = spawnParams->unk4;
        cfg.behaviorFlags = 0x201;
        cfg.textureId = 0x76;
        break;
    case 0x35b:
        if (spawnParams == 0)
            FILL8();
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x580101;
        cfg.textureId = 0xc22;
        break;
    case 0x35c:
        if (spawnParams == 0)
            FILL8();
        if (spawnParams == 0) return -1;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DFDE4 * (lbl_803DFDC0 * (lbl_803DFDE8 + (f32)(s32)spawnParams->unk0));
        cfg.lifetimeFrames = 0xa;
        cfg.colorWord0 = (u16)(spawnParams->unk0 << 8);
        cfg.colorWord1 = (u16)(spawnParams->unk0 << 8);
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = spawnParams->unk0 << 8;
        cfg.overrideColor1 = spawnParams->unk0 << 8;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = spawnParams->unk4;
        cfg.textureId = 0xc9d;
        break;
    case 0x35d:
        if (spawnParams == 0)
            FILL8();
        if (spawnParams == 0) return -1;
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803DFDE4 * (lbl_803DFDC0 * (lbl_803DFDE8 + (f32)(s32)spawnParams->unk0));
        cfg.lifetimeFrames = 0xa;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = (u16)(spawnParams->unk0 << 8);
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = 0xff00;
        cfg.overrideColor1 = spawnParams->unk0 << 8;
        cfg.overrideColor2 = 0xff00;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = spawnParams->unk4;
        cfg.textureId = 0xc9d;
        break;
    case 0x35e:
        if (spawnParams == 0)
            FILL8();
        cfg.scale = lbl_803DFDEC;
        cfg.startPosY = lbl_803DFDF0;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = spawnParams != 0 ? spawnParams->unk4 : 0xff;
        cfg.linkGroup = 0;
        cfg.startPosX = spawnParams != 0 ? spawnParams->posX : 0.0f;
        cfg.startPosY = spawnParams != 0 ? spawnParams->posY : 0.0f;
        cfg.startPosZ = spawnParams != 0 ? spawnParams->posZ : 0.0f;
        cfg.behaviorFlags = 0xa100200;
        cfg.textureId = 0x7d;
        break;
    case 0x367:
        cfg.startPosX = lbl_803DFD9C * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.startPosY = lbl_803DFDF4;
        cfg.startPosZ = lbl_803DFD9C * (f32)(s32)
        randomGetRange(-0x190, 0x190);
        cfg.velocityX = lbl_803DFDF8 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803DFDC0 * (f32)(s32)
        randomGetRange(0x64, 0xc8);
        cfg.velocityZ = lbl_803DFDF8 * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803DFDFC * (f32)(s32)
        randomGetRange(5, 0x19);
        cfg.lifetimeFrames = 0x7d0;
        cfg.initialAlpha = 0xe6;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0xe6, 0x320);
        cfg.renderFlags = 0x10000000;
        cfg.behaviorFlags = 0x8f000000;
        cfg.textureId = 0x56e;
        break;
    case 0x369:
        cfg.scale = lbl_803DFD9C;
        cfg.lifetimeFrames = 0x46;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x580101;
        cfg.textureId = 0x17c;
        break;
    case 0x366:
        cfg.velocityY = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(0x1f4, 0x3e8);
        cfg.startPosZ = lbl_803DFD9C * (f32)(s32)
        randomGetRange(-0x12c, 0x12c);
        cfg.startPosX = lbl_803DFD9C * (f32)(s32)
        randomGetRange(-0x12c, 0x12c);
        cfg.startPosY = lbl_803DFE00;
        cfg.scale = lbl_803DFDB0;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x400000;
        cfg.renderFlags = 0x100;
        cfg.textureId = 0x62;
        cfg.initialAlpha = 0x50;
        break;
    case 0x365:
        cfg.velocityY = lbl_803DFE04 * (f32)(s32)
        randomGetRange(0x6e, 0xc8);
        cfg.startPosZ = lbl_803DFE08 * (f32)(s32)
        randomGetRange(-0x12c, 0x12c);
        cfg.startPosX = lbl_803DFE08 * (f32)(s32)
        randomGetRange(-0x12c, 0x12c);
        cfg.scale = lbl_803DFE0C * (f32)(s32)
        randomGetRange(1, 0x14) + lbl_803DFD98;
        cfg.initialAlpha = 0xff;
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourceVecY = randomGetRange(0, 0xffff);
        cfg.sourceVecX = randomGetRange(0, 0xffff);
        cfg.sourcePosY = (f32)(s32)
        randomGetRange(0, 0x258);
        cfg.sourcePosZ = (f32)(s32)
        randomGetRange(0, 0x258);
        cfg.sourcePosW = (f32)(s32)
        randomGetRange(0, 0x258);
        {
            u16 r2;
            cfg.colorWord0 = (u16)(randomGetRange(0, 0x9c40) + 0x63bf);
            r2 = (u16)(randomGetRange(0, 0x9c40) + 0x3caf);
            cfg.colorWord1 = r2;
            cfg.colorWord2 = 0x3caf;
            cfg.overrideColor0 = cfg.colorWord0;
            cfg.overrideColor1 = r2;
            cfg.overrideColor2 = 0x3caf;
        }
        cfg.renderFlags = 0x20;
        cfg.lifetimeFrames = randomGetRange(0, 0x3c) + 0x15e;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x86000008;
        cfg.textureId = 0x3a2;
        break;
    case 0x364:
        cfg.velocityY = lbl_803DFDB0 * (f32)(s32)
        randomGetRange(5, 0x64);
        cfg.scale = lbl_803DFE10;
        cfg.lifetimeFrames = 0x50;
        {
            u16 r2;
            cfg.colorWord0 = (u16)(randomGetRange(0, 0x2710) + 0x63bf);
            r2 = (u16)(randomGetRange(0, 0x2710) + 0x3caf);
            cfg.colorWord1 = r2;
            cfg.colorWord2 = 0x3caf;
            cfg.overrideColor0 = cfg.colorWord0;
            cfg.overrideColor1 = r2;
            cfg.overrideColor2 = 0x3caf;
        }
        cfg.renderFlags = 0x20;
        cfg.behaviorFlags = (u32)randFn_80080100;
        cfg.textureId = 0x62;
        cfg.initialAlpha = 0xa0;
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
#undef FILL8

extern FxNode9 lbl_8039C338;
extern f32 lbl_803DF884;

#define FILL338() do {                          \
    lbl_8039C338.posX = lbl_803DF884;             \
    lbl_8039C338.posY = lbl_803DF884;            \
    lbl_8039C338.posZ = lbl_803DF884;            \
    lbl_8039C338.scale = lbl_803DF878;             \
    lbl_8039C338.unk0 = 0;                         \
    lbl_8039C338.unk2 = 0;                         \
    lbl_8039C338.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C338;             \
  } while (0)

#undef FILL338

extern FxNode9 lbl_8039C368;
extern f32 lbl_803DFCEC;

#define FILL368() do {                          \
    lbl_8039C368.posX = lbl_803DFCEC;             \
    lbl_8039C368.posY = lbl_803DFCEC;            \
    lbl_8039C368.posZ = lbl_803DFCEC;            \
    lbl_8039C368.scale = lbl_803DFCE0;             \
    lbl_8039C368.unk0 = 0;                         \
    lbl_8039C368.unk2 = 0;                         \
    lbl_8039C368.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C368;             \
  } while (0)

#undef FILL368

extern FxNode9 lbl_8039C350;
extern f32 lbl_803DF9D0;
extern f32 lbl_803DF9D4;

#define FILL350() do {                          \
    lbl_8039C350.posX = lbl_803DF9D0;             \
    lbl_8039C350.posY = lbl_803DF9D0;            \
    lbl_8039C350.posZ = lbl_803DF9D0;            \
    lbl_8039C350.scale = lbl_803DF9D4;             \
    lbl_8039C350.unk0 = 0;                         \
    lbl_8039C350.unk2 = 0;                         \
    lbl_8039C350.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C350;             \
  } while (0)

#undef FILL350

// VERIFY lbl_803DF720 may already exist in modgfx.c
// VERIFY lbl_803DF724 may already exist in modgfx.c
// VERIFY lbl_803DF728 may already exist in modgfx.c
// VERIFY lbl_803DF730 may already exist in modgfx.c
extern FxNode9 lbl_8039C320;
/* MtxBuildArg, vecRotateZXY, randFn_80080100, gExpgfxInterface, randomGetRange
   already declared in modgfx.c. */

/* ===== (2) FILL macro ===== */
#define FILL320() do {                          \
    lbl_8039C320.posX = 0.0f;             \
    lbl_8039C320.posY = 0.0f;            \
    lbl_8039C320.posZ = 0.0f;            \
    lbl_8039C320.scale = 1.0f;             \
    lbl_8039C320.unk0 = 0;                         \
    lbl_8039C320.unk2 = 0;                         \
    lbl_8039C320.unk4 = 0;                         \
    spawnParams = (PartFxSpawnParams *)&lbl_8039C320;             \
  } while (0)

#undef FILL320
