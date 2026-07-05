/*
 * effect3 (DLL 0x1C) - a particle-effect spawner object.
 *
 * The live entry point is Effect3_func04: a spawn dispatcher keyed on
 * effectId (0x1F4..0x20E). For each id it fills a PartFxSpawn request -
 * texture, lifetime, scale, start position, velocity, color, behavior and
 * render flags, mostly randomized via randomGetRange - then hands it to
 * gExpgfxInterface->spawnEffect. Behavior-flag bit 0 means "offset start
 * position by the attached source"; spawnFlags bit 0x200000 selects an
 * explicit PartFxSpawnParams source over the attached object. The object's
 * vtable (projgfx_funcs) is otherwise all nop/unsupported callbacks.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/sfa_shared_decls.h"

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

extern void Sfx_PlayFromObject(void* obj, int id);



/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

extern FxNode9 lbl_8039C350;
extern f32 lbl_803DF9D0;
extern f32 lbl_803DF9D4;
extern f32 lbl_803DF9D8;
extern f32 lbl_803DF9DC;
extern f32 lbl_803DF9E0;
extern f32 lbl_803DF9E4;
extern f32 lbl_803DF9E8;
extern f32 lbl_803DF9EC;
extern f32 lbl_803DF9F0;
extern f32 lbl_803DF9F4;
extern f32 lbl_803DF9F8;
extern f32 lbl_803DF9FC;
extern f32 lbl_803DFA00;
extern f32 lbl_803DFA04;
extern f32 lbl_803DFA08;
extern f32 lbl_803DFA0C;
extern f32 lbl_803DFA10;
extern f32 lbl_803DFA14;
extern f32 lbl_803DFA18;
extern f32 lbl_803DFA1C;
extern f32 lbl_803DFA20;
extern f32 lbl_803DFA24;
extern f32 lbl_803DFA28;
extern f32 lbl_803DFA2C;
extern f32 lbl_803DFA30;
extern f32 lbl_803DFA34;
extern f32 lbl_803DFA38;
extern f32 lbl_803DFA3C;
extern f32 lbl_803DFA40;
extern f32 lbl_803DFA44;
extern f32 lbl_803DFA48;
extern f32 lbl_803DFA4C;
extern f32 lbl_803DFA50;
extern f32 lbl_803DFA54;
extern f32 gEffect3Pi;
extern f32 gEffect3AngleFullScale;
extern f32 lbl_803DFA60;
extern f32 lbl_803DFA64;
extern f32 lbl_803DFA68;
extern f32 lbl_803DFA6C;
extern f32 lbl_803DFA70;
extern f32 lbl_803DFA74;
extern f32 lbl_803DFA78;

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

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
int Effect3_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                   u8 modelId, void* extraArgsIn)
{
    int spawnResult;
    PartFxSpawn cfg;
    s16* extraArgs = extraArgsIn;

    if (sourceObj == 0) return -1;
    if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0)
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
    cfg.startPosX = lbl_803DF9D0;
    cfg.startPosY = lbl_803DF9D0;
    cfg.startPosZ = lbl_803DF9D0;
    cfg.velocityX = lbl_803DF9D0;
    cfg.velocityY = lbl_803DF9D0;
    cfg.velocityZ = lbl_803DF9D0;
    cfg.scale = lbl_803DF9D0;
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
            FILL350();
        cfg.startPosX = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0x14, -0xa);
        cfg.startPosY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xa, 0);
        if (spawnParams != 0)
        {
            cfg.startPosX = cfg.startPosX + spawnParams->posX;
            cfg.startPosY = cfg.startPosY + spawnParams->posY;
            cfg.startPosZ = cfg.startPosZ + spawnParams->posZ;
        }
        cfg.scale = lbl_803DF9DC * (f32)(s32)
        randomGetRange(0xd, 0x14);
        cfg.lifetimeFrames = 0x19;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80200;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0x184;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f5:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosX = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0x14, -0xa);
        cfg.startPosY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosZ = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xa, 0);
        if (spawnParams != 0)
        {
            cfg.startPosX = cfg.startPosX + spawnParams->posX;
            cfg.startPosY = cfg.startPosY + spawnParams->posY;
            cfg.startPosZ = cfg.startPosZ + spawnParams->posZ;
        }
        cfg.scale = lbl_803DF9E0 * (f32)(s32)
        randomGetRange(1, 4);
        cfg.lifetimeFrames = 0x19;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80200;
        cfg.textureId = 0x184;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f6:
        cfg.scale = lbl_803DF9E4 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0x40;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x80;
        cfg.textureId = 0x16d;
        cfg.linkGroup = randomGetRange(0, 0x14) + 4;
        break;
    case 0x1f7:
        if (spawnParams == 0)
            FILL350();
        if (spawnParams != 0) cfg.startPosY = spawnParams->posY;
        cfg.scale = lbl_803DF9E8;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x46;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x80110;
        cfg.textureId = 0xc13;
        cfg.linkGroup = 0x20;
        break;
    case 0x1f8:
        if (spawnParams == 0)
            FILL350();
        if (spawnParams != 0)
        {
            cfg.scale = lbl_803DF9E8 * spawnParams->scale;
        }
        else
        {
            cfg.scale = lbl_803DF9E8;
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
        cfg.scale = lbl_803DF9EC;
        cfg.lifetimeFrames = 0x10;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x100114;
        cfg.textureId = 0x17c;
        break;
    case 0x1fc:
        cfg.scale = lbl_803DF9E8;
        cfg.lifetimeFrames = 0x44;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x4c;
        break;
    case 0x1fd:
        cfg.startPosX = lbl_803DF9D0;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-3, 3);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-3, 3);
        cfg.velocityX = lbl_803DF9F0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803DF9F0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803DF9F0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803DF9F4;
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
            FILL350();
        if (extraArgs == 0) return -1;
        if (spawnParams != 0)
        {
            cfg.startPosX = spawnParams->posX;
            cfg.startPosY = spawnParams->posY;
            cfg.startPosZ = spawnParams->posZ;
        }
        if (extraArgs != 0)
        {
            cfg.velocityX = *(f32*)extraArgs;
            cfg.velocityY = lbl_803DF9E8 * (f32)(s32)
            randomGetRange(0, 0x14);
            cfg.velocityZ = *(f32*)(extraArgs + 2);
        }
        cfg.scale = lbl_803DF9FC * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DF9F8;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0x9b;
        cfg.behaviorFlags = 0x81088000;
        cfg.behaviorFlags = 0x1000000;
        cfg.textureId = 0x23c;
        break;
    case 0x1ff:
        cfg.startPosY = lbl_803DFA00;
        cfg.scale = lbl_803DF9E0;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11000004;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x200;
        break;
    case 0x200:
        Sfx_PlayFromObject(sourceObj, SFXsc_snort02);
        cfg.lifetimeFrames = 0x64;
        cfg.scale = lbl_803DFA04 * cfg.lifetimeFrames;
        cfg.behaviorFlags = 0xa100201;
        cfg.textureId = 0x56;
        break;
    case 0x201:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803DFA08;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803DFA0C;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803DFA08;
        cfg.velocityY = lbl_803DF9E8 * (f32)(s32)
        randomGetRange(1, 5);
        cfg.scale = lbl_803DFA10;
        cfg.lifetimeFrames = 0x64;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x100201;
        cfg.textureId = 0x63;
        break;
    case 0x202:
        cfg.velocityY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(0x96, 0xc8) / lbl_803DFA14;
        cfg.scale = lbl_803DFA1C * ((f32)(s32)
        randomGetRange(0x32, 0x64) / lbl_803DFA14
        )
        +lbl_803DFA18;
        cfg.lifetimeFrames = (s32)(spawnParams->scale / cfg.velocityY);
        if (cfg.lifetimeFrames < 0xa) cfg.lifetimeFrames = 0xa;
        if (cfg.lifetimeFrames > 0x78) cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x201;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = 0xc9f;
        cfg.initialAlpha = 0x60;
        break;
    case 0x203:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosY = spawnParams->posY;
        cfg.velocityY = lbl_803DFA20;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posZ,
                           (s16)(s32)spawnParams->posZ);
            break;
        case 1:
            cfg.startPosX = -spawnParams->posX;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posZ,
                           (s16)(s32)spawnParams->posZ);
            break;
        case 2:
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        case 3:
            cfg.startPosZ = -spawnParams->posZ;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        }
        cfg.scale = lbl_803DFA24;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x100210;
        cfg.textureId = 0x184;
        cfg.initialAlpha = 0xc4;
        break;
    case 0x204:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosY = spawnParams->posY;
        cfg.velocityY = lbl_803DFA20;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posZ,
                           (s16)(s32)spawnParams->posZ);
            break;
        case 1:
            cfg.startPosX = -spawnParams->posX;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posZ,
                           (s16)(s32)spawnParams->posZ);
            break;
        case 2:
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        case 3:
            cfg.startPosZ = -spawnParams->posZ;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        }
        cfg.velocityY = lbl_803DFA28 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DFA2C * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.lifetimeFrames = 0x78;
        cfg.linkGroup = 0;
        cfg.behaviorFlags = 0x80400110;
        cfg.textureId = 0x47;
        break;
    case 0x205:
        if (spawnParams == 0)
            FILL350();
        cfg.startPosY = spawnParams->posY;
        cfg.velocityY = lbl_803DFA20;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posZ,
                           (s16)(s32)spawnParams->posZ);
            break;
        case 1:
            cfg.startPosX = -spawnParams->posX;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posZ,
                           (s16)(s32)spawnParams->posZ);
            break;
        case 2:
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        case 3:
            cfg.startPosZ = -spawnParams->posZ;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        }
        cfg.velocityY = lbl_803DFA28 * (f32)(s32)
        randomGetRange(0x28, 0x50);
        cfg.scale = lbl_803DF9FC * (f32)(s32)
        randomGetRange(0x1e, 0x32);
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
            FILL350();
        cfg.startPosY = spawnParams->posY - lbl_803DFA30;
        cfg.velocityY = lbl_803DFA20;
        switch (randomGetRange(0, 3))
        {
        case 0:
            cfg.startPosX = spawnParams->posX;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posZ,
                           (s16)(s32)spawnParams->posZ);
            break;
        case 1:
            cfg.startPosX = -spawnParams->posX;
            cfg.startPosZ = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posZ,
                           (s16)(s32)spawnParams->posZ);
            break;
        case 2:
            cfg.startPosZ = spawnParams->posZ;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        case 3:
            cfg.startPosZ = -spawnParams->posZ;
            cfg.startPosX = (f32)(s32)
            randomGetRange((s16)(s32) - spawnParams->posX, (s16)(s32)spawnParams->posX);
            break;
        }
        cfg.velocityY = lbl_803DFA34 * (f32)(s32)
        randomGetRange(0x50, 0x64);
        cfg.scale = lbl_803DFA1C * (f32)(s32)
        randomGetRange(0x1e, 0x32);
        cfg.lifetimeFrames = 0x96;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080110;
        cfg.textureId = 0x60;
        break;
    case 0x208:
        cfg.startPosX = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xbb8, 0xbb8);
        cfg.startPosY = lbl_803DFA38;
        cfg.startPosZ = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(-0xbb8, 0xbb8);
        cfg.velocityY = lbl_803DFA3C * (f32)(s32)
        randomGetRange(0x190, 0x258);
        cfg.velocityX = lbl_803DFA04 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803DFA04 * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.scale = lbl_803DFA44 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFA40;
        cfg.lifetimeFrames = 0xb4;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080000;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0xe7;
        break;
    case 0x209:
        cfg.startPosY = (f32)(s32)
        randomGetRange(1, 5);
        cfg.velocityY = lbl_803DFA48 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.scale = lbl_803DFA4C * (lbl_803DF9FC * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFA50
        )
        ;
        cfg.lifetimeFrames = randomGetRange(0x73, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80480200;
        cfg.textureId = 0xc0d;
        break;
    case 0x20a:
        {
            f32 a;
            f32 b;
            if (spawnParams == 0)
                FILL350();
            cfg.startPosX = (f32)(s32)
            randomGetRange(-5, 5);
            cfg.startPosY = (f32)(s32)
            randomGetRange(1, 5);
            cfg.startPosZ = (f32)(s32)
            randomGetRange(-5, 5);
            a = lbl_803DF9E0 * (f32)(s32)
            randomGetRange(0, 0x258) + lbl_803DFA54;
            cfg.velocityY = lbl_803DFA10 * (f32)(s32)
            randomGetRange(0, 0xc8) + lbl_803DF9D4;
            cfg.velocityX = mathSinf(gEffect3Pi * (f32) * (s16*)sourceObj / gEffect3AngleFullScale);
            cfg.velocityZ = mathCosf(gEffect3Pi * (f32) * (s16*)sourceObj / gEffect3AngleFullScale);
            b = a * (lbl_803DFA60 * (f32)(s32)
            randomGetRange(0, 0x14)
            )
            +lbl_803DF9D8;
            cfg.velocityX = cfg.velocityX * b;
            cfg.velocityZ = cfg.velocityZ * b;
            cfg.velocityY = cfg.velocityY * a;
            cfg.scale = lbl_803DFA68 * (f32)(s32)
            randomGetRange(0, 0xa) + lbl_803DFA64;
            cfg.lifetimeFrames = randomGetRange(0xb4, 0xc8);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x3000120;
            cfg.renderFlags = 0x200000;
            cfg.textureId = 0xc0a;
            cfg.quadVertex3Pad06 = 0x20b;
        }
        break;
    case 0x20b:
        cfg.velocityY = lbl_803DF9F0 * (f32)(s32)
        randomGetRange(2, 0x14);
        cfg.scale = lbl_803DFA6C;
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
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x37, 0x37);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0xa, 0xf);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x37, 0x37);
        cfg.velocityX = lbl_803DFA24 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.velocityY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803DFA24 * (f32)(s32)
        randomGetRange(-8, 8);
        cfg.scale = lbl_803DF9FC * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803DFA70;
        cfg.lifetimeFrames = randomGetRange(0x78, 0x8c);
        cfg.initialAlpha = 0xff;
        cfg.quadVertex3Pad06 = 0x20b;
        cfg.renderFlags = 0x200000;
        cfg.behaviorFlags = 0x1001100;
        cfg.textureId = 0xc0a;
        break;
    case 0x20d:
        cfg.velocityX = lbl_803DFA74 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803DFA78 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803DFA74 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.startPosY = lbl_803DF9D8 * (f32)(s32)
        randomGetRange(0, 0x190);
        cfg.scale = lbl_803DFA04 * (f32)(s32)
        randomGetRange(0xf, 0x19);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0x4a0104;
        cfg.renderFlags = 0x40008;
        cfg.sourcePosY = lbl_803DF9D0;
        cfg.sourcePosZ = lbl_803DF9D0;
        cfg.sourcePosW = lbl_803DF9D0;
        cfg.sourceVecX = 0x46;
        cfg.sourceVecY = 0;
        cfg.sourceVecZ = 0;
        cfg.sourcePosX = lbl_803DF9D4;
        cfg.textureId = 0xe0;
        break;
    case 0x20e:
        cfg.startPosY = lbl_803DFA38;
        cfg.scale = lbl_803DF9F0;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11800004;
        cfg.initialAlpha = 0xa0;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x200;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & PROJGFX_SPAWN_FLAG_USE_ATTACHED_SOURCE) != 0)
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
#pragma opt_common_subs reset

#undef FILL350
