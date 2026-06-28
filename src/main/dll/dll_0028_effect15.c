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
#include "main/game_object.h"
#include "main/dll/waterfxcfg_struct.h"
#include "main/dll/partfxspawn_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
extern f32 lbl_803E0110;
extern f32 lbl_803E0114;
extern f32 lbl_803E0118;
extern f32 lbl_803E011C;
extern f32 lbl_803E0120;
extern f32 lbl_803E0124;
extern f32 lbl_803E0128;
extern f32 lbl_803E012C;
extern f32 lbl_803E0130;
extern f32 lbl_803E0134;
extern f32 lbl_803E0138;
extern f32 lbl_803E013C;
extern f32 lbl_803E0140;
extern f32 lbl_803E0144;
extern f32 lbl_803E0148;
extern f32 lbl_803E014C;
extern f32 lbl_803E0150;
extern f32 lbl_803E0154;
extern f32 lbl_803E0158;
extern f32 lbl_803E015C;
extern f32 lbl_803E0160;
extern f32 lbl_803E0164;
extern f32 lbl_803E0168;
extern f32 lbl_803E016C;
extern f32 lbl_803E0170;
extern f32 lbl_803E0174;
extern WaterfxCfg gEffect15DefaultSpawnParams;

/*
 * cfg field names follow ExpgfxSpawnConfig (the consumer-side definition of
 * this 0x64-byte spawn request consumed by gExpgfxInterface->spawnEffect).
 * colorWord0..2 are the u16 spelling of the consumer's color pairs;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores.
 */
int Effect15_func04(void* sourceObj, int effectId, PartFxSpawnParams* spawnParams, u32 spawnFlags,
                    u8 modelId, f32* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

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
    cfg.startPosX = lbl_803E0110;
    cfg.startPosY = lbl_803E0110;
    cfg.startPosZ = lbl_803E0110;
    cfg.velocityX = lbl_803E0110;
    cfg.velocityY = lbl_803E0110;
    cfg.velocityZ = lbl_803E0110;
    cfg.scale = lbl_803E0110;
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
        cfg.scale = lbl_803E0114 * (f32)(s32)
        randomGetRange(0x5a, 0x64);
        cfg.velocityX = lbl_803E0118 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E0110;
        cfg.velocityZ = lbl_803E0118 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
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
            gEffect15DefaultSpawnParams.posX = lbl_803E0110;
            gEffect15DefaultSpawnParams.posY = lbl_803E0110;
            gEffect15DefaultSpawnParams.posZ = lbl_803E0110;
            gEffect15DefaultSpawnParams.scale = lbl_803E011C;
            gEffect15DefaultSpawnParams.rotX = 0;
            gEffect15DefaultSpawnParams.rotY = 0;
            gEffect15DefaultSpawnParams.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect15DefaultSpawnParams;
        }
        cfg.startPosX = spawnParams->posX;
        cfg.startPosY = spawnParams->posY;
        cfg.startPosZ = spawnParams->posZ;
        cfg.scale = lbl_803E0120;
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
            gEffect15DefaultSpawnParams.posX = lbl_803E0110;
            gEffect15DefaultSpawnParams.posY = lbl_803E0110;
            gEffect15DefaultSpawnParams.posZ = lbl_803E0110;
            gEffect15DefaultSpawnParams.scale = lbl_803E011C;
            gEffect15DefaultSpawnParams.rotX = 0;
            gEffect15DefaultSpawnParams.rotY = 0;
            gEffect15DefaultSpawnParams.rotZ = 0;
            spawnParams = (PartFxSpawnParams*)&gEffect15DefaultSpawnParams;
        }
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803E0124;
        cfg.startPosY = (f32)(s32)(-randomGetRange(0x64, 0x96)) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803E0124;
        cfg.behaviorFlags |= 0x80208LL;
        cfg.renderFlags = 0x10000;
        cfg.velocityX = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.initialAlpha = 0xff;
        cfg.lifetimeFrames = 0x3c;
        cfg.textureId = 0x7b;
        cfg.scale = spawnParams->scale *
            (lbl_803E0130 * (lbl_803E0134 * (f32)(s32)
        randomGetRange(0x32, 0x64)
        )
        )
        +
            lbl_803E012C;
        break;
    case 0x3eb:
        cfg.velocityX = lbl_803E0138 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803E013C * (f32)(s32)
        randomGetRange(-5, 5);
        cfg.velocityZ = lbl_803E0138 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosX = lbl_803E0110;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-6, 2);
        cfg.startPosZ = lbl_803E0110;
        cfg.scale = lbl_803E013C;
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
        cfg.velocityX = lbl_803E013C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E0120 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityZ = lbl_803E013C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803E0140 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x80210;
        cfg.renderFlags = 0x8000800;
        cfg.textureId = 0x79;
        break;
    case 0x3ee:
        cfg.startPosX = cfg.startPosX + (f32)(s32)
        randomGetRange(-0xa, 0xa) / lbl_803E0144;
        cfg.startPosY = cfg.startPosY + (f32)(s32)
        randomGetRange(-0x1e, 0) / lbl_803E0148;
        cfg.startPosZ = cfg.startPosZ + (f32)(s32)
        randomGetRange(-0xa, 0xa) / lbl_803E0144;
        cfg.velocityX = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E014C * (f32)(s32)(-randomGetRange(0x28, 0x64));
        cfg.velocityZ = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E012C * (f32)(s32)
        randomGetRange(0xf, 0x16);
        cfg.lifetimeFrames = 0x258;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0xc10;
        cfg.initialAlpha = randomGetRange(0x96, 0xfa);
        break;
    case 0x3ef:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x4b0, 0x4b0) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x4b0, 0x4b0) / lbl_803E0128;
        cfg.velocityY = lbl_803E014C * (f32)(s32)
        randomGetRange(0x1e, 0x46);
        cfg.scale = lbl_803E0154 * (f32)(s32)
        randomGetRange(0, 0x14) + lbl_803E0150;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x33;
        cfg.initialAlpha = 0xb4;
        cfg.renderFlags = 0x8100800;
        break;
    case 0x3f0:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8) / lbl_803E0128;
        cfg.velocityY = lbl_803E0158 * (f32)(s32)
        randomGetRange(0x1e, 0x46);
        cfg.scale = lbl_803E0154 * (f32)(s32)
        randomGetRange(0, 0x14) + lbl_803E015C;
        cfg.lifetimeFrames = 0xfa;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x33;
        cfg.renderFlags = 0x8000800;
        cfg.initialAlpha = 0xb4;
        break;
    case 0x3f1:
        cfg.startPosX = lbl_803E0110;
        cfg.startPosY = lbl_803E0110;
        cfg.startPosZ = lbl_803E0110;
        cfg.behaviorFlags = 0x80800;
        cfg.textureId = 0x76;
        cfg.initialAlpha = 0xd2;
        cfg.scale = lbl_803E0160;
        cfg.lifetimeFrames = 0x64;
        break;
    case 0x3f2:
        if (extraArgs == 0) return 0;
        if (spawnParams == 0)
        {
            gEffect15DefaultSpawnParams.posX = lbl_803E0110;
            gEffect15DefaultSpawnParams.posY = lbl_803E0110;
            gEffect15DefaultSpawnParams.posZ = lbl_803E0110;
            gEffect15DefaultSpawnParams.scale = lbl_803E011C;
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
            cfg.velocityY = lbl_803E0164 * (f32)(s32)
            randomGetRange(0, 0x14);
            cfg.velocityZ = extraArgs[1];
        }
        cfg.scale = lbl_803E0168 *
            (lbl_803E0170 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803E016C
        )
        ;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x81088000;
        cfg.textureId = 0x23c;
        break;
    case 0x3f3:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.velocityX = lbl_803E0118 * (f32)(s32)
        randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityX = -cfg.velocityX;
        cfg.velocityY = lbl_803E0118 * (f32)(s32)
        randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityY = -cfg.velocityY;
        cfg.velocityZ = lbl_803E0118 * (f32)(s32)
        randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityZ = -cfg.velocityZ;
        cfg.scale = lbl_803E0154 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803E012C;
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
        if ((int)randomGetRange(0, 0x28) == 0) cfg.scale = lbl_803E0130;
        else cfg.scale = lbl_803E015C;
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
            cfg.velocityZ = lbl_803E0174;
        }
        cfg.scale = lbl_803E015C;
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
            cfg.velocityZ = lbl_803E0134;
        }
        cfg.scale = lbl_803E015C;
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
