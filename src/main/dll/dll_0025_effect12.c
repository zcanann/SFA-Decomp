/*
 * effect12 (DLL 0x25) - one of the numbered particle-effect DLLs.
 * Its single worker, Effect12_func04, fills an EffectSpawnParams request
 * for one of a fixed set of effect ids (0x47e..0x48c) and hands it to
 * gExpgfxInterface->spawnEffect. Per-id it sets the particle kind,
 * lifetime (count), alpha, behaviour/render flags and a randomised
 * position/velocity/scale (via randomGetRange and per-effect tuning
 * constants); id 0x48c additionally rotates a velocity by the model's
 * rotX (vecRotateZXY).
 *
 * flags bit 0x200000 means the caller supplied an explicit EffectSrcParams
 * source (copied into the request); behaviour-flag bit 1 then adds either
 * that source position or the model's world position (model+0x18..0x20)
 * to the spawn position.
 */
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/effectsrcparams_struct.h"
#include "main/dll/effectspawnparams_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/vecmath.h"
#include "main/dll/dll_0025_effect12.h"

#define EFFECT_FLAG_HAS_SRC 0x200000

EffectSrcParams gEffect12DefaultSrc;

ObjectDescriptor6 lbl_80310D80 = {
    0,
    0,
    0,
    0x00050000,
    (ObjectDescriptorCallback)Effect12_initialise,
    (ObjectDescriptorCallback)Effect12_release,
    0,
    (ObjectDescriptorCallback)Effect12_func03_nop,
    (ObjectDescriptorCallback)Effect12_func04,
    (ObjectDescriptorCallback)Effect12_func05_nop,
};

int Effect12_func04(s16* obj, int id, EffectSrcParams* src, u32 flags, u8 srcByte, f32* auxParam)
{
    EffectSrcParams local;
    EffectSpawnParams p;
    u32 hasOffset;

    if (obj == NULL)
    {
        return -1;
    }
    hasOffset = flags & EFFECT_FLAG_HAS_SRC;
    if (hasOffset != 0)
    {
        if (src == NULL)
        {
            return -1;
        }
        p.srcX = src->x;
        p.srcY = src->y;
        p.srcZ = src->z;
        p.srcW = src->w;
        p.rot2 = src->rot2;
        p.rot1 = src->rot1;
        p.rot0 = src->rot0;
        p.srcFlag = srcByte;
    }
    p.flagsA = 0;
    p.flagsB = 0;
    p.idByte = id;
    p.model = obj;
    p.posX = 0.0f;
    p.posY = 0.0f;
    p.posZ = 0.0f;
    p.velX = 0.0f;
    p.velY = 0.0f;
    p.velZ = 0.0f;
    p.scale = 0.0f;
    p.count = 0;
    p.unk04 = -1;
    p.alpha = 0xff;
    p.linkGroup = 0;
    p.kind = 0;
    p.colD = 0xffff;
    p.colE = 0xffff;
    p.colF = 0xffff;
    p.colA = 0xffff;
    p.colB = 0xffff;
    p.colC = 0xffff;
    switch (id)
    {
    case 0x47e:
        p.scale = 0.075f;
        p.count = randomGetRange(0x32, 0x3c);
        p.alpha = 0x4b;
        p.flagsA = 0x180110;
        p.flagsB = 0x4000800;
        p.kind = 0x159;
        break;
    case 0x483:
        if (src == NULL)
        {
            gEffect12DefaultSrc.x = 0.0f;
            gEffect12DefaultSrc.y = 0.0f;
            gEffect12DefaultSrc.z = 0.0f;
            gEffect12DefaultSrc.w = 1.0f;
            gEffect12DefaultSrc.rot0 = 0;
            gEffect12DefaultSrc.rot1 = 0;
            gEffect12DefaultSrc.rot2 = 0;
            src = &gEffect12DefaultSrc;
        }
        p.posX = (f32)(int)randomGetRange(-10, 10);
        p.posZ = (f32)(int)randomGetRange(-10, 10);
        p.velX = 0.02f * src->w * (f32)(int)randomGetRange(-100, 100);
        p.velY = 0.02f * src->w * (f32)(int)randomGetRange(0x28, 0x50);
        p.velZ = 0.02f * src->w * (f32)(int)randomGetRange(-100, 100);
        p.scale = 0.03f;
        p.count = 0x3c;
        p.flagsA = 0x81080200;
        p.flagsB = 0x8000000;
        p.kind = 0x2b;
        p.alpha = 0x3c;
        break;
    case 0x484:
        if (src == NULL)
        {
            gEffect12DefaultSrc.x = 0.0f;
            gEffect12DefaultSrc.y = 0.0f;
            gEffect12DefaultSrc.z = 0.0f;
            gEffect12DefaultSrc.w = 1.0f;
            gEffect12DefaultSrc.rot0 = 0;
            gEffect12DefaultSrc.rot1 = 0;
            gEffect12DefaultSrc.rot2 = 0;
            src = &gEffect12DefaultSrc;
        }
        p.velX = 0.03f * src->w * (f32)(int)randomGetRange(-100, 100);
        p.velY = 0.03f * src->w * (f32)(int)randomGetRange(0x14, 0x50);
        p.velZ = 0.03f * src->w * (f32)(int)randomGetRange(-100, 100);
        p.scale = 0.01f;
        p.count = 0x3c;
        p.flagsB = 0x200000;
        p.flagsA = 0x3000200;
        p.kind = 0x185;
        p.alpha = 0x7f;
        break;
    case 0x485:
        if (src == NULL)
        {
            gEffect12DefaultSrc.x = 0.0f;
            gEffect12DefaultSrc.y = 0.0f;
            gEffect12DefaultSrc.z = 0.0f;
            gEffect12DefaultSrc.w = 1.0f;
            gEffect12DefaultSrc.rot0 = 0;
            gEffect12DefaultSrc.rot1 = 0;
            gEffect12DefaultSrc.rot2 = 0;
            src = &gEffect12DefaultSrc;
        }
        p.posX = (f32)(int)randomGetRange(-10, 10);
        p.posZ = (f32)(int)randomGetRange(-10, 10);
        p.velX = 0.02f * src->w * (f32)(int)randomGetRange(-100, 100);
        p.velY = 0.02f * src->w * (f32)(int)randomGetRange(0x28, 0x50);
        p.velZ = 0.02f * src->w * (f32)(int)randomGetRange(-100, 100);
        p.scale = 0.03f;
        p.count = 0x3c;
        p.flagsA = 0x81080200;
        p.flagsB = 0x8000000;
        p.kind = 0x2b;
        p.alpha = 0x3c;
        break;
    case 0x486:
        p.posX = 27.5f;
        p.posY = 5.0f;
        p.posZ = 27.5f;
        p.velX = 0.0015f * (f32)(int)randomGetRange(-100, 100);
        p.velY = 0.0019f * (f32)(int)randomGetRange(-0x28, 0x140);
        p.velZ = 0.0015f * (f32)(int)randomGetRange(-100, 100);
        p.scale = 0.000095f * (f32)(int)randomGetRange(0xa, 0xf);
        p.count = randomGetRange(0x2c, 0x2f);
        p.kind = 0x156;
        p.alpha = 0x7f;
        p.flagsA = 0xc80000;
        p.flagsB = 0x908;
        break;
    case 0x487:
        if (auxParam == NULL)
        {
            return 0;
        }
        p.velX = *auxParam;
        p.velY = auxParam[1];
        p.velZ = auxParam[2];
        p.scale = 0.025f;
        p.alpha = 0x40;
        p.count = 100;
        p.flagsA = 0x3000200;
        p.kind = 0x62;
        p.flagsB = 0x200000;
        break;
    case 0x488:
        p.posX = 27.5f + (f32)(int)randomGetRange(-0x18, 0x18);
        p.posY = 0.0f;
        p.posZ = 27.5f + (f32)(int)randomGetRange(-0x18, 0x18);
        p.velX = 0.01f * (f32)(int)randomGetRange(-5, 5);
        p.velY = 0.01f * (f32)(int)randomGetRange(2, 10);
        p.velZ = 0.01f * (f32)(int)randomGetRange(-5, 5);
        p.scale = 0.02f;
        p.count = 0x6e;
        p.flagsA = 0x80180200;
        p.flagsB = 0x8000000;
        p.kind = 0x2b;
        p.alpha = 0xff;
        break;
    case 0x489:
        p.scale = 0.04f;
        p.count = randomGetRange(0x32, 100);
        p.alpha = 0x7f;
        p.flagsA = 0x1180100;
        p.kind = 0x2b;
        p.flagsB = 0x4000000;
        break;
    case 0x48a:
        p.velX = 0.02f * (f32)(int)randomGetRange(-0x32, 0x32);
        p.velY = 0.02f * (f32)(int)randomGetRange(0x1e, 0x32);
        p.velZ = 0.02f * (f32)(int)randomGetRange(-0x32, 0x32);
        p.scale = 0.06f;
        p.count = randomGetRange(0x32, 0x46);
        p.alpha = 0x7f;
        p.flagsA = 0x1180100;
        p.flagsB = 0x8000000;
        p.kind = 0x2b;
        break;
    case 0x48b:
        p.posX = (f32)(int)randomGetRange(-0x32, 0x32);
        p.posY = 100.0f;
        p.posZ = (f32)(int)randomGetRange(-0x32, 0x32);
        p.velX = 0.01f * (f32)(int)randomGetRange(-0x14, 0x14);
        p.velY = 0.03f * (f32)(int)randomGetRange(-0x14, 0);
        p.velZ = 0.01f * (f32)(int)randomGetRange(-0x14, 0x14);
        p.scale = 0.00015f * (f32)(int)randomGetRange(0, 10) + 0.002945f;
        p.count = randomGetRange(0xbe, 0xfa);
        p.flagsA = 0x81088000;
        p.kind = randomGetRange(0, 2) + 0x208;
        p.colD = 0xb400;
        p.colE = 0x8000;
        p.colF = 0;
        p.colA = 0xb400;
        p.colB = 0xa000;
        p.colC = 0;
        p.flagsB = 0x20;
        p.alpha = 0xd2;
        break;
    case 0x48c:
        if (src == NULL)
        {
            gEffect12DefaultSrc.x = 0.0f;
            gEffect12DefaultSrc.y = 0.0f;
            gEffect12DefaultSrc.z = 0.0f;
            gEffect12DefaultSrc.w = 1.0f;
            gEffect12DefaultSrc.rot0 = 0;
            gEffect12DefaultSrc.rot1 = 0;
            gEffect12DefaultSrc.rot2 = 0;
        }
        if (auxParam == NULL)
        {
            return -1;
        }
        if (*(int*)auxParam == 0)
        {
            p.scale = 0.002f * (f32)(int)randomGetRange(8, 0x11);
            p.count = randomGetRange(5, 10);
            p.alpha = 0x64;
            p.flagsA = 0x80110;
            p.flagsB = 0x4000800;
        }
        else if (*(int*)auxParam == 1)
        {
            p.velX = 0.02f * (f32)(int)randomGetRange(-0x32, 0x32);
            p.velY = 0.02f * (f32)(int)randomGetRange(-0x32, 0x32);
            p.velZ = 0.02f * (f32)(int)randomGetRange(0, 0x32);
            p.scale = 0.00035f * (f32)(int)randomGetRange(10, 0x14);
            p.count = 0x2d;
            p.alpha = 0;
            p.flagsA = 0x880014;
            p.flagsB = 0x4010808;
        }
        else
        {
            p.velX = 0.02f * (f32)(int)randomGetRange(-0x28, 0x28);
            p.velY = 0.04f * (f32)(int)randomGetRange(-10, 0x1e);
            p.velZ = 0.04f * (f32)(int)randomGetRange(0, 0x28);
            local.x = 0.0f;
            local.y = 0.0f;
            local.z = 0.0f;
            local.w = 1.0f;
            local.rot2 = 0;
            local.rot1 = 0;
            local.rot0 = ((GameObject*)obj)->anim.rotX;
            vecRotateZXY(&local.rotation.x, &p.velX);
            p.scale = 0.02f;
            p.count = 100;
            p.alpha = 0xff;
            p.flagsB = 0x300800;
            p.flagsA = 0x3000210;
        }
        p.kind = randomGetRange(0x156, 0x157);
        break;
    default:
        return -1;
    }
    p.flagsA = p.flagsA | flags;
    if (((p.flagsA & 1) != 0) && ((p.flagsA & 2) != 0))
    {
        p.flagsA ^= 2LL;
    }
    if ((p.flagsA & 1) != 0)
    {
        if (hasOffset != 0)
        {
            p.posX = p.posX + p.srcX;
            p.posY = p.posY + p.srcY;
            p.posZ = p.posZ + p.srcZ;
        }
        else if (p.model != NULL)
        {
            p.posX = p.posX + ((GameObject*)p.model)->anim.worldPosX;
            p.posY = p.posY + ((GameObject*)p.model)->anim.worldPosY;
            p.posZ = p.posZ + ((GameObject*)p.model)->anim.worldPosZ;
        }
    }
    return (*gExpgfxInterface)->spawnEffect(&p, -1, id, 0);
}

void Effect12_func05_nop(void)
{
}

void Effect12_func03_nop(void)
{
}

void Effect12_release(void)
{
}

void Effect12_initialise(void)
{
}
