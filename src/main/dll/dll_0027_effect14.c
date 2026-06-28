/*
 * effect14 (DLL 0x27) - one of the numbered particle-effect DLLs.
 * Its single worker, Effect14_func04, fills an EffectSpawnParams request
 * for one of a fixed set of effect ids (0x4b0..0x4cd) and hands it to
 * gExpgfxInterface->spawnEffect. Per-id it sets the particle kind,
 * lifetime (count), alpha, behaviour/render flags and a randomised
 * position/velocity/scale (via randomGetRange and the lbl_803E.. float
 * constants); id 0x4c5 rotates a velocity by the model's rotation
 * (vecRotateZXY) and seeds the shared source params gEffect14SharedSrcParams.
 *
 * flags bit 0x200000 means the caller supplied an explicit EffectSrcParams
 * source (copied into the request); behaviour-flag bit 1 then adds either
 * that source position or the model's world position (model+0x18..0x20)
 * to the spawn position.
 */
#include "main/game_object.h"
#include "main/dll/effectsrcparams_struct.h"
#include "main/dll/effectspawnparams_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

#define EFFECT_FLAG_HAS_SRC 0x200000

extern EffectSrcParams gEffect14SharedSrcParams;

extern f32 lbl_803E0000;
extern f32 lbl_803E0004;
extern f32 lbl_803E0008;
extern f32 lbl_803E000C;
extern f32 lbl_803E0010;
extern f32 lbl_803E0014;
extern f32 lbl_803E0018;
extern f32 lbl_803E001C;
extern f32 lbl_803E0020;
extern f32 lbl_803E0024;
extern f32 lbl_803E0028;
extern f32 lbl_803E002C;
extern f32 lbl_803E0030;
extern f32 lbl_803E0034;
extern f32 lbl_803E0038;
extern f32 lbl_803E003C;
extern f32 lbl_803E0040;
extern f32 lbl_803E0044;
extern f32 lbl_803E0048;
extern f32 lbl_803E004C;
extern f32 lbl_803E0050;
extern f32 lbl_803E0054;
extern f32 lbl_803E0058;
extern f32 lbl_803E005C;
extern f32 lbl_803E0060;
extern f32 lbl_803E0064;
extern f32 lbl_803E0068;
extern f32 lbl_803E006C;
extern f32 lbl_803E0070;
extern f32 lbl_803E0074;
extern f32 lbl_803E0078;
extern f32 lbl_803E007C;
extern f32 lbl_803E0080;
extern f64 lbl_803E0088;
extern f32 lbl_803E0090;
extern f32 lbl_803E0094;

int Effect14_func04(s16* obj, int id, EffectSrcParams* src, u32 flags, u8 srcByte, u16* extraArgs)
{
    EffectSrcParams rotCtx;
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
    p.posX = lbl_803E0000;
    p.posY = lbl_803E0000;
    p.posZ = lbl_803E0000;
    p.velX = lbl_803E0000;
    p.velY = lbl_803E0000;
    p.velZ = lbl_803E0000;
    p.scale = lbl_803E0000;
    p.count = 0;
    p.unk04 = -1;
    p.alpha = 0xff;
    p.unk61 = 0;
    p.kind = 0;
    p.colD = 0xffff;
    p.colE = 0xffff;
    p.colF = 0xffff;
    p.colA = 0xffff;
    p.colB = 0xffff;
    p.colC = 0xffff;
    switch (id)
    {
    case 0x4b0:
        if (extraArgs == NULL)
        {
            return 0;
        }
        p.alpha = *extraArgs >> 1;
        p.scale = lbl_803E0004 * p.alpha;
        p.count = 1;
        p.flagsA = 0x80000;
        p.flagsB = 0x800;
        p.kind = 0xc7e;
        break;
    case 0x4b1:
        p.velX = lbl_803E0008 * (f32)(int)randomGetRange(-100, 100);
        p.velY = lbl_803E000C * (f32)(int)randomGetRange(-0x19, 0x96);
        p.velZ = lbl_803E0008 * (f32)(int)randomGetRange(-100, 100);
        p.count = 100;
        p.scale = lbl_803E0010;
        p.flagsA = 0x1180200;
        p.flagsB = 0x4000800;
        p.kind = 0x167;
        p.colD = 0xff00;
        p.colE = 0xff00;
        p.colF = 0xff00;
        p.colA = 0xff00;
        p.colB = 0;
        p.colC = 0;
        p.flagsB = 0x20;
        break;
    case 0x4b2:
        p.count = 0x46;
        p.scale = lbl_803E0014;
        p.flagsA = 0x100100;
        p.flagsB = 0x4000800;
        p.kind = 0x73;
        p.colD = 0xff00;
        p.colE = 0xff00;
        p.colF = 0xff00;
        p.colA = 0xff00;
        p.colB = 0;
        p.colC = 0xff00;
        p.flagsB = 0x20;
        p.alpha = 0x7f;
        break;
    case 0x4b3:
        p.count = 0x23;
        p.scale = lbl_803E0018;
        p.flagsA = 0x100200;
        p.flagsB = 0x4000800;
        p.kind = 0x73;
        break;
    case 0x4b4:
        p.posX = (f32)(int)randomGetRange(-1, 1);
        p.posY = (f32)(int)randomGetRange(-7, 7);
        p.posZ = (f32)(int)randomGetRange(-1, 1);
        p.velX = lbl_803E000C * (f32)(int)randomGetRange(-7, 7);
        p.velY = lbl_803E000C * (f32)(int)randomGetRange(0, 0x1e);
        p.velZ = lbl_803E000C * (f32)(int)randomGetRange(-7, 7);
        p.scale = lbl_803E001C * (f32)(int)randomGetRange(0x32, 100);
        p.alpha = randomGetRange(0x5c, 0xc0);
        p.count = randomGetRange(0x32, 0x50);
        p.flagsA = 0x1180000;
        p.flagsB = 0x4400820;
        p.kind = 0x30;
        p.colD = 0;
        p.colE = randomGetRange(0, 0xffff);
        p.colF = randomGetRange(0, 0xffff);
        p.colA = 0;
        p.colB = 0xff00;
        p.colC = randomGetRange(0, 0xffff);
        break;
    case 0x4b5:
        if (extraArgs != NULL)
        {
            p.velX = *(f32*)extraArgs;
            p.velY = *((f32*)extraArgs + 1);
            p.velZ = *((f32*)extraArgs + 2);
        }
        p.scale = lbl_803E0020;
        p.count = 0x5f;
        p.flagsA = 0x1180200;
        p.flagsB = 0x4000820;
        p.kind = 0x62;
        p.colD = 0;
        p.colE = randomGetRange(0x8000, 0xffff);
        p.colF = 0;
        p.colA = randomGetRange(0, 0x8000);
        p.colB = randomGetRange(0, 0xffff);
        p.colC = 0;
        break;
    case 0x4b6:
        if (extraArgs != NULL)
        {
            p.velX = *(f32*)extraArgs;
            p.velY = *((f32*)extraArgs + 1);
            p.velZ = *((f32*)extraArgs + 2);
        }
        p.alpha = 0x40;
        p.scale = lbl_803E0024;
        p.count = 0x32;
        p.flagsA = 0x180110;
        p.flagsB = 0x4000800;
        p.kind = 0x62;
        break;
    case 0x4b7:
        p.posX = (f32)(int)randomGetRange(-0x14, 0x14);
        p.posY = lbl_803E0028;
        p.posZ = (f32)(int)randomGetRange(-0x14, 0x14);
        p.velX = lbl_803E000C * (f32)(int)randomGetRange(-100, 100);
        p.velY = lbl_803E000C * (f32)(int)randomGetRange(0, 0x32);
        p.velZ = lbl_803E000C * (f32)(int)randomGetRange(-100, 100);
        p.scale = lbl_803E000C;
        p.count = 0x28;
        p.flagsA = 0x80200;
        p.kind = 0x5f;
        p.alpha = 0x3f;
        break;
    case 0x4b8:
        if (extraArgs != NULL)
        {
            p.velX = *(f32*)extraArgs;
            p.velY = *((f32*)extraArgs + 1);
            p.velZ = *((f32*)extraArgs + 2);
        }
        p.count = 0x25;
        p.scale = lbl_803E002C;
        p.flagsA = 0x80200;
        p.flagsB = 0x4000800;
        if ((int)randomGetRange(0, 2) == 0)
        {
            p.kind = 0xc0e;
        }
        else
        {
            p.kind = randomGetRange(0x156, 0x157);
        }
        break;
    case 0x4ba:
        p.posX = (f32)(int)randomGetRange(-7, 7);
        p.posY = (f32)(int)randomGetRange(-7, 7);
        p.posZ = (f32)(int)randomGetRange(-7, 7);
        p.velX = lbl_803E0024 * (f32)(int)randomGetRange(-0x32, 0x32);
        p.velY = lbl_803E0024 * (f32)(int)randomGetRange(-0x32, 0x32);
        p.velZ = lbl_803E0024 * (f32)(int)randomGetRange(-0x32, 0x32);
        p.scale = lbl_803E000C;
        p.count = 0x28;
        p.alpha = 0x96;
        p.flagsA = 0x1080200;
        p.kind = 0x62;
        p.colD = 0;
        p.colE = 0xffff;
        p.colF = 0;
        p.colA = 0xffff;
        p.colB = 0xffff;
        p.colC = 0x7fff;
        p.flagsB = 0x4000820;
        break;
    case 0x4bb:
        p.count = 0x24;
        p.scale = lbl_803E0030;
        p.flagsA = 0x100200;
        p.kind = 0x27;
        p.colD = 0xff00;
        p.colE = 0xff00;
        p.colF = 0xff00;
        p.colA = 0;
        p.colB = 0xff00;
        p.colC = 0;
        p.flagsB = 0x4000820;
        break;
    case 0x4bc:
        if (extraArgs == NULL)
        {
            return 0;
        }
        p.posX = lbl_803E0034 * ((f32)p.alpha * (f32)(int)randomGetRange(-10, 10));
        p.posY = lbl_803E0034 * ((f32)p.alpha * (f32)(int)randomGetRange(0, 10));
        p.posZ = lbl_803E0034 * ((f32)p.alpha * (f32)(int)randomGetRange(-10, 10));
        p.alpha = *(u32*)extraArgs;
        p.scale = lbl_803E0038 * p.alpha + lbl_803E0038;
        p.count = randomGetRange(0xf, 0x1e);
        p.flagsA = 0xc1080100;
        p.flagsB = 0x800;
        p.kind = 0xdb;
        break;
    case 0x4bd:
        p.posX = (f32)(int)randomGetRange(-5, 5);
        p.posY = (f32)(int)randomGetRange(0, 0xf);
        p.posZ = (f32)(int)randomGetRange(-5, 5);
        p.velY = lbl_803E003C;
        p.scale = lbl_803E0040 * (f32)(int)randomGetRange(5, 10);
        p.count = randomGetRange(0x3c, 0x5a);
        p.alpha = 0x5a;
        p.flagsA = 0xc0180200;
        p.kind = 0x5f;
        p.colD = 0xff00;
        p.colE = 0xff00;
        p.colF = 0;
        p.colA = 0xff00;
        p.colB = 0;
        p.colC = 0x8000;
        p.flagsB = 0x4000820;
        break;
    case 0x4be:
        p.posX = (f32)(int)randomGetRange(-0x1c2, 0x1c2);
        p.posY = lbl_803E0044;
        p.posZ = (f32)(int)randomGetRange(-0x1c2, 0x1c2);
        p.velX = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
        p.velY = lbl_803E0048 * (f32)(int)randomGetRange(0, 0x14);
        p.velZ = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
        p.scale = lbl_803E0050 * (f32)(int)randomGetRange(0, 10) + lbl_803E004C;
        p.count = randomGetRange(0xbe, 0xfa);
        p.flagsA = 0x81488000;
        p.kind = randomGetRange(0, 2) + 0x208;
        p.colD = 0x2000;
        p.colE = 0x8000;
        p.colF = 0xc000;
        p.colA = 0xc000;
        p.colB = 0xff00;
        p.colC = 0xff00;
        p.flagsB = 0x20;
        break;
    case 0x4bf:
        p.posX = (f32)(int)randomGetRange(-0x6e, 0x6e);
        p.posY = lbl_803E0054;
        p.posZ = (f32)(int)randomGetRange(-0x3c, 0x3c);
        p.scale = lbl_803E0058;
        p.count = 100;
        p.flagsA = 0x11000004;
        p.kind = 0x151;
        p.colD = 0xff00;
        p.colE = 0x4000;
        p.colF = 0;
        p.colA = 0x4000;
        p.colB = 0xc800;
        p.colC = 0;
        p.unk04 = 0x4c0;
        p.flagsB = 0x20;
        break;
    case 0x4c0:
        p.posY = lbl_803E005C;
        p.count = 0x4b;
        p.scale = lbl_803E0060 * (f32)(int)p.count;
        p.flagsA = 0xa100200;
        p.kind = 0x56;
        break;
    case 0x4c1:
        p.velX = lbl_803E000C * (f32)(int)randomGetRange(-5, 5);
        p.velY = lbl_803E000C * (f32)(int)randomGetRange(-5, 5);
        p.velZ = lbl_803E000C * (f32)(int)randomGetRange(-5, 5);
        p.posX = (f32)(int)randomGetRange(-0x78, 0x78);
        p.posY = (f32)(int)(randomGetRange(-1, 1) * 0xc);
        p.posZ = (f32)(int)randomGetRange(-0x46, 0x46);
        p.scale = lbl_803E0008;
        p.count = 200;
        p.flagsA = 0xa100100;
        p.kind = 0xc10;
        p.colD = 0xff00;
        p.colE = 0xff00;
        p.colF = 0;
        p.colA = 0xff00;
        p.colB = 0;
        p.colC = 0x8000;
        p.flagsB = 0x20;
        break;
    case 0x4c2:
        p.velX = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
        p.velZ = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
        p.scale = lbl_803E0064;
        p.count = 0x46;
        p.flagsA = 0xa100200;
        p.flagsB = 0x1000800;
        p.kind = 0x5f;
        p.alpha = 0x40;
        break;
    case 0x4c3:
        p.velX = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
        p.velZ = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
        p.posX = (f32)(int)randomGetRange(-400, 400);
        p.posZ = (f32)(int)randomGetRange(-400, 400);
        p.scale = lbl_803E0068;
        p.count = 600;
        p.alpha = 0x7f;
        p.flagsA = 0xa100100;
        p.kind = 0x62;
        break;
    case 0x4c4:
        p.scale = lbl_803E0068;
        p.count = randomGetRange(100, 300);
        p.alpha = 0xb4;
        p.flagsA = 0x80180208;
        p.kind = 0x62;
        break;
    case 0x4c5:
        if (src == NULL)
        {
            gEffect14SharedSrcParams.x = lbl_803E0000;
            gEffect14SharedSrcParams.y = lbl_803E0000;
            gEffect14SharedSrcParams.z = lbl_803E0000;
            gEffect14SharedSrcParams.w = lbl_803E006C;
            gEffect14SharedSrcParams.rot0 = 0;
            gEffect14SharedSrcParams.rot1 = 0;
            gEffect14SharedSrcParams.rot2 = 0;
        }
        p.velX = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
        p.velY = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
        p.velZ = lbl_803E0070 * (f32)(int)randomGetRange(10, 0x1e);
        rotCtx.x = lbl_803E0000;
        rotCtx.y = lbl_803E0000;
        rotCtx.z = lbl_803E0000;
        rotCtx.w = lbl_803E006C;
        rotCtx.rot2 = ((GameObject*)obj)->anim.rotZ;
        rotCtx.rot1 = ((GameObject*)obj)->anim.rotY;
        rotCtx.rot0 = ((GameObject*)obj)->anim.rotX;
        vecRotateZXY(&rotCtx, &p.velX);
        p.flagsA = 0x3000000;
        p.flagsB = 0x200000;
        p.scale = lbl_803E000C;
        p.alpha = 0xff;
        p.count = 0x32;
        p.kind = 0x151;
        break;
    case 0x4c6:
        p.alpha = 0x40;
        p.scale = lbl_803E003C;
        p.count = 1;
        p.flagsA = 0x6000000;
        p.kind = 0x45b;
        p.srcX = lbl_803E0000;
        p.srcY = lbl_803E0000;
        p.srcZ = lbl_803E0000;
        p.srcW = lbl_803E006C;
        p.rot2 = ((GameObject*)obj)->anim.rotZ;
        p.rot1 = ((GameObject*)obj)->anim.rotY;
        p.rot0 = ((GameObject*)obj)->anim.rotX;
        break;
    case 0x4c7:
        p.alpha = 0x40;
        p.scale = lbl_803E0074;
        p.count = 1;
        p.flagsA = 0x6000000;
        p.kind = 0x45b;
        p.srcX = lbl_803E0000;
        p.srcY = lbl_803E0000;
        p.srcZ = lbl_803E0000;
        p.srcW = lbl_803E006C;
        p.rot2 = ((GameObject*)obj)->anim.rotZ;
        p.rot1 = ((GameObject*)obj)->anim.rotY;
        p.rot0 = ((GameObject*)obj)->anim.rotX;
        break;
    case 0x4c8:
        p.posX = lbl_803E0078 * (f32)(int)randomGetRange(-10, 10);
        p.posY = lbl_803E0078 * (f32)(int)randomGetRange(-10, 10);
        p.posZ = lbl_803E0078 * (f32)(int)randomGetRange(-10, 10);
        p.scale = lbl_803E007C;
        p.count = randomGetRange(0x4b, 100);
        p.alpha = 0x7f;
        p.flagsA = 0x1080200;
        p.kind = 0x151;
        break;
    case 0x4c9:
        p.count = randomGetRange(0x3c, 100);
        p.velX = lbl_803E003C * (f32)(int)randomGetRange(-0x32, 0x32);
        p.velY = lbl_803E0080 * (f32)(int)p.count;
        p.velZ = lbl_803E003C * (f32)(int)randomGetRange(-0x32, 0x32);
        p.scale = lbl_803E0010;
        p.flagsA = 0x3000000;
        p.flagsB = 0x600020;
        p.kind = 0x20d;
        p.alpha = 0xff;
        p.colA = 0xffff;
        p.colB = 0xffff;
        p.colC = 0xffff;
        p.colD = 0xffff;
        p.colE = 0x4000;
        p.colF = 0;
        break;
    case 0x4ca:
        p.posX = lbl_803E0048 * (f32)(int)randomGetRange(-200, 200);
        p.posZ = lbl_803E0048 * (f32)(int)randomGetRange(-200, 200);
        p.velY = lbl_803E0088 * (f32)(int)randomGetRange(0xf, 0x2d);
        p.scale = lbl_803E0090 * (f32)(int)randomGetRange(6, 0xc);
        p.count = randomGetRange(0x46, 0x82);
        p.flagsA = 0x1580000;
        p.flagsB = 0x400000;
        p.kind = 0x23b;
        p.alpha = 0xff;
        break;
    case 0x4cb:
        p.velY = lbl_803E0068 * (f32)(int)randomGetRange(8, 10);
        p.scale = lbl_803E0094 * (f32)(int)randomGetRange(6, 10);
        p.count = randomGetRange(0x3c, 0x78);
        p.flagsA = 0x80080000;
        p.flagsB = 0x4440820;
        p.colA = 0xffff;
        p.colB = 0xffff;
        p.colC = 0;
        p.colD = 0xffff;
        p.colE = 0;
        p.colF = 0;
        p.kind = 0xc0b;
        p.alpha = 0x40;
        break;
    case 0x4cc:
        p.count = randomGetRange(0x3c, 100);
        p.velX = lbl_803E003C * (f32)(int)randomGetRange(-0x32, 0x32);
        p.velY = lbl_803E0080 * (f32)(int)p.count;
        p.velZ = lbl_803E003C * (f32)(int)randomGetRange(-0x32, 0x32);
        p.scale = lbl_803E0010;
        p.flagsA = 0x3000000;
        p.flagsB = 0x600020;
        p.kind = 0x20d;
        p.alpha = 0xff;
        p.colA = 0xffff;
        p.colB = 0xffff;
        p.colC = 0xffff;
        p.colD = 0x4000;
        p.colE = 0xffff;
        p.colF = 0;
        break;
    case 0x4cd:
        p.velY = lbl_803E0068 * (f32)(int)randomGetRange(8, 10);
        p.scale = lbl_803E0094 * (f32)(int)randomGetRange(6, 10);
        p.count = randomGetRange(0x3c, 0x78);
        p.flagsA = 0x80080000;
        p.flagsB = 0x4440820;
        p.colA = 0xffff;
        p.colB = 0xffff;
        p.colC = 0;
        p.colD = 0;
        p.colE = 0xffff;
        p.colF = 0;
        p.kind = 0xc0b;
        p.alpha = 0x40;
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

void Effect14_func05_nop(void)
{
}

void Effect14_func03_nop(void)
{
}

void Effect14_release(void)
{
}

void Effect14_initialise(void)
{
}
