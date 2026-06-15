#include "main/game_object.h"
#include "main/dll/effectsrcparams_struct.h"
#include "main/dll/effectspawnparams_struct.h"
#include "main/dll_000A_expgfx.h"

extern u32 randomGetRange(int min, int max);

extern void vecRotateZXY(void* params, f32* vec);

extern EffectSrcParams lbl_8039C3E0;
extern f32 lbl_803DFFA8;
extern f32 lbl_803DFFAC;
extern f32 lbl_803DFFB0;
extern f32 lbl_803DFFB4;
extern f32 lbl_803DFFB8;
extern f32 lbl_803DFFBC;
extern f32 lbl_803DFFC0;
extern f32 lbl_803DFFC4;
extern f32 lbl_803DFFC8;
extern f32 lbl_803DFFCC;
extern f32 lbl_803DFFD0;
extern f32 lbl_803DFFD4;
extern f32 lbl_803DFFD8;
extern f32 lbl_803DFFDC;
extern f32 lbl_803DFFE0;
extern f32 lbl_803DFFE4;
extern f32 lbl_803DFFE8;
extern f32 lbl_803DFFEC;
extern f32 lbl_803DFFF0;


int Effect12_func04(s16* obj, int id, EffectSrcParams* src, uint flags, u8 srcByte, f32* p6)
{
  EffectSrcParams local;
  EffectSpawnParams p;
  uint hasOffset;

  if (obj == NULL)
  {
    return -1;
  }
  hasOffset = flags & 0x200000;
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
  p.posX = lbl_803DFFA8;
  p.posY = lbl_803DFFA8;
  p.posZ = lbl_803DFFA8;
  p.velX = lbl_803DFFA8;
  p.velY = lbl_803DFFA8;
  p.velZ = lbl_803DFFA8;
  p.scale = lbl_803DFFA8;
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
  case 0x47e:
    p.scale = lbl_803DFFAC;
    p.count = randomGetRange(0x32, 0x3c);
    p.alpha = 0x4b;
    p.flagsA = 0x180110;
    p.flagsB = 0x4000800;
    p.kind = 0x159;
    break;
  case 0x483:
    if (src == NULL)
    {
      lbl_8039C3E0.x = lbl_803DFFA8;
      lbl_8039C3E0.y = lbl_803DFFA8;
      lbl_8039C3E0.z = lbl_803DFFA8;
      lbl_8039C3E0.w = lbl_803DFFB0;
      lbl_8039C3E0.rot0 = 0;
      lbl_8039C3E0.rot1 = 0;
      lbl_8039C3E0.rot2 = 0;
      src = &lbl_8039C3E0;
    }
    p.posX = (f32)(int)randomGetRange(-10, 10);
    p.posZ = (f32)(int)randomGetRange(-10, 10);
    p.velX = lbl_803DFFB4 * src->w * (f32)(int)randomGetRange(-100, 100);
    p.velY = lbl_803DFFB4 * src->w * (f32)(int)randomGetRange(0x28, 0x50);
    p.velZ = lbl_803DFFB4 * src->w * (f32)(int)randomGetRange(-100, 100);
    p.scale = lbl_803DFFB8;
    p.count = 0x3c;
    p.flagsA = 0x81080200;
    p.flagsB = 0x8000000;
    p.kind = 0x2b;
    p.alpha = 0x3c;
    break;
  case 0x484:
    if (src == NULL)
    {
      lbl_8039C3E0.x = lbl_803DFFA8;
      lbl_8039C3E0.y = lbl_803DFFA8;
      lbl_8039C3E0.z = lbl_803DFFA8;
      lbl_8039C3E0.w = lbl_803DFFB0;
      lbl_8039C3E0.rot0 = 0;
      lbl_8039C3E0.rot1 = 0;
      lbl_8039C3E0.rot2 = 0;
      src = &lbl_8039C3E0;
    }
    p.velX = lbl_803DFFB8 * src->w * (f32)(int)randomGetRange(-100, 100);
    p.velY = lbl_803DFFB8 * src->w * (f32)(int)randomGetRange(0x14, 0x50);
    p.velZ = lbl_803DFFB8 * src->w * (f32)(int)randomGetRange(-100, 100);
    p.scale = lbl_803DFFBC;
    p.count = 0x3c;
    p.flagsB = 0x200000;
    p.flagsA = 0x3000200;
    p.kind = 0x185;
    p.alpha = 0x7f;
    break;
  case 0x485:
    if (src == NULL)
    {
      lbl_8039C3E0.x = lbl_803DFFA8;
      lbl_8039C3E0.y = lbl_803DFFA8;
      lbl_8039C3E0.z = lbl_803DFFA8;
      lbl_8039C3E0.w = lbl_803DFFB0;
      lbl_8039C3E0.rot0 = 0;
      lbl_8039C3E0.rot1 = 0;
      lbl_8039C3E0.rot2 = 0;
      src = &lbl_8039C3E0;
    }
    p.posX = (f32)(int)randomGetRange(-10, 10);
    p.posZ = (f32)(int)randomGetRange(-10, 10);
    p.velX = lbl_803DFFB4 * src->w * (f32)(int)randomGetRange(-100, 100);
    p.velY = lbl_803DFFB4 * src->w * (f32)(int)randomGetRange(0x28, 0x50);
    p.velZ = lbl_803DFFB4 * src->w * (f32)(int)randomGetRange(-100, 100);
    p.scale = lbl_803DFFB8;
    p.count = 0x3c;
    p.flagsA = 0x81080200;
    p.flagsB = 0x8000000;
    p.kind = 0x2b;
    p.alpha = 0x3c;
    break;
  case 0x486:
    p.posX = lbl_803DFFC0;
    p.posY = lbl_803DFFC4;
    p.posZ = lbl_803DFFC0;
    p.velX = lbl_803DFFC8 * (f32)(int)randomGetRange(-100, 100);
    p.velY = lbl_803DFFCC * (f32)(int)randomGetRange(-0x28, 0x140);
    p.velZ = lbl_803DFFC8 * (f32)(int)randomGetRange(-100, 100);
    p.scale = lbl_803DFFD0 * (f32)(int)randomGetRange(0xa, 0xf);
    p.count = randomGetRange(0x2c, 0x2f);
    p.kind = 0x156;
    p.alpha = 0x7f;
    p.flagsA = 0xc80000;
    p.flagsB = 0x908;
    break;
  case 0x487:
    if (p6 == NULL)
    {
      return 0;
    }
    p.velX = *p6;
    p.velY = p6[1];
    p.velZ = p6[2];
    p.scale = lbl_803DFFD4;
    p.alpha = 0x40;
    p.count = 100;
    p.flagsA = 0x3000200;
    p.kind = 0x62;
    p.flagsB = 0x200000;
    break;
  case 0x488:
    p.posX = lbl_803DFFC0 + (f32)(int)randomGetRange(-0x18, 0x18);
    p.posY = lbl_803DFFA8;
    p.posZ = lbl_803DFFC0 + (f32)(int)randomGetRange(-0x18, 0x18);
    p.velX = lbl_803DFFBC * (f32)(int)randomGetRange(-5, 5);
    p.velY = lbl_803DFFBC * (f32)(int)randomGetRange(2, 10);
    p.velZ = lbl_803DFFBC * (f32)(int)randomGetRange(-5, 5);
    p.scale = lbl_803DFFB4;
    p.count = 0x6e;
    p.flagsA = 0x80180200;
    p.flagsB = 0x8000000;
    p.kind = 0x2b;
    p.alpha = 0xff;
    break;
  case 0x489:
    p.scale = lbl_803DFFD8;
    p.count = randomGetRange(0x32, 100);
    p.alpha = 0x7f;
    p.flagsA = 0x1180100;
    p.kind = 0x2b;
    p.flagsB = 0x4000000;
    break;
  case 0x48a:
    p.velX = lbl_803DFFB4 * (f32)(int)randomGetRange(-0x32, 0x32);
    p.velY = lbl_803DFFB4 * (f32)(int)randomGetRange(0x1e, 0x32);
    p.velZ = lbl_803DFFB4 * (f32)(int)randomGetRange(-0x32, 0x32);
    p.scale = lbl_803DFFDC;
    p.count = randomGetRange(0x32, 0x46);
    p.alpha = 0x7f;
    p.flagsA = 0x1180100;
    p.flagsB = 0x8000000;
    p.kind = 0x2b;
    break;
  case 0x48b:
    p.posX = (f32)(int)randomGetRange(-0x32, 0x32);
    p.posY = lbl_803DFFE0;
    p.posZ = (f32)(int)randomGetRange(-0x32, 0x32);
    p.velX = lbl_803DFFBC * (f32)(int)randomGetRange(-0x14, 0x14);
    p.velY = lbl_803DFFB8 * (f32)(int)randomGetRange(-0x14, 0);
    p.velZ = lbl_803DFFBC * (f32)(int)randomGetRange(-0x14, 0x14);
    p.scale = lbl_803DFFE8 * (f32)(int)randomGetRange(0, 10) + lbl_803DFFE4;
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
      lbl_8039C3E0.x = lbl_803DFFA8;
      lbl_8039C3E0.y = lbl_803DFFA8;
      lbl_8039C3E0.z = lbl_803DFFA8;
      lbl_8039C3E0.w = lbl_803DFFB0;
      lbl_8039C3E0.rot0 = 0;
      lbl_8039C3E0.rot1 = 0;
      lbl_8039C3E0.rot2 = 0;
    }
    if (p6 == NULL)
    {
      return -1;
    }
    if (*(int*)p6 == 0)
    {
      p.scale = lbl_803DFFEC * (f32)(int)randomGetRange(8, 0x11);
      p.count = randomGetRange(5, 10);
      p.alpha = 0x64;
      p.flagsA = 0x80110;
      p.flagsB = 0x4000800;
    }
    else if (*(int*)p6 == 1)
    {
      p.velX = lbl_803DFFB4 * (f32)(int)randomGetRange(-0x32, 0x32);
      p.velY = lbl_803DFFB4 * (f32)(int)randomGetRange(-0x32, 0x32);
      p.velZ = lbl_803DFFB4 * (f32)(int)randomGetRange(0, 0x32);
      p.scale = lbl_803DFFF0 * (f32)(int)randomGetRange(10, 0x14);
      p.count = 0x2d;
      p.alpha = 0;
      p.flagsA = 0x880014;
      p.flagsB = 0x4010808;
    }
    else
    {
      p.velX = lbl_803DFFB4 * (f32)(int)randomGetRange(-0x28, 0x28);
      p.velY = lbl_803DFFD8 * (f32)(int)randomGetRange(-10, 0x1e);
      p.velZ = lbl_803DFFD8 * (f32)(int)randomGetRange(0, 0x28);
      local.x = lbl_803DFFA8;
      local.y = lbl_803DFFA8;
      local.z = lbl_803DFFA8;
      local.w = lbl_803DFFB0;
      local.rot2 = 0;
      local.rot1 = 0;
      local.rot0 = ((GameObject*)obj)->anim.rotX;
      vecRotateZXY(&local, &p.velX);
      p.scale = lbl_803DFFB4;
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
      p.posX = p.posX + *(f32*)((char*)p.model + 0x18);
      p.posY = p.posY + *(f32*)((char*)p.model + 0x1c);
      p.posZ = p.posZ + *(f32*)((char*)p.model + 0x20);
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

void Effect14_func05_nop(void);
