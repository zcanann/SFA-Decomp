/*
 * effect11 (DLL 0x24) - a particle-effect spawner DLL.
 *
 * Effect11_func04 is the per-effect spawn handler: given a model, an effect
 * id (0x12c-0x138) and an optional EffectSrcParams source packet, it fills an
 * EffectSpawnParams config (count, scale, alpha, position/velocity, behaviour
 * flags and texture kind) - mostly from per-id tuning constants (lbl_803DFFxx)
 * and randomGetRange jitter - then hands it to the expgfx interface to spawn.
 *
 * flags bit 0x200000 selects an explicit source offset (otherwise the model's
 * world position at +0x18/0x1c/0x20 is used); behaviour-flag bit 0 enables that
 * positional offset. Ids that take no source default it to gEffect11DefaultSrcParams.
 */
#include "main/game_object.h"
#include "main/dll/effectsrcparams_struct.h"
#include "main/dll/effectspawnparams_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"





extern EffectSrcParams gEffect11DefaultSrcParams;
extern f32 lbl_803DFF3C;
extern f32 lbl_803DFF40;
extern f32 lbl_803DFF44;
extern f32 lbl_803DFF48;
extern f32 lbl_803DFF4C;
extern f32 lbl_803DFF50;
extern f32 lbl_803DFF54;
extern f32 lbl_803DFF58;
extern f32 lbl_803DFF5C;
extern f32 lbl_803DFF60;
extern f32 lbl_803DFF64;
extern f32 lbl_803DFF68;
extern f32 lbl_803DFF6C;
extern f32 lbl_803DFF70;
extern f32 lbl_803DFF74;
extern f32 lbl_803DFF78;
extern f32 lbl_803DFF7C;
extern f32 lbl_803DFF80;
extern f32 lbl_803DFF84;
extern f32 lbl_803DFF88;
extern f32 lbl_803DFF8C;
extern f32 lbl_803DFF90;
extern f32 lbl_803DFF94;
extern f32 lbl_803DFF98;
extern f32 lbl_803DFF9C;


int Effect11_func04(s16* obj, int id, EffectSrcParams* src, u32 flags, u8 srcByte)
{
  EffectSpawnParams p;
  u32 hasOffset;

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
  p.unk61 = 0;
  p.kind = 0;
  p.colD = 0xffff;
  p.colE = 0xffff;
  p.colF = 0xffff;
  p.colA = 0xffff;
  p.colB = 0xffff;
  p.colC = 0xffff;
  p.unk40 = 0;
  switch (id)
  {
  case 0x12c:
    p.scale = lbl_803DFF3C;
    p.count = 0xa;
    p.alpha = 0xff;
    p.flagsA = 0x40200;
    p.kind = 0xdb;
    break;
  case 0x12d:
    if (src == NULL)
    {
      gEffect11DefaultSrcParams.x = 0.0f;
      gEffect11DefaultSrcParams.y = 0.0f;
      gEffect11DefaultSrcParams.z = 0.0f;
      gEffect11DefaultSrcParams.w = lbl_803DFF40;
      gEffect11DefaultSrcParams.rot0 = 0;
      gEffect11DefaultSrcParams.rot1 = 0;
      gEffect11DefaultSrcParams.rot2 = 0;
      src = &gEffect11DefaultSrcParams;
    }
    p.scale = lbl_803DFF44;
    p.count = randomGetRange(0, 0x1e) + 0x46;
    p.alpha = src->w > 0.0f ? 0x50 : 0x41;
    p.flagsA = 0x80110;
    p.kind = src->w > 0.0f ? 0x7b : 0xdb;
    break;
  case 0x12e:
    if (src == NULL)
    {
      gEffect11DefaultSrcParams.x = 0.0f;
      gEffect11DefaultSrcParams.y = 0.0f;
      gEffect11DefaultSrcParams.z = 0.0f;
      gEffect11DefaultSrcParams.w = lbl_803DFF40;
      gEffect11DefaultSrcParams.rot0 = 0;
      gEffect11DefaultSrcParams.rot1 = 0;
      gEffect11DefaultSrcParams.rot2 = 0;
      src = &gEffect11DefaultSrcParams;
    }
    p.posX = lbl_803DFF48 * (f32)(int)randomGetRange(-10, 10);
    p.posY = 0.0f;
    p.posZ = lbl_803DFF4C;
    p.velY = lbl_803DFF50 * (f32)(int)randomGetRange(1, 3);
    p.velX = lbl_803DFF48 * src->x;
    p.velZ = lbl_803DFF48 * -src->z;
    p.scale = lbl_803DFF3C * (f32)(int)randomGetRange(1, 3);
    p.count = 0x19;
    p.alpha = 0x55;
    p.flagsA = 0x80118;
    p.kind = 0x5f;
    break;
  case 0x12f:
    if (src == NULL)
    {
      gEffect11DefaultSrcParams.x = 0.0f;
      gEffect11DefaultSrcParams.y = 0.0f;
      gEffect11DefaultSrcParams.z = 0.0f;
      gEffect11DefaultSrcParams.w = lbl_803DFF40;
      gEffect11DefaultSrcParams.rot0 = 0;
      gEffect11DefaultSrcParams.rot1 = 0;
      gEffect11DefaultSrcParams.rot2 = 0;
      src = &gEffect11DefaultSrcParams;
    }
    p.posX = lbl_803DFF48 * (f32)(int)randomGetRange(-10, 10);
    p.posY = 0.0f;
    p.posZ = lbl_803DFF4C;
    p.velY = lbl_803DFF50 * (f32)(int)randomGetRange(1, 3);
    p.velX = lbl_803DFF54 * src->x;
    p.velZ = lbl_803DFF54 * -src->z;
    p.scale = lbl_803DFF58 * (f32)(int)randomGetRange(1, 3);
    p.count = 0x19;
    p.alpha = 0x55;
    p.flagsA = 0x80118;
    p.kind = 0x5f;
    break;
  case 0x130:
    if (src == NULL)
    {
      gEffect11DefaultSrcParams.x = 0.0f;
      gEffect11DefaultSrcParams.y = 0.0f;
      gEffect11DefaultSrcParams.z = 0.0f;
      gEffect11DefaultSrcParams.w = lbl_803DFF40;
      gEffect11DefaultSrcParams.rot0 = 0;
      gEffect11DefaultSrcParams.rot1 = 0;
      gEffect11DefaultSrcParams.rot2 = 0;
      src = &gEffect11DefaultSrcParams;
    }
    p.posX = lbl_803DFF48 * (f32)(int)randomGetRange(-10, 10);
    p.posY = 0.0f;
    p.posZ = lbl_803DFF4C;
    p.velY = lbl_803DFF50 * (f32)(int)randomGetRange(1, 3);
    p.velX = lbl_803DFF5C * src->x;
    p.velZ = lbl_803DFF5C * -src->z;
    p.scale = lbl_803DFF60 * (f32)(int)randomGetRange(1, 3);
    p.count = 0x19;
    p.alpha = 0x55;
    p.flagsA = 0x80118;
    p.kind = 0x5f;
    break;
  case 0x131:
    p.posX = lbl_803DFF50 * (f32)(int)randomGetRange(-0xc, 0xc);
    p.posY = lbl_803DFF50 * (f32)(int)randomGetRange(-0xc, 0xc) + lbl_803DFF64;
    p.posZ = lbl_803DFF4C;
    p.velZ = lbl_803DFF68 * (f32)(int)randomGetRange(5, 10);
    p.scale = lbl_803DFF6C;
    p.count = 100;
    p.alpha = 0xff;
    p.flagsA = 0x100;
    p.kind = 0x33;
    break;
  case 0x132:
    p.posX = lbl_803DFF70 * (f32)(int)randomGetRange(-10, 10);
    p.posY = lbl_803DFF70 * (f32)(int)randomGetRange(-10, 10);
    p.posZ = lbl_803DFF70 * (f32)(int)randomGetRange(-10, 10);
    p.scale = lbl_803DFF74;
    p.count = randomGetRange(0x78, 0x96);
    p.unk61 = 0x1e;
    p.alpha = 0xff;
    p.flagsA = 0x11;
    p.kind = 0x5f;
    break;
  case 0x133:
    if (src == NULL)
    {
      gEffect11DefaultSrcParams.x = 0.0f;
      gEffect11DefaultSrcParams.y = 0.0f;
      gEffect11DefaultSrcParams.z = 0.0f;
      gEffect11DefaultSrcParams.w = lbl_803DFF40;
      gEffect11DefaultSrcParams.rot0 = 0;
      gEffect11DefaultSrcParams.rot1 = 0;
      gEffect11DefaultSrcParams.rot2 = 0;
      src = &gEffect11DefaultSrcParams;
    }
    p.posX = src->x;
    p.posY = src->y;
    p.posZ = src->z;
    p.scale = lbl_803DFF74;
    p.count = 5;
    p.alpha = 0x80;
    p.flagsA |= 0x80210LL;
    p.kind = 0x26d;
    break;
  case 0x134:
    if (src == NULL)
    {
      gEffect11DefaultSrcParams.x = 0.0f;
      gEffect11DefaultSrcParams.y = 0.0f;
      gEffect11DefaultSrcParams.z = 0.0f;
      gEffect11DefaultSrcParams.w = lbl_803DFF40;
      gEffect11DefaultSrcParams.rot0 = 0;
      gEffect11DefaultSrcParams.rot1 = 0;
      gEffect11DefaultSrcParams.rot2 = 0;
      src = &gEffect11DefaultSrcParams;
    }
    p.posX = lbl_803DFF78 * (f32)(int)randomGetRange(-200, 200) + src->x;
    p.posY = src->y;
    p.posZ = lbl_803DFF78 * (f32)(int)randomGetRange(-200, 200) + src->z;
    p.scale = lbl_803DFF7C * (f32)(int)randomGetRange(5, 0xc);
    p.count = 0xc;
    p.alpha = randomGetRange(0x96, 0xfa);
    p.flagsA |= 0x80210LL;
    p.kind = 0xe0;
    break;
  case 0x135:
    if (src == NULL)
    {
      gEffect11DefaultSrcParams.x = 0.0f;
      gEffect11DefaultSrcParams.y = 0.0f;
      gEffect11DefaultSrcParams.z = 0.0f;
      gEffect11DefaultSrcParams.w = lbl_803DFF40;
      gEffect11DefaultSrcParams.rot0 = 0;
      gEffect11DefaultSrcParams.rot1 = 0;
      gEffect11DefaultSrcParams.rot2 = 0;
      src = &gEffect11DefaultSrcParams;
    }
    p.posX = lbl_803DFF70 * (f32)(int)randomGetRange(-10, 10);
    p.posY = lbl_803DFF70 * (f32)(int)randomGetRange(-0x1e, 0);
    p.posZ = lbl_803DFF70 * (f32)(int)randomGetRange(-10, 10);
    p.velX = lbl_803DFF74 * (f32)(int)randomGetRange(-0xf, 0xf);
    p.velY = lbl_803DFF80 * (f32)(int)randomGetRange(0xf, 0x23);
    p.velZ = lbl_803DFF74 * (f32)(int)randomGetRange(-0xf, 0xf);
    p.scale = lbl_803DFF84 * (f32)(int)randomGetRange(0x64, 0x96);
    p.count = randomGetRange(0x32, 0x50);
    p.unk61 = randomGetRange(0xa, 0x1e);
    p.flagsA = 0x218;
    p.kind = src->rot2;
    break;
  case 0x136:
    if (src == NULL)
    {
      gEffect11DefaultSrcParams.x = 0.0f;
      gEffect11DefaultSrcParams.y = 0.0f;
      gEffect11DefaultSrcParams.z = 0.0f;
      gEffect11DefaultSrcParams.w = lbl_803DFF40;
      gEffect11DefaultSrcParams.rot0 = 0;
      gEffect11DefaultSrcParams.rot1 = 0;
      gEffect11DefaultSrcParams.rot2 = 0;
      src = &gEffect11DefaultSrcParams;
    }
    p.posX = (f32)(int)randomGetRange(-src->rot1, src->rot1) / lbl_803DFF88;
    p.posY = (f32)(int)randomGetRange(-src->rot1, src->rot1) / lbl_803DFF88;
    p.posZ = (f32)(int)randomGetRange(-src->rot1, src->rot1) / lbl_803DFF88;
    p.scale = lbl_803DFF8C;
    p.count = randomGetRange(0x14, 0x1e);
    p.flagsA = 0x100200;
    p.kind = src->rot2;
    break;
  case 0x137:
    if (src == NULL)
    {
      gEffect11DefaultSrcParams.x = 0.0f;
      gEffect11DefaultSrcParams.y = 0.0f;
      gEffect11DefaultSrcParams.z = 0.0f;
      gEffect11DefaultSrcParams.w = lbl_803DFF40;
      gEffect11DefaultSrcParams.rot0 = 0;
      gEffect11DefaultSrcParams.rot1 = 0;
      gEffect11DefaultSrcParams.rot2 = 0;
      src = &gEffect11DefaultSrcParams;
    }
    if (src == NULL)
    {
      return -1;
    }
    p.velX = lbl_803DFF94 * (f32)(int)randomGetRange(0, 100) + lbl_803DFF90;
    p.velY = lbl_803DFF98 * (f32)(int)randomGetRange(0, 100) + lbl_803DFF74;
    p.velZ = lbl_803DFF98 * (f32)(int)randomGetRange(0, 100) + lbl_803DFF74;
    vecRotateZXY(src, &p.velX);
    p.scale = lbl_803DFF9C * (f32)(int)randomGetRange(0x14, 0x1e);
    p.alpha = 0xff;
    p.count = 0xf0;
    p.unk61 = 0x10;
    p.unk04 = 0x138;
    p.flagsA = 0x480200;
    p.flagsB = 0x100000;
    p.kind = 0x167;
    break;
  case 0x138:
    p.scale = lbl_803DFF7C * (f32)(int)randomGetRange(0x14, 0x1e);
    p.alpha = 0x37;
    p.count = 4;
    p.unk61 = 0x10;
    p.flagsA = 0x80201;
    p.flagsB = 2;
    p.kind = 0x167;
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

void Effect11_func05_nop(void)
{
}

void Effect11_func03_nop(void)
{
}

void Effect11_release(void)
{
}

void Effect11_initialise(void)
{
}

