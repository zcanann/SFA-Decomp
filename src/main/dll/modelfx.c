#include "ghidra_import.h"
#include "main/dll/modelfx.h"

extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern byte SUB41();

extern undefined4 DAT_8039d010;
extern undefined4 DAT_8039d012;
extern undefined4 DAT_8039d014;
extern undefined4 DAT_8039d018;
extern undefined4 DAT_8039d01c;
extern undefined4 DAT_8039d020;
extern undefined4 DAT_8039d024;
extern undefined4 DAT_8039d028;
extern undefined4 DAT_8039d02a;
extern undefined4 DAT_8039d02c;
extern undefined4 DAT_8039d030;
extern undefined4 DAT_8039d034;
extern undefined4 DAT_8039d038;
extern undefined4 DAT_8039d03c;
extern undefined4 DAT_8039d040;
extern undefined4 DAT_8039d042;
extern undefined4 DAT_8039d044;
extern undefined4 DAT_8039d048;
extern undefined4 DAT_8039d04c;
extern undefined4 DAT_8039d050;
extern undefined4 DAT_8039d054;
extern undefined4 DAT_8039d058;
extern undefined4 DAT_8039d05a;
extern undefined4 DAT_8039d05c;
extern undefined4 DAT_8039d060;
extern undefined4 DAT_8039d064;
extern undefined4 DAT_8039d068;
extern undefined4 DAT_8039d06c;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4 DAT_803de030;
extern undefined4 DAT_803de034;
extern f64 DOUBLE_803e0ba8;
extern f64 DOUBLE_803e0c20;
extern f64 DOUBLE_803e0c78;
extern f64 DOUBLE_803e0d08;
extern f64 DOUBLE_803e0d18;
extern f64 DOUBLE_803e0d20;
extern f32 lbl_803DC074;
extern f32 lbl_803DC490;
extern f32 lbl_803DC494;
extern f32 lbl_803DC498;
extern f32 lbl_803DC49C;
extern f32 lbl_803DE038;
extern f32 lbl_803DE03C;
extern f32 lbl_803E0B38;
extern f32 lbl_803E0B3C;
extern f32 lbl_803E0B40;
extern f32 lbl_803E0B44;
extern f32 lbl_803E0B48;
extern f32 lbl_803E0B4C;
extern f32 lbl_803E0B50;
extern f32 lbl_803E0B54;
extern f32 lbl_803E0B58;
extern f32 lbl_803E0B5C;
extern f32 lbl_803E0B60;
extern f32 lbl_803E0B64;
extern f32 lbl_803E0B68;
extern f32 lbl_803E0B6C;
extern f32 lbl_803E0B70;
extern f32 lbl_803E0B74;
extern f32 lbl_803E0B78;
extern f32 lbl_803E0B7C;
extern f32 lbl_803E0B80;
extern f32 lbl_803E0B84;
extern f32 lbl_803E0B88;
extern f32 lbl_803E0B8C;
extern f32 lbl_803E0B90;
extern f32 lbl_803E0B94;
extern f32 lbl_803E0B98;
extern f32 lbl_803E0B9C;
extern f32 lbl_803E0BA0;
extern f32 lbl_803E0BA4;
extern f32 lbl_803E0BB8;
extern f32 lbl_803E0BBC;
extern f32 lbl_803E0BC0;
extern f32 lbl_803E0BC4;
extern f32 lbl_803E0BC8;
extern f32 lbl_803E0BCC;
extern f32 lbl_803E0BD0;
extern f32 lbl_803E0BD4;
extern f32 lbl_803E0BD8;
extern f32 lbl_803E0BDC;
extern f32 lbl_803E0BE0;
extern f32 lbl_803E0BE4;
extern f32 lbl_803E0BE8;
extern f32 lbl_803E0BEC;
extern f32 lbl_803E0BF0;
extern f32 lbl_803E0BF4;
extern f32 lbl_803E0BF8;
extern f32 lbl_803E0BFC;
extern f32 lbl_803E0C00;
extern f32 lbl_803E0C04;
extern f32 lbl_803E0C08;
extern f32 lbl_803E0C0C;
extern f32 lbl_803E0C10;
extern f32 lbl_803E0C14;
extern f32 lbl_803E0C18;
extern f32 lbl_803E0C1C;
extern f32 lbl_803E0C28;
extern f32 lbl_803E0C2C;
extern f32 lbl_803E0C30;
extern f32 lbl_803E0C34;
extern f32 lbl_803E0C38;
extern f32 lbl_803E0C3C;
extern f32 lbl_803E0C40;
extern f32 lbl_803E0C44;
extern f32 lbl_803E0C48;
extern f32 lbl_803E0C4C;
extern f32 lbl_803E0C50;
extern f32 lbl_803E0C54;
extern f32 lbl_803E0C58;
extern f32 lbl_803E0C5C;
extern f32 lbl_803E0C60;
extern f32 lbl_803E0C64;
extern f32 lbl_803E0C68;
extern f32 lbl_803E0C6C;
extern f32 lbl_803E0C70;
extern f32 lbl_803E0C80;
extern f32 lbl_803E0C84;
extern f32 lbl_803E0C88;
extern f32 lbl_803E0C8C;
extern f32 lbl_803E0C90;
extern f32 lbl_803E0C94;
extern f32 lbl_803E0C98;
extern f32 lbl_803E0C9C;
extern f32 lbl_803E0CA0;
extern f32 lbl_803E0CA4;
extern f32 lbl_803E0CA8;
extern f32 lbl_803E0CAC;
extern f32 lbl_803E0CB0;
extern f32 lbl_803E0CB4;
extern f32 lbl_803E0CB8;
extern f32 lbl_803E0CBC;
extern f32 lbl_803E0CC0;
extern f32 lbl_803E0CC4;
extern f32 lbl_803E0CC8;
extern f32 lbl_803E0CCC;
extern f32 lbl_803E0CD0;
extern f32 lbl_803E0CD4;
extern f32 lbl_803E0CD8;
extern f32 lbl_803E0CDC;
extern f32 lbl_803E0CE0;
extern f32 lbl_803E0CE4;
extern f32 lbl_803E0CE8;
extern f32 lbl_803E0CEC;
extern f32 lbl_803E0CF0;
extern f32 lbl_803E0CF4;
extern f32 lbl_803E0CF8;
extern f32 lbl_803E0CFC;
extern f32 lbl_803E0D00;
extern f32 lbl_803E0D10;
extern f32 lbl_803E0D14;

/*
 * --INFO--
 *
 * Function: Effect10_func04
 * EN v1.0 Address: 0x800C291C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800C2BA8
 * EN v1.1 Size: 7700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
Effect10_func04(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            float *param_6)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800c2924
 * EN v1.0 Address: 0x800C2924
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800C49BC
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c2924(void)
{
  double dVar1;
  
  lbl_803DC498 = lbl_803DC498 + lbl_803E0B38 * lbl_803DC074;
  if (lbl_803E0B40 < lbl_803DC498) {
    lbl_803DC498 = lbl_803E0B3C;
  }
  lbl_803DC49C = lbl_803DC49C + lbl_803E0B38 * lbl_803DC074;
  if (lbl_803E0B40 < lbl_803DC49C) {
    lbl_803DC49C = lbl_803E0B48;
  }
  DAT_803de030 = DAT_803de030 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de030) {
    DAT_803de030 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE03C = (float)dVar1;
  DAT_803de034 = DAT_803de034 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de034) {
    DAT_803de034 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE038 = (float)dVar1;
  return;
}

typedef struct EffectSrcParams {
  s16 rot0;
  s16 rot1;
  s16 rot2;
  f32 w;
  f32 x;
  f32 y;
  f32 z;
} EffectSrcParams;

typedef struct EffectSpawnParams {
  s16 *model;
  int unk04;
  uint count;
  s16 rot0;
  s16 rot1;
  s16 rot2;
  f32 srcW;
  f32 srcX;
  f32 srcY;
  f32 srcZ;
  f32 velX;
  f32 velY;
  f32 velZ;
  f32 posX;
  f32 posY;
  f32 posZ;
  f32 scale;
  s16 unk40;
  s16 kind;
  uint flagsA;
  uint flagsB;
  u32 colA;
  u32 colB;
  u32 colC;
  u16 colD;
  u16 colE;
  u16 colF;
  u8 idByte;
  u8 pad5F;
  u8 alpha;
  u8 unk61;
  u8 srcFlag;
} EffectSpawnParams;

extern int *gExpgfxInterface;
extern EffectSrcParams lbl_8039C3F8;
extern void mathFn_80021ac8(void *params, f32 *vec);

extern EffectSrcParams lbl_8039C3C8;
extern f32 lbl_803DFF38;
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

#pragma scheduling off
#pragma peephole off
int Effect11_func04(s16 *obj, int id, EffectSrcParams *src, uint flags, u8 srcByte)
{
  EffectSpawnParams p;
  uint hasOffset;

  if (obj == NULL) {
    return -1;
  }
  hasOffset = flags & 0x200000;
  if (hasOffset != 0) {
    if (src == NULL) {
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
  p.posX = lbl_803DFF38;
  p.posY = lbl_803DFF38;
  p.posZ = lbl_803DFF38;
  p.velX = lbl_803DFF38;
  p.velY = lbl_803DFF38;
  p.velZ = lbl_803DFF38;
  p.scale = lbl_803DFF38;
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
  switch (id) {
  case 0x12c:
    p.scale = lbl_803DFF3C;
    p.count = 0xa;
    p.alpha = 0xff;
    p.flagsA = 0x40200;
    p.kind = 0xdb;
    break;
  case 0x12d:
    if (src == NULL) {
      lbl_8039C3C8.x = lbl_803DFF38;
      lbl_8039C3C8.y = lbl_803DFF38;
      lbl_8039C3C8.z = lbl_803DFF38;
      lbl_8039C3C8.w = lbl_803DFF40;
      lbl_8039C3C8.rot0 = 0;
      lbl_8039C3C8.rot1 = 0;
      lbl_8039C3C8.rot2 = 0;
      src = &lbl_8039C3C8;
    }
    p.scale = lbl_803DFF44;
    p.count = randomGetRange(0, 0x1e) + 0x46;
    p.alpha = src->w > lbl_803DFF38 ? 0x50 : 0x41;
    p.flagsA = 0x80110;
    p.kind = src->w > lbl_803DFF38 ? 0x7b : 0xdb;
    break;
  case 0x12e:
    if (src == NULL) {
      lbl_8039C3C8.x = lbl_803DFF38;
      lbl_8039C3C8.y = lbl_803DFF38;
      lbl_8039C3C8.z = lbl_803DFF38;
      lbl_8039C3C8.w = lbl_803DFF40;
      lbl_8039C3C8.rot0 = 0;
      lbl_8039C3C8.rot1 = 0;
      lbl_8039C3C8.rot2 = 0;
      src = &lbl_8039C3C8;
    }
    p.posX = lbl_803DFF48 * (f32)(int)randomGetRange(-10, 10);
    p.posY = lbl_803DFF38;
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
    if (src == NULL) {
      lbl_8039C3C8.x = lbl_803DFF38;
      lbl_8039C3C8.y = lbl_803DFF38;
      lbl_8039C3C8.z = lbl_803DFF38;
      lbl_8039C3C8.w = lbl_803DFF40;
      lbl_8039C3C8.rot0 = 0;
      lbl_8039C3C8.rot1 = 0;
      lbl_8039C3C8.rot2 = 0;
      src = &lbl_8039C3C8;
    }
    p.posX = lbl_803DFF48 * (f32)(int)randomGetRange(-10, 10);
    p.posY = lbl_803DFF38;
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
    if (src == NULL) {
      lbl_8039C3C8.x = lbl_803DFF38;
      lbl_8039C3C8.y = lbl_803DFF38;
      lbl_8039C3C8.z = lbl_803DFF38;
      lbl_8039C3C8.w = lbl_803DFF40;
      lbl_8039C3C8.rot0 = 0;
      lbl_8039C3C8.rot1 = 0;
      lbl_8039C3C8.rot2 = 0;
      src = &lbl_8039C3C8;
    }
    p.posX = lbl_803DFF48 * (f32)(int)randomGetRange(-10, 10);
    p.posY = lbl_803DFF38;
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
    if (src == NULL) {
      lbl_8039C3C8.x = lbl_803DFF38;
      lbl_8039C3C8.y = lbl_803DFF38;
      lbl_8039C3C8.z = lbl_803DFF38;
      lbl_8039C3C8.w = lbl_803DFF40;
      lbl_8039C3C8.rot0 = 0;
      lbl_8039C3C8.rot1 = 0;
      lbl_8039C3C8.rot2 = 0;
      src = &lbl_8039C3C8;
    }
    p.posX = src->x;
    p.posY = src->y;
    p.posZ = src->z;
    p.scale = lbl_803DFF74;
    p.count = 5;
    p.alpha = 0x80;
    p.flagsA = p.flagsA | 0x80210;
    p.kind = 0x26d;
    break;
  case 0x134:
    if (src == NULL) {
      lbl_8039C3C8.x = lbl_803DFF38;
      lbl_8039C3C8.y = lbl_803DFF38;
      lbl_8039C3C8.z = lbl_803DFF38;
      lbl_8039C3C8.w = lbl_803DFF40;
      lbl_8039C3C8.rot0 = 0;
      lbl_8039C3C8.rot1 = 0;
      lbl_8039C3C8.rot2 = 0;
      src = &lbl_8039C3C8;
    }
    p.posX = lbl_803DFF78 * (f32)(int)randomGetRange(-200, 200) + src->x;
    p.posY = src->y;
    p.posZ = lbl_803DFF78 * (f32)(int)randomGetRange(-200, 200) + src->z;
    p.scale = lbl_803DFF7C * (f32)(int)randomGetRange(5, 0xc);
    p.count = 0xc;
    p.alpha = randomGetRange(0x96, 0xfa);
    p.flagsA = p.flagsA | 0x80210;
    p.kind = 0xe0;
    break;
  case 0x135:
    if (src == NULL) {
      lbl_8039C3C8.x = lbl_803DFF38;
      lbl_8039C3C8.y = lbl_803DFF38;
      lbl_8039C3C8.z = lbl_803DFF38;
      lbl_8039C3C8.w = lbl_803DFF40;
      lbl_8039C3C8.rot0 = 0;
      lbl_8039C3C8.rot1 = 0;
      lbl_8039C3C8.rot2 = 0;
      src = &lbl_8039C3C8;
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
    if (src == NULL) {
      lbl_8039C3C8.x = lbl_803DFF38;
      lbl_8039C3C8.y = lbl_803DFF38;
      lbl_8039C3C8.z = lbl_803DFF38;
      lbl_8039C3C8.w = lbl_803DFF40;
      lbl_8039C3C8.rot0 = 0;
      lbl_8039C3C8.rot1 = 0;
      lbl_8039C3C8.rot2 = 0;
      src = &lbl_8039C3C8;
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
    if (src == NULL) {
      lbl_8039C3C8.x = lbl_803DFF38;
      lbl_8039C3C8.y = lbl_803DFF38;
      lbl_8039C3C8.z = lbl_803DFF38;
      lbl_8039C3C8.w = lbl_803DFF40;
      lbl_8039C3C8.rot0 = 0;
      lbl_8039C3C8.rot1 = 0;
      lbl_8039C3C8.rot2 = 0;
      src = &lbl_8039C3C8;
    }
    if (src == NULL) {
      return -1;
    }
    p.velX = lbl_803DFF94 * (f32)(int)randomGetRange(0, 100) + lbl_803DFF90;
    p.velY = lbl_803DFF98 * (f32)(int)randomGetRange(0, 100) + lbl_803DFF74;
    p.velZ = lbl_803DFF98 * (f32)(int)randomGetRange(0, 100) + lbl_803DFF74;
    mathFn_80021ac8(src, &p.velX);
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
  if (((p.flagsA & 1) != 0) && ((p.flagsA & 2) != 0)) {
    p.flagsA = p.flagsA ^ 2;
  }
  if ((p.flagsA & 1) != 0) {
    if (hasOffset != 0) {
      p.posX = p.posX + p.srcX;
      p.posY = p.posY + p.srcY;
      p.posZ = p.posZ + p.srcZ;
    } else if (p.model != NULL) {
      p.posX = p.posX + *(f32 *)((char *)p.model + 0x18);
      p.posY = p.posY + *(f32 *)((char *)p.model + 0x1c);
      p.posZ = p.posZ + *(f32 *)((char *)p.model + 0x20);
    }
  }
  return (*(int (**)(EffectSpawnParams *, int, int, int))(*gExpgfxInterface + 2))(&p, -1, id, 0);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800c2a18
 * EN v1.0 Address: 0x800C2A18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800C4AF0
 * EN v1.1 Size: 3708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c2a18(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5)
{
}

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

#pragma scheduling off
#pragma peephole off
int Effect12_func04(s16 *obj, int id, EffectSrcParams *src, uint flags, u8 srcByte, f32 *p6)
{
  EffectSrcParams local;
  EffectSpawnParams p;
  uint hasOffset;

  if (obj == NULL) {
    return -1;
  }
  hasOffset = flags & 0x200000;
  if (hasOffset != 0) {
    if (src == NULL) {
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
  switch (id) {
  case 0x47e:
    p.scale = lbl_803DFFAC;
    p.count = randomGetRange(0x32, 0x3c);
    p.alpha = 0x4b;
    p.flagsA = 0x180110;
    p.flagsB = 0x4000800;
    p.kind = 0x159;
    break;
  case 0x483:
    if (src == NULL) {
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
    if (src == NULL) {
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
    if (src == NULL) {
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
    if (p6 == NULL) {
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
    p.kind = (s16)randomGetRange(0, 2) + 0x208;
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
    if (src == NULL) {
      lbl_8039C3E0.x = lbl_803DFFA8;
      lbl_8039C3E0.y = lbl_803DFFA8;
      lbl_8039C3E0.z = lbl_803DFFA8;
      lbl_8039C3E0.w = lbl_803DFFB0;
      lbl_8039C3E0.rot0 = 0;
      lbl_8039C3E0.rot1 = 0;
      lbl_8039C3E0.rot2 = 0;
    }
    if (p6 == NULL) {
      return -1;
    }
    if (*(int *)p6 == 0) {
      p.scale = lbl_803DFFEC * (f32)(int)randomGetRange(8, 0x11);
      p.count = randomGetRange(5, 10);
      p.alpha = 0x64;
      p.flagsA = 0x80110;
      p.flagsB = 0x4000800;
    } else if (*(int *)p6 == 1) {
      p.velX = lbl_803DFFB4 * (f32)(int)randomGetRange(-0x32, 0x32);
      p.velY = lbl_803DFFB4 * (f32)(int)randomGetRange(-0x32, 0x32);
      p.velZ = lbl_803DFFB4 * (f32)(int)randomGetRange(0, 0x32);
      p.scale = lbl_803DFFF0 * (f32)(int)randomGetRange(10, 0x14);
      p.count = 0x2d;
      p.alpha = 0;
      p.flagsA = 0x880014;
      p.flagsB = 0x4010808;
    } else {
      p.velX = lbl_803DFFB4 * (f32)(int)randomGetRange(-0x28, 0x28);
      p.velY = lbl_803DFFD8 * (f32)(int)randomGetRange(-10, 0x1e);
      p.velZ = lbl_803DFFD8 * (f32)(int)randomGetRange(0, 0x28);
      local.x = lbl_803DFFA8;
      local.y = lbl_803DFFA8;
      local.z = lbl_803DFFA8;
      local.w = lbl_803DFFB0;
      local.rot2 = 0;
      local.rot1 = 0;
      local.rot0 = obj[0];
      mathFn_80021ac8(&local, &p.velX);
      p.scale = lbl_803DFFB4;
      p.count = 100;
      p.alpha = 0xff;
      p.flagsB = 0x300800;
      p.flagsA = 0x300210;
    }
    p.kind = randomGetRange(0x156, 0x157);
    break;
  default:
    return -1;
  }
  p.flagsA = p.flagsA | flags;
  if (((p.flagsA & 1) != 0) && ((p.flagsA & 2) != 0)) {
    p.flagsA = p.flagsA ^ 2;
  }
  if ((p.flagsA & 1) != 0) {
    if (hasOffset != 0) {
      p.posX = p.posX + p.srcX;
      p.posY = p.posY + p.srcY;
      p.posZ = p.posZ + p.srcZ;
    } else if (p.model != NULL) {
      p.posX = p.posX + *(f32 *)((char *)p.model + 0x18);
      p.posY = p.posY + *(f32 *)((char *)p.model + 0x1c);
      p.posZ = p.posZ + *(f32 *)((char *)p.model + 0x20);
    }
  }
  return (*(int (**)(EffectSpawnParams *, int, int, int))(*gExpgfxInterface + 2))(&p, -1, id, 0);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800c2a1c
 * EN v1.0 Address: 0x800C2A1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800C596C
 * EN v1.1 Size: 3796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c2a1c(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800c2a20
 * EN v1.0 Address: 0x800C2A20
 * EN v1.0 Size: 1888b
 * EN v1.1 Address: 0x800C6840
 * EN v1.1 Size: 6724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

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

#pragma scheduling off
#pragma peephole off
int Effect14_func04(s16 *obj, int id, EffectSrcParams *src, uint flags, u8 srcByte, u16 *p6)
{
  EffectSrcParams local;
  EffectSpawnParams p;
  uint hasOffset;

  if (obj == NULL) {
    return -1;
  }
  hasOffset = flags & 0x200000;
  if (hasOffset != 0) {
    if (src == NULL) {
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
  switch (id) {
  case 0x4b0:
    if (p6 == NULL) {
      return 0;
    }
    p.alpha = *p6 >> 1;
    p.scale = lbl_803E0004 * (f32)p.alpha;
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
    if (p6 != NULL) {
      p.velX = *(f32 *)p6;
      p.velY = *((f32 *)p6 + 1);
      p.velZ = *((f32 *)p6 + 2);
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
    if (p6 != NULL) {
      p.velX = *(f32 *)p6;
      p.velY = *((f32 *)p6 + 1);
      p.velZ = *((f32 *)p6 + 2);
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
    if (p6 != NULL) {
      p.velX = *(f32 *)p6;
      p.velY = *((f32 *)p6 + 1);
      p.velZ = *((f32 *)p6 + 2);
    }
    p.count = 0x25;
    p.scale = lbl_803E002C;
    p.flagsA = 0x80200;
    p.flagsB = 0x4000800;
    if (randomGetRange(0, 2) == 0) {
      p.kind = 0xc0e;
    } else {
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
    if (p6 == NULL) {
      return 0;
    }
    p.posX = lbl_803E0034 * ((f32)p.alpha * (f32)(int)randomGetRange(-10, 10));
    p.posY = lbl_803E0034 * ((f32)p.alpha * (f32)(int)randomGetRange(0, 10));
    p.posZ = lbl_803E0034 * ((f32)p.alpha * (f32)(int)randomGetRange(-10, 10));
    p.alpha = *(u32 *)p6;
    p.scale = lbl_803E0038 * (f32)p.alpha + lbl_803E0038;
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
    p.kind = (s16)randomGetRange(0, 2) + 0x208;
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
    if (src == NULL) {
      lbl_8039C3F8.x = lbl_803E0000;
      lbl_8039C3F8.y = lbl_803E0000;
      lbl_8039C3F8.z = lbl_803E0000;
      lbl_8039C3F8.w = lbl_803E006C;
      lbl_8039C3F8.rot0 = 0;
      lbl_8039C3F8.rot1 = 0;
      lbl_8039C3F8.rot2 = 0;
    }
    p.velX = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
    p.velY = lbl_803E000C * (f32)(int)randomGetRange(-0x14, 0x14);
    p.velZ = lbl_803E0070 * (f32)(int)randomGetRange(10, 0x1e);
    local.x = lbl_803E0000;
    local.y = lbl_803E0000;
    local.z = lbl_803E0000;
    local.w = lbl_803E006C;
    local.rot2 = obj[2];
    local.rot1 = obj[1];
    local.rot0 = obj[0];
    mathFn_80021ac8(&local, &p.velX);
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
    p.rot2 = obj[2];
    p.rot1 = obj[1];
    p.rot0 = obj[0];
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
    p.rot2 = obj[2];
    p.rot1 = obj[1];
    p.rot0 = obj[0];
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
  if (((p.flagsA & 1) != 0) && ((p.flagsA & 2) != 0)) {
    p.flagsA = p.flagsA ^ 2;
  }
  if ((p.flagsA & 1) != 0) {
    if (hasOffset != 0) {
      p.posX = p.posX + p.srcX;
      p.posY = p.posY + p.srcY;
      p.posZ = p.posZ + p.srcZ;
    } else if (p.model != NULL) {
      p.posX = p.posX + *(f32 *)((char *)p.model + 0x18);
      p.posY = p.posY + *(f32 *)((char *)p.model + 0x1c);
      p.posZ = p.posZ + *(f32 *)((char *)p.model + 0x20);
    }
  }
  return (*(int (**)(EffectSpawnParams *, int, int, int))(*gExpgfxInterface + 2))(&p, -1, id, 0);
}
#pragma peephole reset
#pragma scheduling reset

/* sda21 externs for Effect10_func05 tick. */
extern f32 lbl_803DB838;
extern f32 lbl_803DB83C;
extern f32 lbl_803DFEB8;
extern f32 lbl_803DFEBC;
extern f32 lbl_803DFEC0;
extern f32 lbl_803DFEC8;
extern s32 lbl_803DD3B0;
extern s32 lbl_803DD3B4;
extern f32 lbl_803DD3B8;
extern f32 lbl_803DD3BC;
extern const double lbl_803DFF28;
extern f32 lbl_803DFF30;
extern f32 lbl_803DFF34;
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 fn_80293E80(f32 x);

/* Advance two periodic counters; compute sin of phase. */
#pragma push
#pragma scheduling off
void Effect10_func05(void)
{
    f32 sum;
    sum = lbl_803DB838 + lbl_803DFEB8 * timeDelta;
    lbl_803DB838 = sum;
    if (sum > lbl_803DFEC0) {
        lbl_803DB838 = lbl_803DFEBC;
    }
    sum = lbl_803DB83C + lbl_803DFEB8 * timeDelta;
    lbl_803DB83C = sum;
    if (sum > lbl_803DFEC0) {
        lbl_803DB83C = lbl_803DFEC8;
    }
    lbl_803DD3B0 = lbl_803DD3B0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3B0 > 0x7fff) {
        lbl_803DD3B0 = 0;
    }
    lbl_803DD3BC = fn_80293E80(lbl_803DFF30 * (f32)(s16)lbl_803DD3B0 / lbl_803DFF34);
    lbl_803DD3B4 = lbl_803DD3B4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3B4 > 0x7fff) {
        lbl_803DD3B4 = 0;
    }
    lbl_803DD3B8 = fn_80293E80(lbl_803DFF30 * (f32)(s16)lbl_803DD3B4 / lbl_803DFF34);
}
#pragma pop

/* Trivial 4b 0-arg blr leaves. */
void Effect10_func03_nop(void) {}
void Effect10_release(void) {}
void Effect10_initialise(void) {}
void Effect11_func05_nop(void) {}
void Effect11_func03_nop(void) {}
void Effect11_release(void) {}
void Effect11_initialise(void) {}
void Effect12_func05_nop(void) {}
void Effect12_func03_nop(void) {}
void Effect12_release(void) {}
void Effect12_initialise(void) {}
void Effect14_func05_nop(void) {}
void Effect14_func03_nop(void) {}
void Effect14_release(void) {}
void Effect14_initialise(void) {}
