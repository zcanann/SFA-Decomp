#include "ghidra_import.h"
#include "main/dll/screens.h"


#pragma peephole off
#pragma scheduling off
extern u32 randomGetRange(int min, int max);
extern int FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();

extern undefined4 DAT_802c2900;
extern undefined4 DAT_802c2904;
extern undefined4 DAT_802c2908;
extern undefined4 DAT_802c290c;
extern undefined4 DAT_803187e8;
extern undefined4 DAT_80318828;
extern undefined4 DAT_803188fc;
extern undefined DAT_803189d8;
extern undefined DAT_80318a04;
extern undefined4 DAT_80318a20;
extern undefined4 DAT_80318a22;
extern undefined4 DAT_80318a24;
extern undefined4 DAT_80318a26;
extern undefined4 DAT_80318a28;
extern undefined4 DAT_80318a2a;
extern undefined4 DAT_80318a2c;
extern undefined4 DAT_80318a50;
extern undefined4 DAT_80318b24;
extern undefined DAT_80318c00;
extern undefined DAT_80318c2c;
extern undefined4 DAT_80318c48;
extern undefined4 DAT_803dc5b8;
extern undefined4 DAT_803dc5c0;
extern undefined DAT_803dc5c4;
extern undefined4* DAT_803dd6fc;
extern f64 DOUBLE_803e2018;
extern f64 DOUBLE_803e2070;
extern f32 lbl_803E1FF0;
extern f32 lbl_803E1FF4;
extern f32 lbl_803E1FF8;
extern f32 lbl_803E1FFC;
extern f32 lbl_803E2000;
extern f32 lbl_803E2004;
extern f32 lbl_803E2008;
extern f32 lbl_803E200C;
extern f32 lbl_803E2010;
extern f32 lbl_803E2014;
extern f32 lbl_803E2020;
extern f32 lbl_803E2024;
extern f32 lbl_803E2028;
extern f32 lbl_803E202C;
extern f32 lbl_803E2030;
extern f32 lbl_803E2034;
extern f32 lbl_803E2038;
extern f32 lbl_803E203C;
extern f32 lbl_803E2040;
extern f32 lbl_803E2044;
extern f32 lbl_803E2048;
extern f32 lbl_803E204C;
extern f32 lbl_803E2050;
extern f32 lbl_803E2054;
extern f32 lbl_803E2058;
extern f32 lbl_803E205C;
extern f32 lbl_803E2060;
extern f32 lbl_803E2064;
extern f32 lbl_803E2068;

/*
 * --INFO--
 *
 * Function: dll_9A_func03
 * EN v1.0 Address: 0x800FC5B8
 * EN v1.0 Size: 2428b
 * EN v1.1 Address: 0x800FC854
 * EN v1.1 Size: 2436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_9A_func03(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  float fVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined2 uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  undefined4 *puVar13;
  double in_f30;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar16;
  undefined2 local_428;
  short sStack_426;
  short local_424;
  short sStack_422;
  short local_420;
  undefined2 uStack_41e;
  undefined4 *local_418;
  int local_414;
  float local_3f8;
  float local_3f4;
  float local_3f0;
  float local_3ec;
  float local_3e8;
  float local_3e4;
  float local_3e0;
  undefined4 local_3dc;
  undefined4 local_3d8;
  undefined2 local_3d4;
  undefined2 local_3d2;
  short local_3d0;
  short local_3ce;
  short local_3cc;
  short local_3ca;
  undefined2 local_3c8;
  undefined2 local_3c6;
  uint local_3c4;
  undefined local_3c0;
  undefined local_3bf;
  undefined local_3be;
  undefined local_3bd;
  char local_3bb;
  undefined4 local_3b8;
  float local_3b4;
  float local_3b0;
  float local_3ac;
  undefined *local_3a8;
  undefined2 local_3a4;
  undefined local_3a2 [2];
  undefined4 local_3a0 [5];
  undefined local_38a [722];
  undefined4 local_b8;
  uint uStack_b4;
  undefined4 local_b0;
  uint uStack_ac;
  undefined4 local_a8;
  uint uStack_a4;
  undefined4 local_a0;
  uint uStack_9c;
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar16 = FUN_8028683c();
  uVar5 = DAT_802c290c;
  uVar4 = DAT_802c2908;
  uVar3 = DAT_802c2904;
  uVar2 = DAT_802c2900;
  iVar7 = (int)((ulonglong)uVar16 >> 0x20);
  iVar6 = (int)uVar16;
  uVar8 = randomGetRange(0,0x14);
  sStack_426 = (short)uVar2;
  local_428 = (undefined2)((uint)uVar2 >> 0x10);
  uVar9 = randomGetRange(0xffffffec,0x14);
  local_424 = (short)((uint)uVar3 >> 0x10);
  sStack_422 = (short)uVar3;
  uVar10 = randomGetRange(0xffffffec,0x14);
  uVar11 = randomGetRange(0xffffffec,0x14);
  local_420 = (short)((uint)uVar4 >> 0x10);
  uStack_41e = (undefined2)uVar4;
  if (iVar6 == 0) {
    local_3a2[0] = 0;
    local_3a4 = 3;
    local_3a8 = &DAT_803dc5c4;
    local_3b8 = 8;
    uVar12 = randomGetRange(0,0x69);
    uStack_b4 = uVar12 + 0x8c ^ 0x80000000;
    local_b8 = 0x43300000;
    local_3b4 = (f32)(s32)uStack_b4;
    uVar12 = randomGetRange(0,0x69);
    uStack_ac = uVar12 + 0x8c ^ 0x80000000;
    local_b0 = 0x43300000;
    local_3b0 = (f32)(s32)uStack_ac;
    uVar12 = randomGetRange(0,0x1e);
    uStack_a4 = uVar12 + 0xe1 ^ 0x80000000;
    local_a8 = 0x43300000;
    local_3ac = (f32)(s32)uStack_a4;
    puVar13 = (undefined4 *)(local_3a2 + 2);
  }
  else {
    puVar13 = &local_3b8;
    if (iVar6 == 1) {
      local_3a2[0] = 0;
      local_3a4 = 3;
      local_3a8 = &DAT_803dc5c4;
      local_3b8 = 8;
      uVar12 = randomGetRange(0,0x1e);
      uStack_a4 = uVar12 + 0xe1 ^ 0x80000000;
      local_a8 = 0x43300000;
      local_3b4 = (f32)(s32)uStack_a4;
      uVar12 = randomGetRange(0,0x69);
      uStack_ac = uVar12 + 0x8c ^ 0x80000000;
      local_b0 = 0x43300000;
      local_3b0 = (f32)(s32)uStack_ac;
      uVar12 = randomGetRange(0,0x41);
      uStack_b4 = uVar12 + 0x78 ^ 0x80000000;
      local_b8 = 0x43300000;
      local_3ac = (f32)(s32)uStack_b4;
      puVar13 = (undefined4 *)(local_3a2 + 2);
    }
  }
  uStack_a4 = randomGetRange(0xffffc950,14000);
  dVar15 = (double)(f32)(s32)uStack_a4;
  uStack_ac = randomGetRange(0xffffd120,12000);
  fVar1 = (f32)(s32)uStack_ac;
  dVar14 = (double)fVar1;
  *(undefined *)((int)puVar13 + 0x16) = 0;
  *(undefined2 *)(puVar13 + 5) = 0;
  puVar13[4] = 0;
  *puVar13 = 0x80;
  puVar13[1] = lbl_803E1FF0;
  puVar13[2] = fVar1;
  puVar13[3] = (float)dVar15;
  *(undefined *)((int)puVar13 + 0x2e) = 0;
  *(undefined2 *)(puVar13 + 0xb) = 3;
  puVar13[10] = (undefined4)&DAT_803dc5c4;
  puVar13[6] = 4;
  puVar13[7] = lbl_803E1FF0;
  puVar13[8] = lbl_803E1FF0;
  puVar13[9] = lbl_803E1FF0;
  *(undefined *)((int)puVar13 + 0x46) = 0;
  *(undefined2 *)(puVar13 + 0x11) = 3;
  puVar13[0x10] = (undefined4)&DAT_803dc5c4;
  puVar13[0xc] = 2;
  puVar13[0xd] = lbl_803E1FF4;
  uStack_b4 = randomGetRange(0,0x32);
  puVar13[0xe] = lbl_803E1FFC * (f32)(s32)uStack_b4
                 + lbl_803E1FF8;
  uStack_9c = randomGetRange(4,6);
  puVar13[0xf] = lbl_803E1FFC * (f32)(s32)uStack_9c
                 + lbl_803E2000;
  *(undefined *)((int)puVar13 + 0x5e) = 1;
  *(undefined2 *)(puVar13 + 0x17) = 1;
  puVar13[0x16] = (undefined4)&DAT_803dc5c0;
  puVar13[0x12] = 4;
  puVar13[0x13] = lbl_803E2004;
  puVar13[0x14] = lbl_803E1FF0;
  puVar13[0x15] = lbl_803E1FF0;
  *(undefined *)((int)puVar13 + 0x76) = 1;
  *(undefined2 *)(puVar13 + 0x1d) = 0;
  puVar13[0x1c] = (undefined4)&DAT_803dc5c0;
  puVar13[0x18] = 0x4000;
  puVar13[0x19] = lbl_803E2008;
  puVar13[0x1a] = lbl_803E1FF0;
  puVar13[0x1b] = lbl_803E1FF0;
  *(undefined *)((int)puVar13 + 0x8e) = 1;
  *(undefined2 *)(puVar13 + 0x23) = 3;
  puVar13[0x22] = (undefined4)&DAT_803dc5c4;
  puVar13[0x1e] = 2;
  puVar13[0x1f] = lbl_803E200C;
  puVar13[0x20] = lbl_803E2010;
  puVar13[0x21] = lbl_803E2010;
  *(undefined *)((int)puVar13 + 0xa6) = 1;
  *(undefined2 *)(puVar13 + 0x29) = 0;
  puVar13[0x28] = 0;
  puVar13[0x24] = 0x80;
  uStack_94 = randomGetRange(0xffff8300,32000);
  puVar13[0x25] = (f32)(s32)uStack_94;
  uStack_8c = randomGetRange(0xffffffff,1);
  puVar13[0x26] =
       (float)(dVar14 * (double)(f32)(s32)uStack_8c);
  uStack_84 = randomGetRange(0xffffffff,1);
  puVar13[0x27] =
       (float)(dVar15 * (double)(f32)(s32)uStack_84);
  *(undefined *)((int)puVar13 + 0xbe) = 2;
  *(undefined2 *)(puVar13 + 0x2f) = 0;
  puVar13[0x2e] = 0;
  puVar13[0x2a] = 0x80;
  uStack_7c = randomGetRange(0xffff8300,32000);
  puVar13[0x2b] = (f32)(s32)uStack_7c;
  uStack_74 = randomGetRange(0xffffffff,1);
  puVar13[0x2c] =
       (float)(dVar14 * (double)(f32)(s32)uStack_74);
  uStack_6c = randomGetRange(0xffffffff,1);
  puVar13[0x2d] =
       (float)(dVar15 * (double)(f32)(s32)uStack_6c);
  *(undefined *)((int)puVar13 + 0xd6) = 2;
  *(undefined2 *)(puVar13 + 0x35) = 0;
  puVar13[0x34] = (undefined4)&DAT_803dc5c0;
  puVar13[0x30] = 0x4000;
  puVar13[0x31] = lbl_803E2008;
  puVar13[0x32] = lbl_803E1FF0;
  puVar13[0x33] = lbl_803E1FF0;
  *(undefined *)((int)puVar13 + 0xee) = 3;
  *(undefined2 *)(puVar13 + 0x3b) = 0;
  puVar13[0x3a] = 0;
  puVar13[0x36] = 0x80;
  uStack_64 = randomGetRange(0xffff8300,32000);
  puVar13[0x37] = (f32)(s32)uStack_64;
  uStack_5c = randomGetRange(0xffffffff,1);
  puVar13[0x38] =
       (float)(dVar14 * (double)(f32)(s32)uStack_5c);
  uStack_54 = randomGetRange(0xffffffff,1);
  puVar13[0x39] =
       (float)(dVar15 * (double)(f32)(s32)uStack_54);
  *(undefined *)((int)puVar13 + 0x106) = 3;
  *(undefined2 *)(puVar13 + 0x41) = 0;
  puVar13[0x40] = (undefined4)&DAT_803dc5c0;
  puVar13[0x3c] = 0x4000;
  puVar13[0x3d] = lbl_803E2008;
  puVar13[0x3e] = lbl_803E1FF0;
  puVar13[0x3f] = lbl_803E1FF0;
  *(undefined *)((int)puVar13 + 0x11e) = 4;
  *(undefined2 *)(puVar13 + 0x47) = 0;
  puVar13[0x46] = 0;
  puVar13[0x42] = 0x80;
  uStack_4c = randomGetRange(0xffff8300,32000);
  puVar13[0x43] = (f32)(s32)uStack_4c;
  uStack_44 = randomGetRange(0xffffffff,1);
  puVar13[0x44] =
       (float)(dVar14 * (double)(f32)(s32)uStack_44);
  uStack_3c = randomGetRange(0xffffffff,1);
  puVar13[0x45] =
       (float)(dVar15 * (double)(f32)(s32)uStack_3c);
  *(undefined *)((int)puVar13 + 0x136) = 4;
  *(undefined2 *)(puVar13 + 0x4d) = 0;
  puVar13[0x4c] = (undefined4)&DAT_803dc5c0;
  puVar13[0x48] = 0x4000;
  puVar13[0x49] = lbl_803E2008;
  puVar13[0x4a] = lbl_803E1FF0;
  puVar13[0x4b] = lbl_803E1FF0;
  *(undefined *)((int)puVar13 + 0x14e) = 4;
  *(undefined2 *)(puVar13 + 0x53) = 1;
  puVar13[0x52] = (undefined4)&DAT_803dc5c0;
  puVar13[0x4e] = 4;
  puVar13[0x4f] = lbl_803E1FF0;
  puVar13[0x50] = lbl_803E1FF0;
  puVar13[0x51] = lbl_803E1FF0;
  local_3c0 = 0;
  local_3d4 = (undefined2)uVar16;
  local_3ec = lbl_803E1FF0;
  if (iVar6 == 0) {
    local_3e8 = lbl_803E1FF0;
  }
  else if (iVar6 == 1) {
    local_3e8 = lbl_803E2014;
  }
  local_3e4 = lbl_803E1FF0;
  local_3f8 = lbl_803E1FF0;
  local_3f4 = lbl_803E1FF0;
  local_3f0 = lbl_803E1FF0;
  local_3e0 = lbl_803E2010;
  local_3d8 = 1;
  local_3dc = 0;
  local_3bf = 3;
  local_3be = 0;
  local_3bd = 0;
  iVar6 = (int)puVar13 + (0x150 - (int)&local_3b8);
  iVar6 = iVar6 / 0x18 + (iVar6 >> 0x1f);
  local_3bb = (char)iVar6 - (char)(iVar6 >> 0x1f);
  local_3d2 = local_428;
  local_3c8 = uStack_41e;
  local_3c6 = uVar5;
  local_418 = &local_3b8;
  local_3c4 = param_4 | 0x4000400;
  if ((param_4 & 1) != 0) {
    if ((iVar7 == 0) || (param_3 == 0)) {
      if (iVar7 == 0) {
        if (param_3 != 0) {
          local_3ec = lbl_803E1FF0 + *(float *)(param_3 + 0xc);
          local_3e8 = local_3e8 + *(float *)(param_3 + 0x10);
          local_3e4 = lbl_803E1FF0 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_3ec = lbl_803E1FF0 + *(float *)(iVar7 + 0x18);
        local_3e8 = local_3e8 + *(float *)(iVar7 + 0x1c);
        local_3e4 = lbl_803E1FF0 + *(float *)(iVar7 + 0x20);
      }
    }
    else {
      local_3ec = lbl_803E1FF0 + *(float *)(iVar7 + 0x18) + *(float *)(param_3 + 0xc);
      local_3e8 = local_3e8 + *(float *)(iVar7 + 0x1c) + *(float *)(param_3 + 0x10);
      local_3e4 = lbl_803E1FF0 + *(float *)(iVar7 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_414 = iVar7;
  local_3d0 = sStack_426 + (short)uVar8;
  local_3ce = local_424 + (short)uVar9;
  local_3cc = sStack_422 + (short)uVar10;
  local_3ca = local_420 + (short)uVar11;
  (**(code **)(*DAT_803dd6fc + 8))(&local_418,0,3,&DAT_803187e8,1,&DAT_803dc5b8,0x31,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: dll_9B_func03
 * EN v1.0 Address: 0x800FCF3C
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x800FD1D8
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct {
    u32 flags;
    f32 x;
    f32 y;
    f32 z;
    u8 *tex;
    u16 id;
    u8 state;
} ScreenFxPart; /* 0x18 */

typedef struct {
    ScreenFxPart *parts; /* 0x00 */
    int target;          /* 0x04 */
    u8 pad0[0x18];       /* 0x08 */
    f32 ax, ay, az;      /* 0x20 */
    f32 bx, by, bz;      /* 0x2c */
    f32 r;               /* 0x38 */
    u32 c7;              /* 0x3c */
    u32 c2;              /* 0x40 */
    s16 b;               /* 0x44 */
    s16 anim[7];         /* 0x46 */
    u32 flags;           /* 0x54 */
    u8 v0, v1, v2, v3;   /* 0x58 */
    u8 pad1;             /* 0x5c */
    s8 count;            /* 0x5d */
    u8 pad2[2];          /* 0x5e */
} ScreenFxHdr; /* 0x60 */

typedef void (*ModgfxLaunchFn)(ScreenFxHdr *hdr, int a, int b, u8 *c, int d, u8 *e, int f, int g);

typedef struct {
    u8 pad[0x1f8];
    s16 anims[21];
} ScreenAnimTable;

extern u8 lbl_80317BD8[];
extern int *gModgfxInterface;
extern f32 lbl_803E13A0;
extern f32 lbl_803E13A4;
extern f32 lbl_803E13A8;
extern f32 lbl_803E13AC;
extern f32 lbl_803E13B0;
extern f32 lbl_803E13B4;
extern f32 lbl_803E13B8;
extern f32 lbl_803E13BC;
extern f32 lbl_803E13C0;
extern f32 lbl_803E13C4;

void dll_9B_func03(int a, int b, int p, uint flags)
{
    ScreenFxHdr hdr;
    u8 buf[440];
    ScreenFxPart parts[14];
    u8 *base = (u8 *)lbl_80317BD8;
    ScreenFxPart *pp = parts;

    parts[0].state = 0;
    parts[0].id = 0x15;
    parts[0].tex = base + 0x1b0;
    parts[0].flags = 4;
    parts[0].x = lbl_803E13A0;
    parts[0].y = lbl_803E13A0;
    parts[0].z = lbl_803E13A0;
    parts[1].state = 0;
    parts[1].id = 0x15;
    parts[1].tex = base + 0x1b0;
    parts[1].flags = 2;
    parts[1].x = lbl_803E13A4;
    parts[1].y = lbl_803E13A8;
    parts[1].z = lbl_803E13A4;
    parts[2].state = 0;
    parts[2].id = 0;
    parts[2].tex = 0;
    parts[2].flags = 0x400000;
    parts[2].x = lbl_803E13A0;
    parts[2].y = lbl_803E13AC;
    parts[2].z = lbl_803E13A0;
    parts[3].state = 0;
    parts[3].id = 0x124;
    parts[3].tex = 0;
    parts[3].flags = 0x20000;
    parts[3].x = lbl_803E13A0;
    parts[3].y = lbl_803E13A0;
    parts[3].z = lbl_803E13A0;
    parts[4].state = 1;
    parts[4].id = 0x15;
    parts[4].tex = base + 0x1b0;
    parts[4].flags = 2;
    parts[4].x = lbl_803E13B0;
    parts[4].y = lbl_803E13B4;
    parts[4].z = lbl_803E13B0;
    parts[5].state = 1;
    parts[5].id = 0xe;
    parts[5].tex = base + 0x1dc;
    parts[5].flags = 4;
    parts[5].x = lbl_803E13B8;
    parts[5].y = lbl_803E13A0;
    parts[5].z = lbl_803E13A0;
    parts[6].state = 1;
    parts[6].id = 0x15;
    parts[6].tex = base + 0x1b0;
    parts[6].flags = 0x4000;
    parts[6].x = lbl_803E13A8;
    parts[6].y = lbl_803E13BC;
    parts[6].z = lbl_803E13A0;
    parts[7].state = 1;
    parts[7].id = 0;
    parts[7].tex = 0;
    parts[7].flags = 0x400000;
    parts[7].x = lbl_803E13A0;
    parts[7].y = lbl_803E13C0;
    parts[7].z = lbl_803E13A0;
    parts[8].state = 2;
    parts[8].id = 0x15;
    parts[8].tex = base + 0x1b0;
    parts[8].flags = 0x4000;
    parts[8].x = lbl_803E13A8;
    parts[8].y = lbl_803E13BC;
    parts[8].z = lbl_803E13A0;
    parts[9].state = 3;
    parts[9].id = 0x124;
    parts[9].tex = 0;
    parts[9].flags = 0x20000;
    parts[9].x = lbl_803E13A0;
    parts[9].y = lbl_803E13A0;
    parts[9].z = lbl_803E13A0;
    parts[10].state = 3;
    parts[10].id = 0xe;
    parts[10].tex = base + 0x1dc;
    parts[10].flags = 4;
    parts[10].x = lbl_803E13A0;
    parts[10].y = lbl_803E13A0;
    parts[10].z = lbl_803E13A0;
    parts[11].state = 3;
    parts[11].id = 0x15;
    parts[11].tex = base + 0x1b0;
    parts[11].flags = 0x4000;
    parts[11].x = lbl_803E13A8;
    parts[11].y = lbl_803E13BC;
    parts[11].z = lbl_803E13A0;
    parts[12].state = 3;
    parts[12].id = 0x15;
    parts[12].tex = base + 0x1b0;
    parts[12].flags = 2;
    parts[12].x = lbl_803E13A4;
    parts[12].y = lbl_803E13C4;
    parts[12].z = lbl_803E13A4;
    parts[13].state = 3;
    parts[13].id = 0;
    parts[13].tex = 0;
    parts[13].flags = 0x400000;
    parts[13].x = lbl_803E13A0;
    parts[13].y = lbl_803E13AC;
    parts[13].z = lbl_803E13A0;

    hdr.v0 = 0;
    hdr.target = a;
    hdr.b = (s16)b;
    hdr.bx = lbl_803E13A0;
    hdr.by = lbl_803E13A0;
    hdr.bz = lbl_803E13A0;
    hdr.ax = lbl_803E13A0;
    hdr.ay = lbl_803E13A0;
    hdr.az = lbl_803E13A0;
    hdr.r = lbl_803E13C4;
    hdr.c2 = 2;
    hdr.c7 = 7;
    hdr.v1 = 0xe;
    hdr.v2 = 0;
    hdr.v3 = 0x1e;
    hdr.count = (s8)((buf - (u8 *)pp) / 0x18);
    hdr.anim[0] = *(s16 *)(base + 0x1f8);
    hdr.anim[1] = *(s16 *)(base + 0x1fa);
    hdr.anim[2] = *(s16 *)(base + 0x1fc);
    hdr.anim[3] = *(s16 *)(base + 0x1fe);
    hdr.anim[4] = *(s16 *)(base + 0x200);
    hdr.anim[5] = *(s16 *)(base + 0x202);
    hdr.anim[6] = *(s16 *)(base + 0x204);
    hdr.parts = pp;
    hdr.flags = 0xc010480;
    hdr.flags |= flags;
    if ((hdr.flags & 1) != 0) {
        if ((void *)a != NULL) {
            hdr.bx = lbl_803E13A0 + *(f32 *)(a + 0x18);
            hdr.by = lbl_803E13A0 + *(f32 *)(a + 0x1c);
            hdr.bz = lbl_803E13A0 + *(f32 *)(a + 0x20);
        } else {
            hdr.bx = lbl_803E13A0 + *(f32 *)(p + 0xc);
            hdr.by = lbl_803E13A0 + *(f32 *)(p + 0x10);
            hdr.bz = lbl_803E13A0 + *(f32 *)(p + 0x14);
        }
    }
    (*(ModgfxLaunchFn)*(int *)(*gModgfxInterface + 8))(&hdr, 0, 0x15, base, 0x18, base + 0xd4,
                                                       0x156, 0);
}

/*
 * --INFO--
 *
 * Function: dll_9C_func03
 * EN v1.0 Address: 0x800FD2B4
 * EN v1.0 Size: 1160b
 * EN v1.1 Address: 0x800FD550
 * EN v1.1 Size: 1160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_80317E00[];
extern f32 lbl_803E13C8;
extern f32 lbl_803E13CC;
extern f32 lbl_803E13D0;
extern f32 lbl_803E13D4;
extern f32 lbl_803E13D8;
extern f32 lbl_803E13DC;
extern f32 lbl_803E13E0;
extern f32 lbl_803E13E4;
extern f32 lbl_803E13E8;

void dll_9C_func03(int a, int b, int p, uint flags)
{
    ScreenFxHdr hdr;
    ScreenFxPart parts[32];
    u8 *base = (u8 *)lbl_80317E00;
    ScreenFxPart *pp = parts;
    ScreenFxPart *cur;
    int idx;

    parts[0].state = 0;
    parts[0].id = 0x15;
    parts[0].tex = base + 0x1b0;
    parts[0].flags = 4;
    parts[0].x = lbl_803E13C8;
    parts[0].y = lbl_803E13C8;
    parts[0].z = lbl_803E13C8;
    parts[1].state = 0;
    parts[1].id = 0x15;
    parts[1].tex = base + 0x1b0;
    parts[1].flags = 2;
    parts[1].x = lbl_803E13CC;
    parts[1].y = lbl_803E13D0;
    parts[1].z = lbl_803E13CC;
    cur = pp + 2;
    if (b != 1) {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x400000;
        cur->x = lbl_803E13C8;
        cur->y = lbl_803E13C8;
        cur->z = lbl_803E13C8;
        cur++;
    }
    if (b == 1) {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x80;
        cur->x = (f32)*(s16 *)(p + 4);
        cur->y = (f32)*(s16 *)(p + 2);
        cur->z = (f32)*(s16 *)(p + 0);
        cur++;
    }
    if (b == 1) {
        cur->state = 1;
        cur->id = 0x15;
        cur->tex = base + 0x1b0;
        cur->flags = 2;
        cur->x = lbl_803E13D4;
        cur->y = *(f32 *)(p + 0x10) / lbl_803E13D4;
        cur->z = lbl_803E13D4;
    } else {
        cur->state = 1;
        cur->id = 0x15;
        cur->tex = base + 0x1b0;
        cur->flags = 2;
        cur->x = lbl_803E13D4;
        cur->y = lbl_803E13D8;
        cur->z = lbl_803E13D4;
    }
    cur[1].state = 1;
    cur[1].id = 0xe;
    cur[1].tex = base + 0x1dc;
    cur[1].flags = 4;
    cur[1].x = lbl_803E13DC;
    cur[1].y = lbl_803E13C8;
    cur[1].z = lbl_803E13C8;
    cur[2].state = 1;
    cur[2].id = 0x15;
    cur[2].tex = base + 0x1b0;
    cur[2].flags = 0x4000;
    cur[2].x = lbl_803E13D0;
    cur[2].y = lbl_803E13E0;
    cur[2].z = lbl_803E13C8;
    cur += 3;
    if (b != 1) {
        cur->state = 1;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x100;
        cur->x = lbl_803E13C8;
        cur->y = lbl_803E13C8;
        cur->z = lbl_803E13E4;
        cur++;
    }
    cur[0].state = 2;
    cur[0].id = 0x15;
    cur[0].tex = base + 0x1b0;
    cur[0].flags = 0x4000;
    cur[0].x = lbl_803E13D0;
    cur[0].y = lbl_803E13E0;
    cur[0].z = lbl_803E13C8;
    cur[1].state = 3;
    cur[1].id = 0x15;
    cur[1].tex = base + 0x1b0;
    cur[1].flags = 0x4000;
    cur[1].x = lbl_803E13D0;
    cur[1].y = lbl_803E13E0;
    cur[1].z = lbl_803E13C8;
    cur[2].state = 3;
    cur[2].id = 0xe;
    cur[2].tex = base + 0x1dc;
    cur[2].flags = 4;
    cur[2].x = lbl_803E13C8;
    cur[2].y = lbl_803E13C8;
    cur[2].z = lbl_803E13C8;
    cur[3].state = 1;

    hdr.v0 = 0;
    hdr.target = a;
    hdr.b = (s16)b;
    hdr.bx = lbl_803E13C8;
    hdr.by = lbl_803E13C8;
    hdr.bz = lbl_803E13C8;
    hdr.ax = lbl_803E13C8;
    hdr.ay = lbl_803E13C8;
    hdr.az = lbl_803E13C8;
    hdr.r = lbl_803E13E8;
    hdr.c2 = 2;
    hdr.c7 = 7;
    hdr.v1 = 0xe;
    hdr.v2 = 0;
    hdr.v3 = 0x1e;
    hdr.count = (s8)(((u8 *)(cur + 3) - (u8 *)pp) / 0x18);
    idx = b * 7;
    hdr.anim[0] = *(s16 *)((u8 *)(base + idx * 2) + 0x1f8);
    hdr.anim[1] = *(s16 *)((u8 *)(base + (idx + 1) * 2) + 0x1f8);
    hdr.anim[2] = *(s16 *)((u8 *)(base + (idx + 2) * 2) + 0x1f8);
    hdr.anim[3] = *(s16 *)((u8 *)(base + (idx + 3) * 2) + 0x1f8);
    hdr.anim[4] = *(s16 *)((u8 *)(base + (idx + 4) * 2) + 0x1f8);
    hdr.anim[5] = *(s16 *)((u8 *)(base + (idx + 5) * 2) + 0x1f8);
    hdr.anim[6] = *(s16 *)((u8 *)(base + (idx + 6) * 2) + 0x1f8);
    hdr.parts = parts;
    hdr.flags = 0xc010480;
    hdr.flags |= flags;
    if ((hdr.flags & 1) != 0) {
        if ((void *)a != NULL) {
            hdr.bx = lbl_803E13C8 + *(f32 *)(a + 0x18);
            hdr.by = lbl_803E13C8 + *(f32 *)(a + 0x1c);
            hdr.bz = lbl_803E13C8 + *(f32 *)(a + 0x20);
        } else {
            hdr.bx = lbl_803E13C8 + *(f32 *)(p + 0xc);
            hdr.by = lbl_803E13C8 + *(f32 *)(p + 0x10);
            hdr.bz = lbl_803E13C8 + *(f32 *)(p + 0x14);
        }
    }
    (*(ModgfxLaunchFn)*(int *)(*gModgfxInterface + 8))(&hdr, 0, 0x15, base, 0x18, base + 0xd4,
                                                       0x154, 0);
}


/* Trivial nops */
void dll_9A_func01_nop(void) {}
void dll_9A_func00_nop(void) {}
void dll_9B_func01_nop(void) {}
void dll_9B_func00_nop(void) {}
void dll_9C_func01_nop(void) {}
void dll_9C_func00_nop(void) {}
