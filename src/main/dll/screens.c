#include "ghidra_import.h"
#include "main/dll/screens.h"

extern uint FUN_80022264();
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
extern f32 FLOAT_803e1ff0;
extern f32 FLOAT_803e1ff4;
extern f32 FLOAT_803e1ff8;
extern f32 FLOAT_803e1ffc;
extern f32 FLOAT_803e2000;
extern f32 FLOAT_803e2004;
extern f32 FLOAT_803e2008;
extern f32 FLOAT_803e200c;
extern f32 FLOAT_803e2010;
extern f32 FLOAT_803e2014;
extern f32 FLOAT_803e2020;
extern f32 FLOAT_803e2024;
extern f32 FLOAT_803e2028;
extern f32 FLOAT_803e202c;
extern f32 FLOAT_803e2030;
extern f32 FLOAT_803e2034;
extern f32 FLOAT_803e2038;
extern f32 FLOAT_803e203c;
extern f32 FLOAT_803e2040;
extern f32 FLOAT_803e2044;
extern f32 FLOAT_803e2048;
extern f32 FLOAT_803e204c;
extern f32 FLOAT_803e2050;
extern f32 FLOAT_803e2054;
extern f32 FLOAT_803e2058;
extern f32 FLOAT_803e205c;
extern f32 FLOAT_803e2060;
extern f32 FLOAT_803e2064;
extern f32 FLOAT_803e2068;

/*
 * --INFO--
 *
 * Function: FUN_800fc854
 * EN v1.0 Address: 0x800FC854
 * EN v1.0 Size: 2436b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fc854(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
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
  uVar8 = FUN_80022264(0,0x14);
  sStack_426 = (short)uVar2;
  local_428 = (undefined2)((uint)uVar2 >> 0x10);
  uVar9 = FUN_80022264(0xffffffec,0x14);
  local_424 = (short)((uint)uVar3 >> 0x10);
  sStack_422 = (short)uVar3;
  uVar10 = FUN_80022264(0xffffffec,0x14);
  uVar11 = FUN_80022264(0xffffffec,0x14);
  local_420 = (short)((uint)uVar4 >> 0x10);
  uStack_41e = (undefined2)uVar4;
  if (iVar6 == 0) {
    local_3a2[0] = 0;
    local_3a4 = 3;
    local_3a8 = &DAT_803dc5c4;
    local_3b8 = 8;
    uVar12 = FUN_80022264(0,0x69);
    uStack_b4 = uVar12 + 0x8c ^ 0x80000000;
    local_b8 = 0x43300000;
    local_3b4 = (float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e2018);
    uVar12 = FUN_80022264(0,0x69);
    uStack_ac = uVar12 + 0x8c ^ 0x80000000;
    local_b0 = 0x43300000;
    local_3b0 = (float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e2018);
    uVar12 = FUN_80022264(0,0x1e);
    uStack_a4 = uVar12 + 0xe1 ^ 0x80000000;
    local_a8 = 0x43300000;
    local_3ac = (float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e2018);
    puVar13 = (undefined4 *)(local_3a2 + 2);
  }
  else {
    puVar13 = &local_3b8;
    if (iVar6 == 1) {
      local_3a2[0] = 0;
      local_3a4 = 3;
      local_3a8 = &DAT_803dc5c4;
      local_3b8 = 8;
      uVar12 = FUN_80022264(0,0x1e);
      uStack_a4 = uVar12 + 0xe1 ^ 0x80000000;
      local_a8 = 0x43300000;
      local_3b4 = (float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e2018);
      uVar12 = FUN_80022264(0,0x69);
      uStack_ac = uVar12 + 0x8c ^ 0x80000000;
      local_b0 = 0x43300000;
      local_3b0 = (float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e2018);
      uVar12 = FUN_80022264(0,0x41);
      uStack_b4 = uVar12 + 0x78 ^ 0x80000000;
      local_b8 = 0x43300000;
      local_3ac = (float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e2018);
      puVar13 = (undefined4 *)(local_3a2 + 2);
    }
  }
  uStack_a4 = FUN_80022264(0xffffc950,14000);
  uStack_a4 = uStack_a4 ^ 0x80000000;
  local_a8 = 0x43300000;
  dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack_a4) - DOUBLE_803e2018);
  uStack_ac = FUN_80022264(0xffffd120,12000);
  uStack_ac = uStack_ac ^ 0x80000000;
  local_b0 = 0x43300000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uStack_ac) - DOUBLE_803e2018);
  dVar14 = (double)fVar1;
  *(undefined *)((int)puVar13 + 0x16) = 0;
  *(undefined2 *)(puVar13 + 5) = 0;
  puVar13[4] = 0;
  *puVar13 = 0x80;
  puVar13[1] = FLOAT_803e1ff0;
  puVar13[2] = fVar1;
  puVar13[3] = (float)dVar15;
  *(undefined *)((int)puVar13 + 0x2e) = 0;
  *(undefined2 *)(puVar13 + 0xb) = 3;
  puVar13[10] = (undefined4)&DAT_803dc5c4;
  puVar13[6] = 4;
  puVar13[7] = FLOAT_803e1ff0;
  puVar13[8] = FLOAT_803e1ff0;
  puVar13[9] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0x46) = 0;
  *(undefined2 *)(puVar13 + 0x11) = 3;
  puVar13[0x10] = (undefined4)&DAT_803dc5c4;
  puVar13[0xc] = 2;
  puVar13[0xd] = FLOAT_803e1ff4;
  uStack_b4 = FUN_80022264(0,0x32);
  uStack_b4 = uStack_b4 ^ 0x80000000;
  local_b8 = 0x43300000;
  puVar13[0xe] = FLOAT_803e1ffc * (float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e2018)
                 + FLOAT_803e1ff8;
  uStack_9c = FUN_80022264(4,6);
  uStack_9c = uStack_9c ^ 0x80000000;
  local_a0 = 0x43300000;
  puVar13[0xf] = FLOAT_803e1ffc * (float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e2018)
                 + FLOAT_803e2000;
  *(undefined *)((int)puVar13 + 0x5e) = 1;
  *(undefined2 *)(puVar13 + 0x17) = 1;
  puVar13[0x16] = (undefined4)&DAT_803dc5c0;
  puVar13[0x12] = 4;
  puVar13[0x13] = FLOAT_803e2004;
  puVar13[0x14] = FLOAT_803e1ff0;
  puVar13[0x15] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0x76) = 1;
  *(undefined2 *)(puVar13 + 0x1d) = 0;
  puVar13[0x1c] = (undefined4)&DAT_803dc5c0;
  puVar13[0x18] = 0x4000;
  puVar13[0x19] = FLOAT_803e2008;
  puVar13[0x1a] = FLOAT_803e1ff0;
  puVar13[0x1b] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0x8e) = 1;
  *(undefined2 *)(puVar13 + 0x23) = 3;
  puVar13[0x22] = (undefined4)&DAT_803dc5c4;
  puVar13[0x1e] = 2;
  puVar13[0x1f] = FLOAT_803e200c;
  puVar13[0x20] = FLOAT_803e2010;
  puVar13[0x21] = FLOAT_803e2010;
  *(undefined *)((int)puVar13 + 0xa6) = 1;
  *(undefined2 *)(puVar13 + 0x29) = 0;
  puVar13[0x28] = 0;
  puVar13[0x24] = 0x80;
  uStack_94 = FUN_80022264(0xffff8300,32000);
  uStack_94 = uStack_94 ^ 0x80000000;
  local_98 = 0x43300000;
  puVar13[0x25] = (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e2018);
  uStack_8c = FUN_80022264(0xffffffff,1);
  uStack_8c = uStack_8c ^ 0x80000000;
  local_90 = 0x43300000;
  puVar13[0x26] =
       (float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e2018));
  uStack_84 = FUN_80022264(0xffffffff,1);
  uStack_84 = uStack_84 ^ 0x80000000;
  local_88 = 0x43300000;
  puVar13[0x27] =
       (float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e2018));
  *(undefined *)((int)puVar13 + 0xbe) = 2;
  *(undefined2 *)(puVar13 + 0x2f) = 0;
  puVar13[0x2e] = 0;
  puVar13[0x2a] = 0x80;
  uStack_7c = FUN_80022264(0xffff8300,32000);
  uStack_7c = uStack_7c ^ 0x80000000;
  local_80 = 0x43300000;
  puVar13[0x2b] = (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e2018);
  uStack_74 = FUN_80022264(0xffffffff,1);
  uStack_74 = uStack_74 ^ 0x80000000;
  local_78 = 0x43300000;
  puVar13[0x2c] =
       (float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e2018));
  uStack_6c = FUN_80022264(0xffffffff,1);
  uStack_6c = uStack_6c ^ 0x80000000;
  local_70 = 0x43300000;
  puVar13[0x2d] =
       (float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e2018));
  *(undefined *)((int)puVar13 + 0xd6) = 2;
  *(undefined2 *)(puVar13 + 0x35) = 0;
  puVar13[0x34] = (undefined4)&DAT_803dc5c0;
  puVar13[0x30] = 0x4000;
  puVar13[0x31] = FLOAT_803e2008;
  puVar13[0x32] = FLOAT_803e1ff0;
  puVar13[0x33] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0xee) = 3;
  *(undefined2 *)(puVar13 + 0x3b) = 0;
  puVar13[0x3a] = 0;
  puVar13[0x36] = 0x80;
  uStack_64 = FUN_80022264(0xffff8300,32000);
  uStack_64 = uStack_64 ^ 0x80000000;
  local_68 = 0x43300000;
  puVar13[0x37] = (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e2018);
  uStack_5c = FUN_80022264(0xffffffff,1);
  uStack_5c = uStack_5c ^ 0x80000000;
  local_60 = 0x43300000;
  puVar13[0x38] =
       (float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e2018));
  uStack_54 = FUN_80022264(0xffffffff,1);
  uStack_54 = uStack_54 ^ 0x80000000;
  local_58 = 0x43300000;
  puVar13[0x39] =
       (float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e2018));
  *(undefined *)((int)puVar13 + 0x106) = 3;
  *(undefined2 *)(puVar13 + 0x41) = 0;
  puVar13[0x40] = (undefined4)&DAT_803dc5c0;
  puVar13[0x3c] = 0x4000;
  puVar13[0x3d] = FLOAT_803e2008;
  puVar13[0x3e] = FLOAT_803e1ff0;
  puVar13[0x3f] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0x11e) = 4;
  *(undefined2 *)(puVar13 + 0x47) = 0;
  puVar13[0x46] = 0;
  puVar13[0x42] = 0x80;
  uStack_4c = FUN_80022264(0xffff8300,32000);
  uStack_4c = uStack_4c ^ 0x80000000;
  local_50 = 0x43300000;
  puVar13[0x43] = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e2018);
  uStack_44 = FUN_80022264(0xffffffff,1);
  uStack_44 = uStack_44 ^ 0x80000000;
  local_48 = 0x43300000;
  puVar13[0x44] =
       (float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e2018));
  uStack_3c = FUN_80022264(0xffffffff,1);
  uStack_3c = uStack_3c ^ 0x80000000;
  local_40 = 0x43300000;
  puVar13[0x45] =
       (float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e2018));
  *(undefined *)((int)puVar13 + 0x136) = 4;
  *(undefined2 *)(puVar13 + 0x4d) = 0;
  puVar13[0x4c] = (undefined4)&DAT_803dc5c0;
  puVar13[0x48] = 0x4000;
  puVar13[0x49] = FLOAT_803e2008;
  puVar13[0x4a] = FLOAT_803e1ff0;
  puVar13[0x4b] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0x14e) = 4;
  *(undefined2 *)(puVar13 + 0x53) = 1;
  puVar13[0x52] = (undefined4)&DAT_803dc5c0;
  puVar13[0x4e] = 4;
  puVar13[0x4f] = FLOAT_803e1ff0;
  puVar13[0x50] = FLOAT_803e1ff0;
  puVar13[0x51] = FLOAT_803e1ff0;
  local_3c0 = 0;
  local_3d4 = (undefined2)uVar16;
  local_3ec = FLOAT_803e1ff0;
  if (iVar6 == 0) {
    local_3e8 = FLOAT_803e1ff0;
  }
  else if (iVar6 == 1) {
    local_3e8 = FLOAT_803e2014;
  }
  local_3e4 = FLOAT_803e1ff0;
  local_3f8 = FLOAT_803e1ff0;
  local_3f4 = FLOAT_803e1ff0;
  local_3f0 = FLOAT_803e1ff0;
  local_3e0 = FLOAT_803e2010;
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
          local_3ec = FLOAT_803e1ff0 + *(float *)(param_3 + 0xc);
          local_3e8 = local_3e8 + *(float *)(param_3 + 0x10);
          local_3e4 = FLOAT_803e1ff0 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_3ec = FLOAT_803e1ff0 + *(float *)(iVar7 + 0x18);
        local_3e8 = local_3e8 + *(float *)(iVar7 + 0x1c);
        local_3e4 = FLOAT_803e1ff0 + *(float *)(iVar7 + 0x20);
      }
    }
    else {
      local_3ec = FLOAT_803e1ff0 + *(float *)(iVar7 + 0x18) + *(float *)(param_3 + 0xc);
      local_3e8 = local_3e8 + *(float *)(iVar7 + 0x1c) + *(float *)(param_3 + 0x10);
      local_3e4 = FLOAT_803e1ff0 + *(float *)(iVar7 + 0x20) + *(float *)(param_3 + 0x14);
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
 * Function: FUN_800fd1d8
 * EN v1.0 Address: 0x800FD1D8
 * EN v1.0 Size: 888b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fd1d8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined2 extraout_r4;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined4 local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined *local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined4 local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined *local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined4 local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined *local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined *local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined4 local_1e0;
  undefined2 local_1dc;
  undefined local_1da;
  undefined auStack_1d8 [472];
  
  local_384 = FUN_80286838();
  local_388 = &local_328;
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_803189d8;
  local_328 = 4;
  local_324 = FLOAT_803e2020;
  local_320 = FLOAT_803e2020;
  local_31c = FLOAT_803e2020;
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_803189d8;
  local_310 = 2;
  local_30c = FLOAT_803e2024;
  local_308 = FLOAT_803e2028;
  local_304 = FLOAT_803e2024;
  local_2e2 = 0;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x400000;
  local_2f4 = FLOAT_803e2020;
  local_2f0 = FLOAT_803e202c;
  local_2ec = FLOAT_803e2020;
  local_2ca = 0;
  local_2cc = 0x124;
  local_2d0 = 0;
  local_2e0 = 0x20000;
  local_2dc = FLOAT_803e2020;
  local_2d8 = FLOAT_803e2020;
  local_2d4 = FLOAT_803e2020;
  local_2b2 = 1;
  local_2b4 = 0x15;
  local_2b8 = &DAT_803189d8;
  local_2c8 = 2;
  local_2c4 = FLOAT_803e2030;
  local_2c0 = FLOAT_803e2034;
  local_2bc = FLOAT_803e2030;
  local_29a = 1;
  local_29c = 0xe;
  local_2a0 = &DAT_80318a04;
  local_2b0 = 4;
  local_2ac = FLOAT_803e2038;
  local_2a8 = FLOAT_803e2020;
  local_2a4 = FLOAT_803e2020;
  local_282 = 1;
  local_284 = 0x15;
  local_288 = &DAT_803189d8;
  local_298 = 0x4000;
  local_294 = FLOAT_803e2028;
  local_290 = FLOAT_803e203c;
  local_28c = FLOAT_803e2020;
  local_26a = 1;
  local_26c = 0;
  local_270 = 0;
  local_280 = 0x400000;
  local_27c = FLOAT_803e2020;
  local_278 = FLOAT_803e2040;
  local_274 = FLOAT_803e2020;
  local_252 = 2;
  local_254 = 0x15;
  local_258 = &DAT_803189d8;
  local_268 = 0x4000;
  local_264 = FLOAT_803e2028;
  local_260 = FLOAT_803e203c;
  local_25c = FLOAT_803e2020;
  local_23a = 3;
  local_23c = 0x124;
  local_240 = 0;
  local_250 = 0x20000;
  local_24c = FLOAT_803e2020;
  local_248 = FLOAT_803e2020;
  local_244 = FLOAT_803e2020;
  local_222 = 3;
  local_224 = 0xe;
  local_228 = &DAT_80318a04;
  local_238 = 4;
  local_234 = FLOAT_803e2020;
  local_230 = FLOAT_803e2020;
  local_22c = FLOAT_803e2020;
  local_20a = 3;
  local_20c = 0x15;
  local_210 = &DAT_803189d8;
  local_220 = 0x4000;
  local_21c = FLOAT_803e2028;
  local_218 = FLOAT_803e203c;
  local_214 = FLOAT_803e2020;
  local_1f2 = 3;
  local_1f4 = 0x15;
  local_1f8 = &DAT_803189d8;
  local_208 = 2;
  local_204 = FLOAT_803e2024;
  local_200 = FLOAT_803e2044;
  local_1fc = FLOAT_803e2024;
  local_1da = 3;
  local_1dc = 0;
  local_1e0 = 0;
  local_1f0 = 0x400000;
  local_1ec = FLOAT_803e2020;
  local_1e8 = FLOAT_803e202c;
  local_1e4 = FLOAT_803e2020;
  local_330 = 0;
  local_35c = FLOAT_803e2020;
  local_358 = FLOAT_803e2020;
  local_354 = FLOAT_803e2020;
  local_368 = FLOAT_803e2020;
  local_364 = FLOAT_803e2020;
  local_360 = FLOAT_803e2020;
  local_350 = FLOAT_803e2044;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  iVar1 = (int)(auStack_1d8 + -(int)local_388) / 0x18 +
          ((int)(auStack_1d8 + -(int)local_388) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_80318a20;
  local_340 = DAT_80318a22;
  local_33e = DAT_80318a24;
  local_33c = DAT_80318a26;
  local_33a = DAT_80318a28;
  local_338 = DAT_80318a2a;
  local_336 = DAT_80318a2c;
  local_334 = param_4 | 0xc010480;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = FLOAT_803e2020 + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e2020 + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e2020 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e2020 + *(float *)(local_384 + 0x18);
      local_358 = FLOAT_803e2020 + *(float *)(local_384 + 0x1c);
      local_354 = FLOAT_803e2020 + *(float *)(local_384 + 0x20);
    }
  }
  local_344 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80318828,0x18,&DAT_803188fc,0x156,0);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fd550
 * EN v1.0 Address: 0x800FD550
 * EN v1.0 Size: 1160b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fd550(int param_1,int param_2,short *param_3,uint param_4)
{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined4 local_288;
  undefined2 local_284;
  undefined local_282 [2];
  undefined4 local_280 [5];
  undefined local_26a [578];
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_80318c00;
  local_328 = 4;
  local_324 = FLOAT_803e2048;
  local_320 = FLOAT_803e2048;
  local_31c = FLOAT_803e2048;
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_80318c00;
  local_310 = 2;
  local_30c = FLOAT_803e204c;
  local_308 = FLOAT_803e2050;
  local_304 = FLOAT_803e204c;
  if (param_2 == 1) {
    local_2f8 = 0x80;
    uStack_24 = (int)param_3[2] ^ 0x80000000;
    local_28 = 0x43300000;
    local_2f4 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2070);
    uStack_1c = (int)param_3[1] ^ 0x80000000;
    local_20 = 0x43300000;
    local_2f0 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e2070);
    uStack_14 = (int)*param_3 ^ 0x80000000;
    local_18 = 0x43300000;
    local_2ec = (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e2070);
    local_2d8 = *(float *)(param_3 + 8) / FLOAT_803e2054;
  }
  else {
    local_2f8 = 0x400000;
    local_2f4 = FLOAT_803e2048;
    local_2f0 = FLOAT_803e2048;
    local_2ec = FLOAT_803e2048;
    local_2d8 = FLOAT_803e2058;
  }
  local_2ca = 1;
  local_2cc = 0x15;
  local_2d0 = &DAT_80318c00;
  local_2dc = FLOAT_803e2054;
  local_2e0 = 2;
  local_2e2 = 0;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2b2 = 1;
  local_2b4 = 0xe;
  local_2b8 = &DAT_80318c2c;
  local_2c8 = 4;
  local_2c4 = FLOAT_803e205c;
  local_2c0 = FLOAT_803e2048;
  local_2bc = FLOAT_803e2048;
  local_29a = 1;
  local_29c = 0x15;
  local_2a0 = &DAT_80318c00;
  local_2b0 = 0x4000;
  local_2ac = FLOAT_803e2050;
  local_2a8 = FLOAT_803e2060;
  local_2a4 = FLOAT_803e2048;
  puVar2 = &local_298;
  if (param_2 != 1) {
    local_282[0] = 1;
    local_284 = 0;
    local_288 = 0;
    local_298 = 0x100;
    local_294 = FLOAT_803e2048;
    local_290 = FLOAT_803e2048;
    local_28c = FLOAT_803e2064;
    puVar2 = (undefined4 *)(local_282 + 2);
  }
  *(undefined *)((int)puVar2 + 0x16) = 2;
  *(undefined2 *)(puVar2 + 5) = 0x15;
  puVar2[4] = (undefined4)&DAT_80318c00;
  *puVar2 = 0x4000;
  puVar2[1] = FLOAT_803e2050;
  puVar2[2] = FLOAT_803e2060;
  puVar2[3] = FLOAT_803e2048;
  *(undefined *)((int)puVar2 + 0x2e) = 3;
  *(undefined2 *)(puVar2 + 0xb) = 0x15;
  puVar2[10] = (undefined4)&DAT_80318c00;
  puVar2[6] = 0x4000;
  puVar2[7] = FLOAT_803e2050;
  puVar2[8] = FLOAT_803e2060;
  puVar2[9] = FLOAT_803e2048;
  *(undefined *)((int)puVar2 + 0x46) = 3;
  *(undefined2 *)(puVar2 + 0x11) = 0xe;
  puVar2[0x10] = (undefined4)&DAT_80318c2c;
  puVar2[0xc] = 4;
  puVar2[0xd] = FLOAT_803e2048;
  puVar2[0xe] = FLOAT_803e2048;
  puVar2[0xf] = FLOAT_803e2048;
  *(undefined *)((int)puVar2 + 0x5e) = 1;
  local_330 = 0;
  local_344 = (undefined2)param_2;
  local_35c = FLOAT_803e2048;
  local_358 = FLOAT_803e2048;
  local_354 = FLOAT_803e2048;
  local_368 = FLOAT_803e2048;
  local_364 = FLOAT_803e2048;
  local_360 = FLOAT_803e2048;
  local_350 = FLOAT_803e2068;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  iVar1 = (int)puVar2 + (0x48 - (int)&local_328);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  iVar1 = param_2 * 7;
  local_342 = *(undefined2 *)(&DAT_80318c48 + param_2 * 0xe);
  local_340 = *(undefined2 *)(&DAT_80318c48 + (iVar1 + 1) * 2);
  local_33e = *(undefined2 *)(&DAT_80318c48 + (iVar1 + 2) * 2);
  local_33c = *(undefined2 *)(&DAT_80318c48 + (iVar1 + 3) * 2);
  local_33a = *(undefined2 *)(&DAT_80318c48 + (iVar1 + 4) * 2);
  local_338 = *(undefined2 *)(&DAT_80318c48 + (iVar1 + 5) * 2);
  local_336 = *(undefined2 *)(&DAT_80318c48 + (iVar1 + 6) * 2);
  local_388 = &local_328;
  local_334 = param_4 | 0xc010480;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_35c = FLOAT_803e2048 + *(float *)(param_3 + 6);
      local_358 = FLOAT_803e2048 + *(float *)(param_3 + 8);
      local_354 = FLOAT_803e2048 + *(float *)(param_3 + 10);
    }
    else {
      local_35c = FLOAT_803e2048 + *(float *)(param_1 + 0x18);
      local_358 = FLOAT_803e2048 + *(float *)(param_1 + 0x1c);
      local_354 = FLOAT_803e2048 + *(float *)(param_1 + 0x20);
    }
  }
  local_384 = param_1;
  local_2d4 = local_2dc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80318a50,0x18,&DAT_80318b24,0x154,0);
  return;
}
