// Function: FUN_800fc854
// Entry: 800fc854
// Size: 2428 bytes

/* WARNING: Removing unreachable block (ram,0x800fd1b0) */
/* WARNING: Removing unreachable block (ram,0x800fd1a8) */
/* WARNING: Removing unreachable block (ram,0x800fc86c) */
/* WARNING: Removing unreachable block (ram,0x800fc864) */

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
  puVar13[10] = &DAT_803dc5c4;
  puVar13[6] = 4;
  puVar13[7] = FLOAT_803e1ff0;
  puVar13[8] = FLOAT_803e1ff0;
  puVar13[9] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0x46) = 0;
  *(undefined2 *)(puVar13 + 0x11) = 3;
  puVar13[0x10] = &DAT_803dc5c4;
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
  puVar13[0x16] = &DAT_803dc5c0;
  puVar13[0x12] = 4;
  puVar13[0x13] = FLOAT_803e2004;
  puVar13[0x14] = FLOAT_803e1ff0;
  puVar13[0x15] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0x76) = 1;
  *(undefined2 *)(puVar13 + 0x1d) = 0;
  puVar13[0x1c] = &DAT_803dc5c0;
  puVar13[0x18] = 0x4000;
  puVar13[0x19] = FLOAT_803e2008;
  puVar13[0x1a] = FLOAT_803e1ff0;
  puVar13[0x1b] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0x8e) = 1;
  *(undefined2 *)(puVar13 + 0x23) = 3;
  puVar13[0x22] = &DAT_803dc5c4;
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
  puVar13[0x34] = &DAT_803dc5c0;
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
  puVar13[0x40] = &DAT_803dc5c0;
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
  puVar13[0x4c] = &DAT_803dc5c0;
  puVar13[0x48] = 0x4000;
  puVar13[0x49] = FLOAT_803e2008;
  puVar13[0x4a] = FLOAT_803e1ff0;
  puVar13[0x4b] = FLOAT_803e1ff0;
  *(undefined *)((int)puVar13 + 0x14e) = 4;
  *(undefined2 *)(puVar13 + 0x53) = 1;
  puVar13[0x52] = &DAT_803dc5c0;
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

