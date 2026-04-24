// Function: FUN_800fc5b8
// Entry: 800fc5b8
// Size: 2428 bytes

/* WARNING: Removing unreachable block (ram,0x800fcf0c) */
/* WARNING: Removing unreachable block (ram,0x800fcf14) */

void FUN_800fc5b8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  float fVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined4 uVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined8 uVar11;
  short sStack1062;
  short local_424;
  short local_420;
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
  uint uStack180;
  undefined4 local_b0;
  uint uStack172;
  undefined4 local_a8;
  uint uStack164;
  undefined4 local_a0;
  uint uStack156;
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  undefined4 local_88;
  uint uStack132;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar11 = FUN_802860d8();
  local_3c6 = DAT_802c218c;
  uVar4 = DAT_802c2188;
  uVar3 = DAT_802c2184;
  uVar2 = DAT_802c2180;
  local_414 = (int)((ulonglong)uVar11 >> 0x20);
  iVar5 = (int)uVar11;
  local_3d0 = FUN_800221a0(0,0x14);
  sStack1062 = (short)uVar2;
  local_3d0 = sStack1062 + local_3d0;
  local_3d2 = (undefined2)((uint)uVar2 >> 0x10);
  local_3ce = FUN_800221a0(0xffffffec,0x14);
  local_424 = (short)((uint)uVar3 >> 0x10);
  local_3ce = local_424 + local_3ce;
  local_3cc = FUN_800221a0(0xffffffec,0x14);
  local_3cc = (short)uVar3 + local_3cc;
  local_3ca = FUN_800221a0(0xffffffec,0x14);
  local_420 = (short)((uint)uVar4 >> 0x10);
  local_3ca = local_420 + local_3ca;
  local_3c8 = (undefined2)uVar4;
  if (iVar5 == 0) {
    local_3a2[0] = 0;
    local_3a4 = 3;
    local_3a8 = &DAT_803db964;
    local_3b8 = 8;
    iVar6 = FUN_800221a0(0,0x69);
    uStack180 = iVar6 + 0x8cU ^ 0x80000000;
    local_b8 = 0x43300000;
    local_3b4 = (float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e1398);
    iVar6 = FUN_800221a0(0,0x69);
    uStack172 = iVar6 + 0x8cU ^ 0x80000000;
    local_b0 = 0x43300000;
    local_3b0 = (float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803e1398);
    iVar6 = FUN_800221a0(0,0x1e);
    uStack164 = iVar6 + 0xe1U ^ 0x80000000;
    local_a8 = 0x43300000;
    local_3ac = (float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803e1398);
    puVar7 = (undefined4 *)(local_3a2 + 2);
  }
  else {
    puVar7 = &local_3b8;
    if (iVar5 == 1) {
      local_3a2[0] = 0;
      local_3a4 = 3;
      local_3a8 = &DAT_803db964;
      local_3b8 = 8;
      iVar6 = FUN_800221a0(0,0x1e);
      uStack164 = iVar6 + 0xe1U ^ 0x80000000;
      local_a8 = 0x43300000;
      local_3b4 = (float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803e1398);
      iVar6 = FUN_800221a0(0,0x69);
      uStack172 = iVar6 + 0x8cU ^ 0x80000000;
      local_b0 = 0x43300000;
      local_3b0 = (float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803e1398);
      iVar6 = FUN_800221a0(0,0x41);
      uStack180 = iVar6 + 0x78U ^ 0x80000000;
      local_b8 = 0x43300000;
      local_3ac = (float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e1398);
      puVar7 = (undefined4 *)(local_3a2 + 2);
    }
  }
  uStack164 = FUN_800221a0(0xffffc950,14000);
  uStack164 = uStack164 ^ 0x80000000;
  local_a8 = 0x43300000;
  dVar10 = (double)(float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803e1398);
  uStack172 = FUN_800221a0(0xffffd120,12000);
  uStack172 = uStack172 ^ 0x80000000;
  local_b0 = 0x43300000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uStack172) - DOUBLE_803e1398);
  dVar9 = (double)fVar1;
  *(undefined *)((int)puVar7 + 0x16) = 0;
  *(undefined2 *)(puVar7 + 5) = 0;
  puVar7[4] = 0;
  *puVar7 = 0x80;
  puVar7[1] = FLOAT_803e1370;
  puVar7[2] = fVar1;
  puVar7[3] = (float)dVar10;
  *(undefined *)((int)puVar7 + 0x2e) = 0;
  *(undefined2 *)(puVar7 + 0xb) = 3;
  puVar7[10] = &DAT_803db964;
  puVar7[6] = 4;
  puVar7[7] = FLOAT_803e1370;
  puVar7[8] = FLOAT_803e1370;
  puVar7[9] = FLOAT_803e1370;
  *(undefined *)((int)puVar7 + 0x46) = 0;
  *(undefined2 *)(puVar7 + 0x11) = 3;
  puVar7[0x10] = &DAT_803db964;
  puVar7[0xc] = 2;
  puVar7[0xd] = FLOAT_803e1374;
  uStack180 = FUN_800221a0(0,0x32);
  uStack180 = uStack180 ^ 0x80000000;
  local_b8 = 0x43300000;
  puVar7[0xe] = FLOAT_803e137c * (float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e1398) +
                FLOAT_803e1378;
  uStack156 = FUN_800221a0(4,6);
  uStack156 = uStack156 ^ 0x80000000;
  local_a0 = 0x43300000;
  puVar7[0xf] = FLOAT_803e137c * (float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803e1398) +
                FLOAT_803e1380;
  *(undefined *)((int)puVar7 + 0x5e) = 1;
  *(undefined2 *)(puVar7 + 0x17) = 1;
  puVar7[0x16] = &DAT_803db960;
  puVar7[0x12] = 4;
  puVar7[0x13] = FLOAT_803e1384;
  puVar7[0x14] = FLOAT_803e1370;
  puVar7[0x15] = FLOAT_803e1370;
  *(undefined *)((int)puVar7 + 0x76) = 1;
  *(undefined2 *)(puVar7 + 0x1d) = 0;
  puVar7[0x1c] = &DAT_803db960;
  puVar7[0x18] = 0x4000;
  puVar7[0x19] = FLOAT_803e1388;
  puVar7[0x1a] = FLOAT_803e1370;
  puVar7[0x1b] = FLOAT_803e1370;
  *(undefined *)((int)puVar7 + 0x8e) = 1;
  *(undefined2 *)(puVar7 + 0x23) = 3;
  puVar7[0x22] = &DAT_803db964;
  puVar7[0x1e] = 2;
  puVar7[0x1f] = FLOAT_803e138c;
  puVar7[0x20] = FLOAT_803e1390;
  puVar7[0x21] = FLOAT_803e1390;
  *(undefined *)((int)puVar7 + 0xa6) = 1;
  *(undefined2 *)(puVar7 + 0x29) = 0;
  puVar7[0x28] = 0;
  puVar7[0x24] = 0x80;
  uStack148 = FUN_800221a0(0xffff8300,32000);
  uStack148 = uStack148 ^ 0x80000000;
  local_98 = 0x43300000;
  puVar7[0x25] = (float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e1398);
  uStack140 = FUN_800221a0(0xffffffff,1);
  uStack140 = uStack140 ^ 0x80000000;
  local_90 = 0x43300000;
  puVar7[0x26] = (float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,uStack140) -
                                                DOUBLE_803e1398));
  uStack132 = FUN_800221a0(0xffffffff,1);
  uStack132 = uStack132 ^ 0x80000000;
  local_88 = 0x43300000;
  puVar7[0x27] = (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack132) -
                                                 DOUBLE_803e1398));
  *(undefined *)((int)puVar7 + 0xbe) = 2;
  *(undefined2 *)(puVar7 + 0x2f) = 0;
  puVar7[0x2e] = 0;
  puVar7[0x2a] = 0x80;
  uStack124 = FUN_800221a0(0xffff8300,32000);
  uStack124 = uStack124 ^ 0x80000000;
  local_80 = 0x43300000;
  puVar7[0x2b] = (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e1398);
  uStack116 = FUN_800221a0(0xffffffff,1);
  uStack116 = uStack116 ^ 0x80000000;
  local_78 = 0x43300000;
  puVar7[0x2c] = (float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,uStack116) -
                                                DOUBLE_803e1398));
  uStack108 = FUN_800221a0(0xffffffff,1);
  uStack108 = uStack108 ^ 0x80000000;
  local_70 = 0x43300000;
  puVar7[0x2d] = (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack108) -
                                                 DOUBLE_803e1398));
  *(undefined *)((int)puVar7 + 0xd6) = 2;
  *(undefined2 *)(puVar7 + 0x35) = 0;
  puVar7[0x34] = &DAT_803db960;
  puVar7[0x30] = 0x4000;
  puVar7[0x31] = FLOAT_803e1388;
  puVar7[0x32] = FLOAT_803e1370;
  puVar7[0x33] = FLOAT_803e1370;
  *(undefined *)((int)puVar7 + 0xee) = 3;
  *(undefined2 *)(puVar7 + 0x3b) = 0;
  puVar7[0x3a] = 0;
  puVar7[0x36] = 0x80;
  uStack100 = FUN_800221a0(0xffff8300,32000);
  uStack100 = uStack100 ^ 0x80000000;
  local_68 = 0x43300000;
  puVar7[0x37] = (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e1398);
  uStack92 = FUN_800221a0(0xffffffff,1);
  uStack92 = uStack92 ^ 0x80000000;
  local_60 = 0x43300000;
  puVar7[0x38] = (float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,uStack92) -
                                                DOUBLE_803e1398));
  uStack84 = FUN_800221a0(0xffffffff,1);
  uStack84 = uStack84 ^ 0x80000000;
  local_58 = 0x43300000;
  puVar7[0x39] = (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack84) -
                                                 DOUBLE_803e1398));
  *(undefined *)((int)puVar7 + 0x106) = 3;
  *(undefined2 *)(puVar7 + 0x41) = 0;
  puVar7[0x40] = &DAT_803db960;
  puVar7[0x3c] = 0x4000;
  puVar7[0x3d] = FLOAT_803e1388;
  puVar7[0x3e] = FLOAT_803e1370;
  puVar7[0x3f] = FLOAT_803e1370;
  *(undefined *)((int)puVar7 + 0x11e) = 4;
  *(undefined2 *)(puVar7 + 0x47) = 0;
  puVar7[0x46] = 0;
  puVar7[0x42] = 0x80;
  uStack76 = FUN_800221a0(0xffff8300,32000);
  uStack76 = uStack76 ^ 0x80000000;
  local_50 = 0x43300000;
  puVar7[0x43] = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e1398);
  uStack68 = FUN_800221a0(0xffffffff,1);
  uStack68 = uStack68 ^ 0x80000000;
  local_48 = 0x43300000;
  puVar7[0x44] = (float)(dVar9 * (double)(float)((double)CONCAT44(0x43300000,uStack68) -
                                                DOUBLE_803e1398));
  uStack60 = FUN_800221a0(0xffffffff,1);
  uStack60 = uStack60 ^ 0x80000000;
  local_40 = 0x43300000;
  puVar7[0x45] = (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uStack60) -
                                                 DOUBLE_803e1398));
  *(undefined *)((int)puVar7 + 0x136) = 4;
  *(undefined2 *)(puVar7 + 0x4d) = 0;
  puVar7[0x4c] = &DAT_803db960;
  puVar7[0x48] = 0x4000;
  puVar7[0x49] = FLOAT_803e1388;
  puVar7[0x4a] = FLOAT_803e1370;
  puVar7[0x4b] = FLOAT_803e1370;
  *(undefined *)((int)puVar7 + 0x14e) = 4;
  *(undefined2 *)(puVar7 + 0x53) = 1;
  puVar7[0x52] = &DAT_803db960;
  puVar7[0x4e] = 4;
  puVar7[0x4f] = FLOAT_803e1370;
  puVar7[0x50] = FLOAT_803e1370;
  puVar7[0x51] = FLOAT_803e1370;
  local_3c0 = 0;
  local_3d4 = (undefined2)uVar11;
  local_3ec = FLOAT_803e1370;
  if (iVar5 == 0) {
    local_3e8 = FLOAT_803e1370;
  }
  else if (iVar5 == 1) {
    local_3e8 = FLOAT_803e1394;
  }
  local_3e4 = FLOAT_803e1370;
  local_3f8 = FLOAT_803e1370;
  local_3f4 = FLOAT_803e1370;
  local_3f0 = FLOAT_803e1370;
  local_3e0 = FLOAT_803e1390;
  local_3d8 = 1;
  local_3dc = 0;
  local_3bf = 3;
  local_3be = 0;
  local_3bd = 0;
  iVar5 = (int)puVar7 + (0x150 - (int)&local_3b8);
  iVar5 = iVar5 / 0x18 + (iVar5 >> 0x1f);
  local_3bb = (char)iVar5 - (char)(iVar5 >> 0x1f);
  local_418 = &local_3b8;
  local_3c4 = param_4 | 0x4000400;
  if ((param_4 & 1) != 0) {
    if ((local_414 == 0) || (param_3 == 0)) {
      if (local_414 == 0) {
        if (param_3 != 0) {
          local_3ec = FLOAT_803e1370 + *(float *)(param_3 + 0xc);
          local_3e8 = local_3e8 + *(float *)(param_3 + 0x10);
          local_3e4 = FLOAT_803e1370 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_3ec = FLOAT_803e1370 + *(float *)(local_414 + 0x18);
        local_3e8 = local_3e8 + *(float *)(local_414 + 0x1c);
        local_3e4 = FLOAT_803e1370 + *(float *)(local_414 + 0x20);
      }
    }
    else {
      local_3ec = FLOAT_803e1370 + *(float *)(local_414 + 0x18) + *(float *)(param_3 + 0xc);
      local_3e8 = local_3e8 + *(float *)(local_414 + 0x1c) + *(float *)(param_3 + 0x10);
      local_3e4 = FLOAT_803e1370 + *(float *)(local_414 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  (**(code **)(*DAT_803dca7c + 8))(&local_418,0,3,&DAT_80317b98,1,&DAT_803db958,0x31,0);
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  FUN_80286124();
  return;
}

