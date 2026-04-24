// Function: FUN_800c9140
// Entry: 800c9140
// Size: 4732 bytes

void FUN_800c9140(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined8 uVar4;
  int local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined2 local_ac;
  undefined2 local_aa;
  undefined2 local_a8;
  undefined4 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  undefined2 local_76;
  uint local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined2 local_60;
  undefined2 local_5e;
  undefined2 local_5c;
  undefined local_5a;
  undefined local_58;
  undefined local_57;
  undefined local_56;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  uVar4 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = (int)uVar4;
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
    goto LAB_800ca3a4;
  }
  if ((param_4 & 0x200000) != 0) {
    if (param_3 == (undefined2 *)0x0) {
      uVar2 = 0xffffffff;
      goto LAB_800ca3a4;
    }
    local_a0 = *(float *)(param_3 + 6);
    local_9c = *(float *)(param_3 + 8);
    local_98 = *(float *)(param_3 + 10);
    local_a4 = *(undefined4 *)(param_3 + 4);
    local_a8 = param_3[2];
    local_aa = param_3[1];
    local_ac = *param_3;
    local_56 = param_5;
  }
  local_74 = 0;
  local_70 = 0;
  local_5a = (undefined)uVar4;
  local_88 = FLOAT_803e0110;
  local_84 = FLOAT_803e0110;
  local_80 = FLOAT_803e0110;
  local_94 = FLOAT_803e0110;
  local_90 = FLOAT_803e0110;
  local_8c = FLOAT_803e0110;
  local_7c = FLOAT_803e0110;
  local_b0 = 0;
  local_b4 = 0xffffffff;
  local_58 = 0xff;
  local_57 = 0;
  local_76 = 0;
  local_60 = 0xffff;
  local_5e = 0xffff;
  local_5c = 0xffff;
  local_6c = 0xffff;
  local_68 = 0xffff;
  local_64 = 0xffff;
  local_b8 = iVar1;
  switch(iVar3) {
  case 1000:
    uStack76 = FUN_800221a0(0x5a,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_7c = FLOAT_803e0114 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0178);
    uStack68 = FUN_800221a0(0xffffffce,0x32);
    uStack68 = uStack68 ^ 0x80000000;
    local_48 = 0x43300000;
    local_94 = FLOAT_803e0118 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e0178);
    local_90 = FLOAT_803e0110;
    uStack60 = FUN_800221a0(0xffffffce,0x32);
    uStack60 = uStack60 ^ 0x80000000;
    local_40 = 0x43300000;
    local_8c = FLOAT_803e0118 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0178);
    local_b0 = 0x28;
    local_74 = local_74 | 0x80218;
    local_70 = 0x20;
    iVar1 = FUN_800221a0(0,2);
    if (iVar1 == 1) {
      local_76 = 0x157;
    }
    else if (iVar1 < 1) {
      if (iVar1 < 0) {
LAB_800c9380:
        local_76 = 0x156;
      }
      else {
        local_76 = 0x156;
      }
    }
    else {
      if (2 < iVar1) goto LAB_800c9380;
      local_76 = 0xc0e;
    }
    local_60 = 0xffff;
    local_5e = 55000;
    local_5c = 0xffff;
    local_6c = 0xffff;
    local_68 = 30000;
    local_64 = 0xffff;
    local_58 = 0xff;
    break;
  case 0x3e9:
    if (param_3 == (undefined2 *)0x0) {
      DAT_8039c434 = FLOAT_803e0110;
      DAT_8039c438 = FLOAT_803e0110;
      DAT_8039c43c = FLOAT_803e0110;
      DAT_8039c430 = FLOAT_803e011c;
      DAT_8039c428 = 0;
      DAT_8039c42a = 0;
      DAT_8039c42c = 0;
      param_3 = &DAT_8039c428;
    }
    local_88 = *(float *)(param_3 + 6);
    local_84 = *(float *)(param_3 + 8);
    local_80 = *(float *)(param_3 + 10);
    local_7c = FLOAT_803e0120;
    local_74 = 0x180110;
    local_70 = 0x20;
    local_b0 = 0x12;
    local_58 = 0xff;
    local_76 = 0x159;
    local_60 = 0xffff;
    local_5e = 0xffff;
    local_5c = 0xffff;
    local_6c = 0xffff;
    local_68 = 50000;
    local_64 = 0xffff;
    break;
  case 0x3ea:
    if (param_3 == (undefined2 *)0x0) {
      DAT_8039c434 = FLOAT_803e0110;
      DAT_8039c438 = FLOAT_803e0110;
      DAT_8039c43c = FLOAT_803e0110;
      DAT_8039c430 = FLOAT_803e011c;
      DAT_8039c428 = 0;
      DAT_8039c42a = 0;
      DAT_8039c42c = 0;
      param_3 = &DAT_8039c428;
    }
    uStack60 = FUN_800221a0(0xffffff9c,100);
    uStack60 = uStack60 ^ 0x80000000;
    local_40 = 0x43300000;
    local_88 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0178) / FLOAT_803e0124;
    iVar1 = FUN_800221a0(100,0x96);
    uStack68 = -iVar1 ^ 0x80000000;
    local_48 = 0x43300000;
    local_84 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e0178) / FLOAT_803e0128;
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_80 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0178) / FLOAT_803e0124;
    local_74 = local_74 | 0x80208;
    local_70 = 0x10000;
    uStack52 = FUN_800221a0(0xffffff9c,100);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    local_94 = FLOAT_803e012c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0178);
    uStack44 = FUN_800221a0(0xffffff9c,100);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_8c = FLOAT_803e012c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0178);
    local_58 = 0xff;
    local_b0 = 0x3c;
    local_76 = 0x7b;
    uStack36 = FUN_800221a0(0x32,100);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    local_7c = *(float *)(param_3 + 4) *
               FLOAT_803e0130 *
               FLOAT_803e0134 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0178) +
               FLOAT_803e012c;
    break;
  case 0x3eb:
    uStack36 = FUN_800221a0(0xffffffe2,0x1e);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    local_94 = FLOAT_803e0138 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0178);
    uStack44 = FUN_800221a0(0xfffffffb,5);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_90 = FLOAT_803e013c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0178);
    uStack52 = FUN_800221a0(0xffffffe2,0x1e);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    local_8c = FLOAT_803e0138 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0178);
    local_88 = FLOAT_803e0110;
    uStack60 = FUN_800221a0(0xfffffffa,2);
    uStack60 = uStack60 ^ 0x80000000;
    local_40 = 0x43300000;
    local_84 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0178);
    local_80 = FLOAT_803e0110;
    local_7c = FLOAT_803e013c;
    local_b0 = 0x32;
    local_74 = 0x80080208;
    local_76 = 0x60;
    local_60 = 0x7f00;
    local_5e = 0x6400;
    local_5c = 0;
    local_6c = 0x5a00;
    local_68 = 0;
    local_64 = 0;
    local_70 = 0x20;
    local_58 = 0x7f;
    break;
  case 0x3ec:
    uVar2 = 0xffffffff;
    goto LAB_800ca3a4;
  case 0x3ed:
    uStack36 = FUN_800221a0(0xffffffce,0x32);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    local_94 = FLOAT_803e013c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0178);
    uStack44 = FUN_800221a0(0xffffffce,0x32);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_90 = FLOAT_803e0120 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0178);
    uStack52 = FUN_800221a0(0xffffffce,0x32);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    local_8c = FLOAT_803e013c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0178);
    uStack60 = FUN_800221a0(10,0x14);
    uStack60 = uStack60 ^ 0x80000000;
    local_40 = 0x43300000;
    local_7c = FLOAT_803e0140 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0178);
    local_b0 = 0x32;
    local_74 = 0x80210;
    local_70 = 0x8000800;
    local_76 = 0x79;
    break;
  case 0x3ee:
    uStack36 = FUN_800221a0(0xfffffff6,10);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    local_88 = local_88 +
               (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0178) / FLOAT_803e0144;
    uStack44 = FUN_800221a0(0xffffffe2,0);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_84 = local_84 +
               (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0178) / FLOAT_803e0148;
    uStack52 = FUN_800221a0(0xfffffff6,10);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    local_80 = local_80 +
               (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0178) / FLOAT_803e0144;
    uStack60 = FUN_800221a0(0xffffffec,0x14);
    uStack60 = uStack60 ^ 0x80000000;
    local_40 = 0x43300000;
    local_94 = FLOAT_803e012c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0178);
    iVar1 = FUN_800221a0(0x28,100);
    uStack68 = -iVar1 ^ 0x80000000;
    local_48 = 0x43300000;
    local_90 = FLOAT_803e014c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e0178);
    uStack76 = FUN_800221a0(0xffffffec,0x14);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_8c = FLOAT_803e012c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0178);
    uStack28 = FUN_800221a0(0xf,0x16);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    local_7c = FLOAT_803e012c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0178);
    local_b0 = 600;
    local_74 = 0x180100;
    local_76 = 0xc10;
    local_58 = FUN_800221a0(0x96,0xfa);
    break;
  case 0x3ef:
    uStack28 = FUN_800221a0(0xfffffb50,0x4b0);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    local_88 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0178) / FLOAT_803e0128;
    uStack36 = FUN_800221a0(0xfffffb50,0x4b0);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    local_80 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0178) / FLOAT_803e0128;
    uStack44 = FUN_800221a0(0x1e,0x46);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_90 = FLOAT_803e014c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0178);
    uStack52 = FUN_800221a0(0,0x14);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    local_7c = FLOAT_803e0154 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0178) +
               FLOAT_803e0150;
    local_b0 = 200;
    local_74 = 0x80100;
    local_76 = 0x33;
    local_58 = 0xb4;
    local_70 = 0x8100800;
    break;
  case 0x3f0:
    uStack28 = FUN_800221a0(0xfffffc18,1000);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    local_88 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0178) / FLOAT_803e0128;
    uStack36 = FUN_800221a0(0xfffffc18,1000);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    local_80 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0178) / FLOAT_803e0128;
    uStack44 = FUN_800221a0(0x1e,0x46);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_90 = FLOAT_803e0158 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0178);
    uStack52 = FUN_800221a0(0,0x14);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    local_7c = FLOAT_803e0154 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0178) +
               FLOAT_803e015c;
    local_b0 = 0xfa;
    local_74 = 0x80100;
    local_76 = 0x33;
    local_70 = 0x8000800;
    local_58 = 0xb4;
    break;
  case 0x3f1:
    local_74 = 0x80800;
    local_76 = 0x76;
    local_58 = 0xd2;
    local_7c = FLOAT_803e0160;
    local_b0 = 100;
    break;
  case 0x3f2:
    if (param_6 == (float *)0x0) {
      uVar2 = 0;
      goto LAB_800ca3a4;
    }
    if (param_3 == (undefined2 *)0x0) {
      DAT_8039c434 = FLOAT_803e0110;
      DAT_8039c438 = FLOAT_803e0110;
      DAT_8039c43c = FLOAT_803e0110;
      DAT_8039c430 = FLOAT_803e011c;
      DAT_8039c428 = 0;
      DAT_8039c42a = 0;
      DAT_8039c42c = 0;
      param_3 = &DAT_8039c428;
    }
    if (param_3 != (undefined2 *)0x0) {
      local_88 = *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      local_80 = *(float *)(param_3 + 10);
    }
    if (param_6 != (float *)0x0) {
      local_94 = *param_6;
      uStack28 = FUN_800221a0(0,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_90 = FLOAT_803e0164 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0178);
      local_8c = param_6[1];
    }
    uStack28 = FUN_800221a0(0,10);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    local_7c = FLOAT_803e0168 *
               (FLOAT_803e0170 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0178) +
               FLOAT_803e016c);
    local_b0 = FUN_800221a0(0xbe,0xfa);
    local_58 = 0xff;
    local_74 = 0x81088000;
    local_76 = 0x23c;
    break;
  case 0x3f3:
    uStack28 = FUN_800221a0(0xffffffce,0x32);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    local_88 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0178) / FLOAT_803e0128;
    uStack36 = FUN_800221a0(0xffffffce,0x32);
    uStack36 = uStack36 ^ 0x80000000;
    local_28 = 0x43300000;
    local_84 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0178) / FLOAT_803e0128;
    uStack44 = FUN_800221a0(0xffffffce,0x32);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_80 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0178) / FLOAT_803e0128;
    uStack52 = FUN_800221a0(0x1e,0x3c);
    uStack52 = uStack52 ^ 0x80000000;
    local_38 = 0x43300000;
    local_94 = FLOAT_803e0118 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e0178);
    iVar1 = FUN_800221a0(0,1);
    if (iVar1 != 0) {
      local_94 = -local_94;
    }
    uStack28 = FUN_800221a0(0x1e,0x3c);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    local_90 = FLOAT_803e0118 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0178);
    iVar1 = FUN_800221a0(0,1);
    if (iVar1 != 0) {
      local_90 = -local_90;
    }
    uStack28 = FUN_800221a0(0x1e,0x3c);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    local_8c = FLOAT_803e0118 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0178);
    iVar1 = FUN_800221a0(0,1);
    if (iVar1 != 0) {
      local_8c = -local_8c;
    }
    uStack28 = FUN_800221a0(0,10);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    local_7c = FLOAT_803e0154 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0178) +
               FLOAT_803e012c;
    local_b0 = 0x46;
    local_74 = 0x80208;
    local_76 = 0x76;
    local_58 = 0xb4;
    local_70 = 0x100000;
    break;
  case 0x3f4:
  case 0x3f5:
  case 0x3f6:
    if (param_3 != (undefined2 *)0x0) {
      local_88 = *(float *)(param_3 + 6) - *(float *)(iVar1 + 0x18);
      local_84 = *(float *)(param_3 + 8) - *(float *)(iVar1 + 0x1c);
      local_80 = *(float *)(param_3 + 10) - *(float *)(iVar1 + 0x20);
    }
    iVar1 = FUN_800221a0(0,0x28);
    if (iVar1 == 0) {
      local_7c = FLOAT_803e0130;
    }
    else {
      local_7c = FLOAT_803e015c;
    }
    local_b0 = 0x14;
    local_58 = 0xff;
    local_74 = 0x80210;
    iVar1 = iVar3 + -0x3f4;
    if (iVar1 == 1) {
      local_76 = 0x157;
    }
    else if (iVar1 < 1) {
      if (iVar1 < 0) {
LAB_800ca064:
        local_76 = 0x156;
      }
      else {
        local_76 = 0x156;
      }
    }
    else {
      if (2 < iVar1) goto LAB_800ca064;
      local_76 = 0xc0e;
    }
    break;
  case 0x3f7:
  case 0x3f8:
  case 0x3f9:
    if (param_3 != (undefined2 *)0x0) {
      local_88 = *(float *)(param_3 + 6) - *(float *)(iVar1 + 0x18);
      local_84 = *(float *)(param_3 + 8) - *(float *)(iVar1 + 0x1c);
      local_80 = *(float *)(param_3 + 10) - *(float *)(iVar1 + 0x20);
      local_8c = FLOAT_803e0174;
    }
    local_7c = FLOAT_803e015c;
    local_b0 = 100;
    local_58 = 0xff;
    local_74 = 0x480210;
    local_70 = 0x100000;
    iVar1 = iVar3 + -0x3f7;
    if (iVar1 == 1) {
      local_76 = 0x4fc;
    }
    else if (iVar1 < 1) {
      if (iVar1 < 0) {
LAB_800ca138:
        local_76 = 0x4fb;
      }
      else {
        local_76 = 0x4fb;
      }
    }
    else {
      if (2 < iVar1) goto LAB_800ca138;
      local_76 = 0x4fd;
    }
    break;
  case 0x3fa:
    if (param_3 != (undefined2 *)0x0) {
      local_88 = *(float *)(param_3 + 6) - *(float *)(iVar1 + 0x18);
      local_84 = *(float *)(param_3 + 8) - *(float *)(iVar1 + 0x1c);
      local_80 = *(float *)(param_3 + 10) - *(float *)(iVar1 + 0x20);
      local_8c = FLOAT_803e0134;
    }
    local_7c = FLOAT_803e015c;
    local_b0 = 100;
    local_58 = 0xff;
    local_74 = 0x480210;
    local_70 = 0x100000;
    local_76 = 0x4fb;
    break;
  case 0x3fb:
    if (param_3 != (undefined2 *)0x0) {
      local_88 = *(float *)(param_3 + 6) - *(float *)(iVar1 + 0x18);
      local_84 = *(float *)(param_3 + 8) - *(float *)(iVar1 + 0x1c);
      local_80 = *(float *)(param_3 + 10) - *(float *)(iVar1 + 0x20);
      local_7c = *(float *)(param_3 + 4);
    }
    local_b0 = 5;
    local_58 = 0xff;
    local_74 = 0x80800;
    local_70 = 0x1000000;
    local_76 = 0x5ea;
    break;
  case 0x3fc:
    if (param_3 != (undefined2 *)0x0) {
      local_88 = *(float *)(param_3 + 6) - *(float *)(iVar1 + 0x18);
      local_84 = *(float *)(param_3 + 8) - *(float *)(iVar1 + 0x1c);
      local_80 = *(float *)(param_3 + 10) - *(float *)(iVar1 + 0x20);
      local_7c = *(float *)(param_3 + 4);
    }
    local_b0 = 5;
    local_58 = 0xff;
    local_74 = 0x80800;
    local_70 = 0x1000000;
    local_76 = 0x5eb;
    break;
  default:
    uVar2 = 0xffffffff;
    goto LAB_800ca3a4;
  }
  local_74 = local_74 | param_4;
  if (((local_74 & 1) != 0) && ((local_74 & 2) != 0)) {
    local_74 = local_74 ^ 2;
  }
  if ((local_74 & 1) != 0) {
    if ((param_4 & 0x200000) == 0) {
      if (local_b8 != 0) {
        local_88 = local_88 + *(float *)(local_b8 + 0x18);
        local_84 = local_84 + *(float *)(local_b8 + 0x1c);
        local_80 = local_80 + *(float *)(local_b8 + 0x20);
      }
    }
    else {
      local_88 = local_88 + local_a0;
      local_84 = local_84 + local_9c;
      local_80 = local_80 + local_98;
    }
  }
  uVar2 = (**(code **)(*DAT_803dca78 + 8))(&local_b8,0xffffffff,iVar3,0);
LAB_800ca3a4:
  FUN_80286128(uVar2);
  return;
}

