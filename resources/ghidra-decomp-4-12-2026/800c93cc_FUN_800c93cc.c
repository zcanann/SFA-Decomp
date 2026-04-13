// Function: FUN_800c93cc
// Entry: 800c93cc
// Size: 4732 bytes

void FUN_800c93cc(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
  int local_b8 [3];
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
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar4 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = (int)uVar4;
  if (iVar1 == 0) goto LAB_800ca630;
  if ((param_4 & 0x200000) != 0) {
    if (param_3 == (undefined2 *)0x0) goto LAB_800ca630;
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
  local_88 = FLOAT_803e0d90;
  local_84 = FLOAT_803e0d90;
  local_80 = FLOAT_803e0d90;
  local_94 = FLOAT_803e0d90;
  local_90 = FLOAT_803e0d90;
  local_8c = FLOAT_803e0d90;
  local_7c = FLOAT_803e0d90;
  local_b8[2] = 0;
  local_b8[1] = 0xffffffff;
  local_58 = 0xff;
  local_57 = 0;
  local_76 = 0;
  local_60 = 0xffff;
  local_5e = 0xffff;
  local_5c = 0xffff;
  local_6c = 0xffff;
  local_68 = 0xffff;
  local_64 = 0xffff;
  local_b8[0] = iVar1;
  switch(iVar3) {
  case 1000:
    uStack_4c = FUN_80022264(0x5a,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_7c = FLOAT_803e0d94 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0df8);
    uStack_44 = FUN_80022264(0xffffffce,0x32);
    uStack_44 = uStack_44 ^ 0x80000000;
    local_48 = 0x43300000;
    local_94 = FLOAT_803e0d98 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0df8);
    local_90 = FLOAT_803e0d90;
    uStack_3c = FUN_80022264(0xffffffce,0x32);
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    local_8c = FLOAT_803e0d98 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0df8);
    local_b8[2] = 0x28;
    local_74 = local_74 | 0x80218;
    local_70 = 0x20;
    uVar2 = FUN_80022264(0,2);
    if (uVar2 == 1) {
      local_76 = 0x157;
    }
    else if ((int)uVar2 < 1) {
      if ((int)uVar2 < 0) {
LAB_800c960c:
        local_76 = 0x156;
      }
      else {
        local_76 = 0x156;
      }
    }
    else {
      if (2 < (int)uVar2) goto LAB_800c960c;
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
      DAT_8039d094 = FLOAT_803e0d90;
      DAT_8039d098 = FLOAT_803e0d90;
      DAT_8039d09c = FLOAT_803e0d90;
      DAT_8039d090 = FLOAT_803e0d9c;
      DAT_8039d088 = 0;
      DAT_8039d08a = 0;
      DAT_8039d08c = 0;
      param_3 = &DAT_8039d088;
    }
    local_88 = *(float *)(param_3 + 6);
    local_84 = *(float *)(param_3 + 8);
    local_80 = *(float *)(param_3 + 10);
    local_7c = FLOAT_803e0da0;
    local_74 = 0x180110;
    local_70 = 0x20;
    local_b8[2] = 0x12;
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
      DAT_8039d094 = FLOAT_803e0d90;
      DAT_8039d098 = FLOAT_803e0d90;
      DAT_8039d09c = FLOAT_803e0d90;
      DAT_8039d090 = FLOAT_803e0d9c;
      DAT_8039d088 = 0;
      DAT_8039d08a = 0;
      DAT_8039d08c = 0;
      param_3 = &DAT_8039d088;
    }
    uStack_3c = FUN_80022264(0xffffff9c,100);
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    local_88 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0df8) / FLOAT_803e0da4;
    uVar2 = FUN_80022264(100,0x96);
    uStack_44 = -uVar2 ^ 0x80000000;
    local_48 = 0x43300000;
    local_84 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0df8) / FLOAT_803e0da8;
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_80 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0df8) / FLOAT_803e0da4;
    local_74 = local_74 | 0x80208;
    local_70 = 0x10000;
    uStack_34 = FUN_80022264(0xffffff9c,100);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_94 = FLOAT_803e0dac * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0df8);
    uStack_2c = FUN_80022264(0xffffff9c,100);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_8c = FLOAT_803e0dac * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0df8);
    local_58 = 0xff;
    local_b8[2] = 0x3c;
    local_76 = 0x7b;
    uStack_24 = FUN_80022264(0x32,100);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_7c = *(float *)(param_3 + 4) *
               FLOAT_803e0db0 *
               FLOAT_803e0db4 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0df8) +
               FLOAT_803e0dac;
    break;
  case 0x3eb:
    uStack_24 = FUN_80022264(0xffffffe2,0x1e);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_94 = FLOAT_803e0db8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0df8);
    uStack_2c = FUN_80022264(0xfffffffb,5);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_90 = FLOAT_803e0dbc * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0df8);
    uStack_34 = FUN_80022264(0xffffffe2,0x1e);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_8c = FLOAT_803e0db8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0df8);
    local_88 = FLOAT_803e0d90;
    uStack_3c = FUN_80022264(0xfffffffa,2);
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    local_84 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0df8);
    local_80 = FLOAT_803e0d90;
    local_7c = FLOAT_803e0dbc;
    local_b8[2] = 0x32;
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
    goto LAB_800ca630;
  case 0x3ed:
    uStack_24 = FUN_80022264(0xffffffce,0x32);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_94 = FLOAT_803e0dbc * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0df8);
    uStack_2c = FUN_80022264(0xffffffce,0x32);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_90 = FLOAT_803e0da0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0df8);
    uStack_34 = FUN_80022264(0xffffffce,0x32);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_8c = FLOAT_803e0dbc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0df8);
    uStack_3c = FUN_80022264(10,0x14);
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    local_7c = FLOAT_803e0dc0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0df8);
    local_b8[2] = 0x32;
    local_74 = 0x80210;
    local_70 = 0x8000800;
    local_76 = 0x79;
    break;
  case 0x3ee:
    uStack_24 = FUN_80022264(0xfffffff6,10);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_88 = local_88 +
               (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0df8) / FLOAT_803e0dc4;
    uStack_2c = FUN_80022264(0xffffffe2,0);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_84 = local_84 +
               (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0df8) / FLOAT_803e0dc8;
    uStack_34 = FUN_80022264(0xfffffff6,10);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_80 = local_80 +
               (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0df8) / FLOAT_803e0dc4;
    uStack_3c = FUN_80022264(0xffffffec,0x14);
    uStack_3c = uStack_3c ^ 0x80000000;
    local_40 = 0x43300000;
    local_94 = FLOAT_803e0dac * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0df8);
    uVar2 = FUN_80022264(0x28,100);
    uStack_44 = -uVar2 ^ 0x80000000;
    local_48 = 0x43300000;
    local_90 = FLOAT_803e0dcc * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0df8);
    uStack_4c = FUN_80022264(0xffffffec,0x14);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_8c = FLOAT_803e0dac * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0df8);
    uStack_1c = FUN_80022264(0xf,0x16);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    local_7c = FLOAT_803e0dac * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0df8);
    local_b8[2] = 600;
    local_74 = 0x180100;
    local_76 = 0xc10;
    uVar2 = FUN_80022264(0x96,0xfa);
    local_58 = (undefined)uVar2;
    break;
  case 0x3ef:
    uStack_1c = FUN_80022264(0xfffffb50,0x4b0);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    local_88 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0df8) / FLOAT_803e0da8;
    uStack_24 = FUN_80022264(0xfffffb50,0x4b0);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_80 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0df8) / FLOAT_803e0da8;
    uStack_2c = FUN_80022264(0x1e,0x46);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_90 = FLOAT_803e0dcc * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0df8);
    uStack_34 = FUN_80022264(0,0x14);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_7c = FLOAT_803e0dd4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0df8) +
               FLOAT_803e0dd0;
    local_b8[2] = 200;
    local_74 = 0x80100;
    local_76 = 0x33;
    local_58 = 0xb4;
    local_70 = 0x8100800;
    break;
  case 0x3f0:
    uStack_1c = FUN_80022264(0xfffffc18,1000);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    local_88 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0df8) / FLOAT_803e0da8;
    uStack_24 = FUN_80022264(0xfffffc18,1000);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_80 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0df8) / FLOAT_803e0da8;
    uStack_2c = FUN_80022264(0x1e,0x46);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_90 = FLOAT_803e0dd8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0df8);
    uStack_34 = FUN_80022264(0,0x14);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_7c = FLOAT_803e0dd4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0df8) +
               FLOAT_803e0ddc;
    local_b8[2] = 0xfa;
    local_74 = 0x80100;
    local_76 = 0x33;
    local_70 = 0x8000800;
    local_58 = 0xb4;
    break;
  case 0x3f1:
    local_74 = 0x80800;
    local_76 = 0x76;
    local_58 = 0xd2;
    local_7c = FLOAT_803e0de0;
    local_b8[2] = 100;
    break;
  case 0x3f2:
    if (param_6 == (float *)0x0) goto LAB_800ca630;
    if (param_3 == (undefined2 *)0x0) {
      DAT_8039d094 = FLOAT_803e0d90;
      DAT_8039d098 = FLOAT_803e0d90;
      DAT_8039d09c = FLOAT_803e0d90;
      DAT_8039d090 = FLOAT_803e0d9c;
      DAT_8039d088 = 0;
      DAT_8039d08a = 0;
      DAT_8039d08c = 0;
      param_3 = &DAT_8039d088;
    }
    if (param_3 != (undefined2 *)0x0) {
      local_88 = *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      local_80 = *(float *)(param_3 + 10);
    }
    if (param_6 != (float *)0x0) {
      local_94 = *param_6;
      uStack_1c = FUN_80022264(0,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_90 = FLOAT_803e0de4 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0df8);
      local_8c = param_6[1];
    }
    uStack_1c = FUN_80022264(0,10);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    local_7c = FLOAT_803e0de8 *
               (FLOAT_803e0df0 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0df8) +
               FLOAT_803e0dec);
    local_b8[2] = FUN_80022264(0xbe,0xfa);
    local_58 = 0xff;
    local_74 = 0x81088000;
    local_76 = 0x23c;
    break;
  case 0x3f3:
    uStack_1c = FUN_80022264(0xffffffce,0x32);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    local_88 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0df8) / FLOAT_803e0da8;
    uStack_24 = FUN_80022264(0xffffffce,0x32);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_84 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0df8) / FLOAT_803e0da8;
    uStack_2c = FUN_80022264(0xffffffce,0x32);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_80 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0df8) / FLOAT_803e0da8;
    uStack_34 = FUN_80022264(0x1e,0x3c);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_94 = FLOAT_803e0d98 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0df8);
    uVar2 = FUN_80022264(0,1);
    if (uVar2 != 0) {
      local_94 = -local_94;
    }
    uStack_1c = FUN_80022264(0x1e,0x3c);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    local_90 = FLOAT_803e0d98 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0df8);
    uVar2 = FUN_80022264(0,1);
    if (uVar2 != 0) {
      local_90 = -local_90;
    }
    uStack_1c = FUN_80022264(0x1e,0x3c);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    local_8c = FLOAT_803e0d98 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0df8);
    uVar2 = FUN_80022264(0,1);
    if (uVar2 != 0) {
      local_8c = -local_8c;
    }
    uStack_1c = FUN_80022264(0,10);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    local_7c = FLOAT_803e0dd4 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0df8) +
               FLOAT_803e0dac;
    local_b8[2] = 0x46;
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
    uVar2 = FUN_80022264(0,0x28);
    if (uVar2 == 0) {
      local_7c = FLOAT_803e0db0;
    }
    else {
      local_7c = FLOAT_803e0ddc;
    }
    local_b8[2] = 0x14;
    local_58 = 0xff;
    local_74 = 0x80210;
    iVar1 = iVar3 + -0x3f4;
    if (iVar1 == 1) {
      local_76 = 0x157;
    }
    else if (iVar1 < 1) {
      if (iVar1 < 0) {
LAB_800ca2f0:
        local_76 = 0x156;
      }
      else {
        local_76 = 0x156;
      }
    }
    else {
      if (2 < iVar1) goto LAB_800ca2f0;
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
      local_8c = FLOAT_803e0df4;
    }
    local_7c = FLOAT_803e0ddc;
    local_b8[2] = 100;
    local_58 = 0xff;
    local_74 = 0x480210;
    local_70 = 0x100000;
    iVar1 = iVar3 + -0x3f7;
    if (iVar1 == 1) {
      local_76 = 0x4fc;
    }
    else if (iVar1 < 1) {
      if (iVar1 < 0) {
LAB_800ca3c4:
        local_76 = 0x4fb;
      }
      else {
        local_76 = 0x4fb;
      }
    }
    else {
      if (2 < iVar1) goto LAB_800ca3c4;
      local_76 = 0x4fd;
    }
    break;
  case 0x3fa:
    if (param_3 != (undefined2 *)0x0) {
      local_88 = *(float *)(param_3 + 6) - *(float *)(iVar1 + 0x18);
      local_84 = *(float *)(param_3 + 8) - *(float *)(iVar1 + 0x1c);
      local_80 = *(float *)(param_3 + 10) - *(float *)(iVar1 + 0x20);
      local_8c = FLOAT_803e0db4;
    }
    local_7c = FLOAT_803e0ddc;
    local_b8[2] = 100;
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
    local_b8[2] = 5;
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
    local_b8[2] = 5;
    local_58 = 0xff;
    local_74 = 0x80800;
    local_70 = 0x1000000;
    local_76 = 0x5eb;
    break;
  default:
    goto LAB_800ca630;
  }
  local_74 = local_74 | param_4;
  if (((local_74 & 1) != 0) && ((local_74 & 2) != 0)) {
    local_74 = local_74 ^ 2;
  }
  if ((local_74 & 1) != 0) {
    if ((param_4 & 0x200000) == 0) {
      if (local_b8[0] != 0) {
        local_88 = local_88 + *(float *)(local_b8[0] + 0x18);
        local_84 = local_84 + *(float *)(local_b8[0] + 0x1c);
        local_80 = local_80 + *(float *)(local_b8[0] + 0x20);
      }
    }
    else {
      local_88 = local_88 + local_a0;
      local_84 = local_84 + local_9c;
      local_80 = local_80 + local_98;
    }
  }
  (**(code **)(*DAT_803dd6f8 + 8))(local_b8,0xffffffff,iVar3,0);
LAB_800ca630:
  FUN_8028688c();
  return;
}

