// Function: FUN_800c1458
// Entry: 800c1458
// Size: 5660 bytes

undefined4
FUN_800c1458(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5)

{
  undefined4 uVar1;
  uint uVar2;
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
  undefined2 local_78;
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
  undefined8 local_20;
  
  FLOAT_803dc480 = FLOAT_803dc480 + FLOAT_803e0aa8;
  if (FLOAT_803e0ab0 < FLOAT_803dc480) {
    FLOAT_803dc480 = FLOAT_803e0aac;
  }
  FLOAT_803dc484 = FLOAT_803dc484 + FLOAT_803e0ab4;
  if (FLOAT_803e0ab0 < FLOAT_803dc484) {
    FLOAT_803dc484 = FLOAT_803e0ab8;
  }
  if (param_1 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        return 0xffffffff;
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
    local_5a = (undefined)param_2;
    local_88 = FLOAT_803e0abc;
    local_84 = FLOAT_803e0abc;
    local_80 = FLOAT_803e0abc;
    local_94 = FLOAT_803e0abc;
    local_90 = FLOAT_803e0abc;
    local_8c = FLOAT_803e0abc;
    local_7c = FLOAT_803e0abc;
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
    local_78 = 0;
    local_b8[0] = param_1;
    switch(param_2) {
    case 0x3b5:
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0b28);
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0b28);
      uStack_3c = FUN_80022264(0x1e,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0ac8 + (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0b28);
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0acc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0b28);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0acc * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0ad0 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      uVar2 = FUN_80022264(0x14,0x50);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_7c = FLOAT_803e0ad4 * (float)(local_20 - DOUBLE_803e0b28);
      local_b8[2] = FUN_80022264(0,0x118);
      local_b8[2] = local_b8[2] + 0xb4;
      local_58 = 0xfe;
      local_74 = 0x81008000;
      local_b8[1] = 0x284;
      local_76 = 0x208;
      break;
    case 0x3b6:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
        param_3 = &DAT_8039cff8;
      }
      if (param_3 == (undefined2 *)0x0) {
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_80 = *(float *)(param_3 + 10);
      }
      uStack_4c = FUN_80022264(0xf,0x23);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = FLOAT_803e0ac0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0b28);
      uStack_44 = FUN_80022264(6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_7c = FLOAT_803e0ac4 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0b28);
      local_b8[2] = 0x3c;
      local_58 = 0xff;
      local_74 = 0x80180100;
      local_76 = 0x5f;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0x63bf;
      local_6c = 0xffff;
      local_68 = 0xffff;
      local_64 = 0xb1df;
      local_70 = 0x20;
      break;
    default:
      return 0xffffffff;
    case 0x3ba:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
        param_3 = &DAT_8039cff8;
      }
      local_88 = *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      local_80 = *(float *)(param_3 + 10);
      uVar2 = FUN_80022264(1,4);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = FLOAT_803e0adc * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e0ae4 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28)
                 + FLOAT_803e0ae0;
      local_b8[2] = 0xa0;
      local_57 = 0;
      local_74 = 0x100201;
      local_76 = 99;
      break;
    case 0x3bb:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
        param_3 = &DAT_8039cff8;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_88 = *(float *)(param_3 + 6);
        local_84 = *(float *)(param_3 + 8);
        local_80 = *(float *)(param_3 + 10);
      }
      local_7c = FLOAT_803e0ad8;
      local_b8[2] = 0x96;
      local_58 = 0xff;
      local_74 = 0x8000201;
      local_76 = 0x62;
      break;
    case 0x3bc:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
      }
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803e0ae8 * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(10,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0ae8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      uStack_2c = FUN_80022264(0,300);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0aa8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0b28);
      uStack_34 = FUN_80022264(0xffffff38,200);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0b28);
      uStack_3c = FUN_80022264(0xffffff38,200);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0b28);
      uStack_44 = FUN_80022264(4,8);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_7c = FLOAT_803e0ad8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0b28);
      local_b8[2] = 0x46;
      local_58 = 100;
      local_57 = 0;
      local_74 = 0x180108;
      local_76 = 0x2b;
      break;
    case 0x3bd:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
        param_3 = &DAT_8039cff8;
      }
      uVar2 = FUN_80022264(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803e0af4 * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0x14,0x1e);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0af8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0af4 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0b28);
      uStack_34 = FUN_80022264(0xffffff6a,0x96);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0b28);
      local_84 = FLOAT_803e0b20;
      local_80 = FLOAT_803e0abc;
      if (param_3 != (undefined2 *)0x0) {
        local_80 = *(float *)(param_3 + 10);
        local_84 = *(float *)(param_3 + 8);
      }
      uStack_3c = FUN_80022264(0xffffffce,0xfffffff6);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0b28)
                 + local_80;
      local_7c = FLOAT_803e0b24;
      local_b8[2] = 0x1e;
      local_74 = 0x108000e;
      local_76 = 0x60;
      local_58 = 0xbe;
      break;
    case 0x3be:
      uVar2 = FUN_80022264(1,4);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = FLOAT_803e0b1c * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0,0x3c);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e0ae4 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28)
                 + FLOAT_803e0b1c;
      local_b8[2] = 0xa0;
      local_57 = 0;
      local_74 = 0x80100201;
      local_76 = 99;
      break;
    case 0x3c0:
    case 0x3c1:
      if (param_3 == (undefined2 *)0x0) {
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_80 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_80022264(0xffffffd8,0x28);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_8c = FLOAT_803e0b04 * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0xffffffd8,0x28);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_94 = FLOAT_803e0b04 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      uStack_2c = FUN_80022264(0,0x28);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803e0ae8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0b28);
      local_58 = 0xff;
      local_7c = FLOAT_803e0b08;
      local_b8[2] = 0x8c;
      local_74 = 0x81000000;
      local_70 = 0x200000;
      local_76 = 0x26d;
      uVar2 = FUN_80022264(0,3);
      if (uVar2 == 3) {
        uVar2 = FUN_80022264(1,4);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_7c = FLOAT_803e0b0c * (float)(local_20 - DOUBLE_803e0b28);
        local_74 = local_74 | 0x100100;
        local_76 = 0x2b;
        local_58 = 0x9b;
        param_2 = 0x3c1;
      }
      break;
    case 0x3c2:
      if (param_3 == (undefined2 *)0x0) {
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_80 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_80022264(6,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_7c = FLOAT_803e0ac4 * (float)(local_20 - DOUBLE_803e0b28);
      local_b8[2] = 0x3c;
      local_58 = 0xff;
      local_74 = 0x80180108;
      local_76 = 0x5f;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0x63bf;
      local_6c = 0xffff;
      local_68 = 0xffff;
      local_64 = 0xb1df;
      local_70 = 0x20;
      break;
    case 0x3c3:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
        param_3 = &DAT_8039cff8;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_94 = *(float *)(param_3 + 6);
        local_90 = *(float *)(param_3 + 8);
        local_8c = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_80022264(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_84 = FLOAT_803e0aac * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_80 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0b28);
      local_7c = FLOAT_803e0af4;
      local_b8[2] = 0x3c;
      local_74 = 0x1080006;
      local_76 = 0x60;
      local_58 = 0xa0;
      break;
    case 0x3c4:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
        param_3 = &DAT_8039cff8;
      }
      local_b8[2] = (int)(FLOAT_803e0ac8 * *(float *)(param_3 + 4) + FLOAT_803e0b10);
      local_20 = (double)(longlong)local_b8[2];
      uStack_24 = local_b8[2] ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e0b14 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      local_74 = 0xe100200;
      local_76 = 0x57;
      local_88 = *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      local_80 = *(float *)(param_3 + 10);
      local_a0 = FLOAT_803e0abc;
      local_9c = FLOAT_803e0abc;
      local_98 = FLOAT_803e0abc;
      local_ac = *param_3;
      local_aa = 0;
      local_a8 = 0;
      break;
    case 0x3c5:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
        param_3 = &DAT_8039cff8;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_88 = *(float *)(param_3 + 6);
        local_84 = *(float *)(param_3 + 8);
        local_80 = *(float *)(param_3 + 10);
      }
      local_7c = FLOAT_803e0af8;
      local_b8[2] = 100;
      local_58 = 0xff;
      local_74 = 0x8100201;
      local_76 = 0x60;
      break;
    case 0x3c6:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
        param_3 = &DAT_8039cff8;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_80022264(0xfffffff6,10);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_94 = FLOAT_803e0aa8 * (float)(local_20 - DOUBLE_803e0b28);
        uStack_24 = FUN_80022264(5,100);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_28 = 0x43300000;
        local_90 = FLOAT_803e0af4 *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
        uStack_2c = FUN_80022264(0xfffffff6,10);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_8c = FLOAT_803e0aa8 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0b28);
      }
      else {
        local_94 = *(float *)(param_3 + 6);
        local_90 = *(float *)(param_3 + 8);
        local_8c = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_80022264(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_84 = FLOAT_803e0aac * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0xfffffda8,600);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0abc;
      local_7c = FLOAT_803e0af8;
      local_b8[2] = 0x28;
      local_74 = 0x1080006;
      local_76 = 0x60;
      local_58 = 0xa0;
      break;
    case 0x3c7:
      local_7c = FLOAT_803e0b00;
      if (param_3 != (undefined2 *)0x0) {
        local_84 = *(float *)(param_3 + 8);
        local_7c = FLOAT_803e0afc * *(float *)(param_3 + 4);
      }
      local_b8[2] = 0xf;
      local_58 = 0x7f;
      local_74 = 0x80210;
      local_76 = 0x4f9;
      local_57 = 0x20;
      local_60 = 0xff00;
      local_5e = 0xff00;
      local_5c = 0xff00;
      local_6c = 0xff00;
      local_68 = 0xff00;
      local_64 = 0xff00;
      local_70 = 0x2000020;
      break;
    case 0x3c9:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d004 = FLOAT_803e0abc;
        DAT_8039d008 = FLOAT_803e0abc;
        DAT_8039d00c = FLOAT_803e0abc;
        DAT_8039d000 = FLOAT_803e0ab0;
        DAT_8039cff8 = 0;
        DAT_8039cffa = 0;
        DAT_8039cffc = 0;
        param_3 = &DAT_8039cff8;
      }
      uVar2 = FUN_80022264(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803e0afc * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0x14,0x1e);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0b18 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0afc * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0b28);
      local_80 = FLOAT_803e0abc;
      local_88 = FLOAT_803e0abc;
      local_84 = FLOAT_803e0abc;
      if (param_3 != (undefined2 *)0x0) {
        local_88 = *(float *)(param_3 + 6);
        local_84 = *(float *)(param_3 + 8);
        local_80 = *(float *)(param_3 + 10);
      }
      uStack_34 = FUN_80022264(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0b28)
                 + local_84;
      uStack_3c = FUN_80022264(0xffffffce,0x32);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0b28)
                 + local_88;
      uStack_44 = FUN_80022264(0xffffffce,0x32);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = FLOAT_803e0aac * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0b28)
                 + local_80;
      local_7c = FLOAT_803e0af8;
      local_b8[2] = 0x14;
      local_74 = 0x1080006;
      local_76 = 0x60;
      local_58 = 0xa0;
      break;
    case 0x3ca:
      uVar2 = FUN_80022264(0xffffffce,0x32);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803e0af8 * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0x1e,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0af8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      uStack_2c = FUN_80022264(0xffffffce,0x32);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0af8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0b28);
      uStack_34 = FUN_80022264(0,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_7c = FLOAT_803e0ae4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0b28)
                 + FLOAT_803e0af4;
      local_b8[2] = FUN_80022264(0x32,0x46);
      local_58 = 0x7f;
      local_74 = 0x1180100;
      local_76 = 0x2b;
      break;
    case 0x3cb:
      local_7c = FLOAT_803e0af4;
      local_b8[2] = FUN_80022264(0x32,100);
      local_58 = 0x7f;
      local_74 = 0x1180100;
      local_76 = 0x2b;
      break;
    case 0x3cc:
      uVar2 = FUN_80022264(0xffffffce,0x32);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803e0ae8 * (float)(local_20 - DOUBLE_803e0b28);
      uStack_24 = FUN_80022264(0x1e,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0ae8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0b28);
      uStack_2c = FUN_80022264(0xffffffce,0x32);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0ae8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0b28);
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0aec * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0b28);
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0aec * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0b28);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = FLOAT_803e0aec * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0b28);
      local_b8[2] = FUN_80022264(0,0x14);
      local_b8[2] = local_b8[2] + 0x1e;
      local_57 = 0;
      local_58 = 0xa5;
      local_74 = 0x180108;
      uStack_4c = FUN_80022264(0x28,0x50);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_7c = FLOAT_803e0af0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0b28);
      local_76 = 0x167;
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
    uVar1 = (**(code **)(*DAT_803dd6f8 + 8))(local_b8,0xffffffff,param_2,0);
  }
  return uVar1;
}

