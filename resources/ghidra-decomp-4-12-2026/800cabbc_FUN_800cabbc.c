// Function: FUN_800cabbc
// Entry: 800cabbc
// Size: 3116 bytes

undefined4
FUN_800cabbc(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            int param_6)

{
  undefined4 uVar1;
  uint uVar2;
  int local_98 [3];
  undefined2 local_8c;
  undefined2 local_8a;
  undefined2 local_88;
  undefined4 local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  undefined2 local_58;
  undefined2 local_56;
  uint local_54;
  undefined4 local_50;
  undefined4 local_4c;
  uint local_48;
  uint local_44;
  undefined2 local_40;
  undefined2 local_3e;
  undefined2 local_3c;
  undefined local_3a;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  FLOAT_803dc4b0 = FLOAT_803dc4b0 + FLOAT_803e0e38;
  if (FLOAT_803e0e40 < FLOAT_803dc4b0) {
    FLOAT_803dc4b0 = FLOAT_803e0e3c;
  }
  FLOAT_803dc4b4 = FLOAT_803dc4b4 + FLOAT_803e0e44;
  if (FLOAT_803e0e40 < FLOAT_803dc4b4) {
    FLOAT_803dc4b4 = FLOAT_803e0e48;
  }
  if (param_1 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        return 0xffffffff;
      }
      local_80 = *(float *)(param_3 + 6);
      local_7c = *(float *)(param_3 + 8);
      local_78 = *(float *)(param_3 + 10);
      local_84 = *(undefined4 *)(param_3 + 4);
      local_88 = param_3[2];
      local_8a = param_3[1];
      local_8c = *param_3;
      local_36 = param_5;
    }
    local_54 = 0;
    local_50 = 0;
    local_3a = (undefined)param_2;
    local_68 = FLOAT_803e0e4c;
    local_64 = FLOAT_803e0e4c;
    local_60 = FLOAT_803e0e4c;
    local_74 = FLOAT_803e0e4c;
    local_70 = FLOAT_803e0e4c;
    local_6c = FLOAT_803e0e4c;
    local_5c = FLOAT_803e0e4c;
    local_98[2] = 0;
    local_98[1] = 0xffffffff;
    local_38 = 0xff;
    local_37 = 0;
    local_56 = 0;
    local_40 = 0xffff;
    local_3e = 0xffff;
    local_3c = 0xffff;
    local_4c = 0xffff;
    local_48 = 0xffff;
    local_44 = 0xffff;
    local_58 = 0;
    local_98[0] = param_1;
    switch(param_2) {
    case 0x73a:
      uStack_2c = FUN_80022264(8,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_70 = FLOAT_803e0e50 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
      uVar2 = FUN_80022264(0,0x28);
      if (uVar2 == 0) {
        uStack_2c = FUN_80022264(0x15,0x29);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_5c = FLOAT_803e0e38 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
        local_98[2] = 0x1cc;
      }
      else {
        uStack_2c = FUN_80022264(8,0x14);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_5c = FLOAT_803e0e38 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
        local_98[2] = FUN_80022264(0x5a,0x78);
      }
      local_54 = 0x80180200;
      local_50 = 0x1000020;
      local_56 = 0xc0b;
      local_38 = 0x7f;
      local_3c = 0x3fff;
      local_3e = 0x3fff;
      local_40 = 0x3fff;
      local_44 = 0xffff;
      local_48 = 0xffff;
      local_4c = 0xffff;
      local_64 = FLOAT_803e0e54;
      break;
    case 0x73b:
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e0e50 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
      uStack_24 = FUN_80022264(8,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e0e50 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e0e50 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      local_5c = FLOAT_803e0e58;
      local_98[2] = 0x32;
      local_54 = 0x3000200;
      local_50 = 0x200020;
      local_56 = 0x33;
      local_38 = 0xff;
      local_40 = 0xffff;
      local_3e = 0xffff;
      local_3c = 0xffff;
      local_4c = 0xffff;
      local_48 = FUN_80022264(0,0x8000);
      local_64 = FLOAT_803e0e5c;
      local_44 = local_48;
      break;
    default:
      return 0xffffffff;
    case 0x73d:
      uStack_1c = FUN_80022264(0xfffffff6,10);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_68 = FLOAT_803e0e3c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      uStack_24 = FUN_80022264(0xfffffff6,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_64 = FLOAT_803e0e50 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_60 = FLOAT_803e0e3c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
      uStack_14 = FUN_80022264(7,9);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0e60 *
                 FLOAT_803e0e64 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xde;
      break;
    case 0x73e:
      uStack_14 = FUN_80022264(0xfffffff6,10);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_68 = FLOAT_803e0e3c * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      uStack_1c = FUN_80022264(0xfffffff6,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_64 = FLOAT_803e0e50 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      uStack_24 = FUN_80022264(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_60 = FLOAT_803e0e3c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      uStack_2c = FUN_80022264(7,9);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e0e60 *
                 FLOAT_803e0e64 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xdf;
      break;
    case 0x73f:
      if (param_6 == 0) {
        uStack_14 = FUN_80022264(0xfffffff6,10);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = FLOAT_803e0e3c *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
        uStack_1c = FUN_80022264(0xfffffff6,100);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = FLOAT_803e0e50 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
        uStack_24 = FUN_80022264(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = FLOAT_803e0e3c *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      }
      else {
        uStack_14 = FUN_80022264(0xfffffff6,10);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = FLOAT_803e0e3c *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90) +
                   FLOAT_803e0e68;
        uStack_1c = FUN_80022264(0xfffffff6,100);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = FLOAT_803e0e50 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90) +
                   FLOAT_803e0e6c;
        uStack_24 = FUN_80022264(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = FLOAT_803e0e3c *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90) +
                   FLOAT_803e0e70;
      }
      local_28 = 0x43300000;
      uStack_14 = FUN_80022264(7,9);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0e74 *
                 FLOAT_803e0e64 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xde;
      break;
    case 0x740:
      if (param_6 == 0) {
        uStack_14 = FUN_80022264(0xfffffff6,10);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = FLOAT_803e0e3c *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
        uStack_1c = FUN_80022264(0xfffffff6,100);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = FLOAT_803e0e50 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
        uStack_24 = FUN_80022264(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = FLOAT_803e0e3c *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      }
      else {
        uStack_14 = FUN_80022264(0xfffffff6,10);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = FLOAT_803e0e3c *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90) +
                   FLOAT_803e0e68;
        uStack_1c = FUN_80022264(0xfffffff6,100);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = FLOAT_803e0e50 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90) +
                   FLOAT_803e0e6c;
        uStack_24 = FUN_80022264(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = FLOAT_803e0e3c *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90) +
                   FLOAT_803e0e70;
      }
      local_28 = 0x43300000;
      uStack_14 = FUN_80022264(7,9);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0e74 *
                 FLOAT_803e0e64 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xdf;
      break;
    case 0x741:
      if (param_3 != (undefined2 *)0x0) {
        local_64 = *(float *)(param_3 + 8);
      }
      local_5c = FLOAT_803e0e78;
      local_98[2] = FUN_80022264(0,0x1e);
      local_98[2] = local_98[2] + 0x50;
      local_38 = 0x60;
      local_54 = 0x80110;
      local_56 = 0x7b;
      local_37 = 0x20;
      break;
    case 0x742:
      local_6c = FLOAT_803e0e7c;
      uStack_14 = FUN_80022264(0xffffffec,0x14);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e0e80 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_70 = FLOAT_803e0e80 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      local_5c = FLOAT_803e0e84;
      local_98[2] = FUN_80022264(0x46,0x50);
      local_38 = 0xff;
      local_54 = 0x82000104;
      local_50 = 0x400;
      local_56 = 0x3f4;
      break;
    case 0x743:
      local_6c = FLOAT_803e0e7c;
      uStack_14 = FUN_80022264(0xffffffec,0x14);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e0e80 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_70 = FLOAT_803e0e80 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      local_5c = FLOAT_803e0e84;
      local_98[2] = FUN_80022264(0x46,0x50);
      local_38 = 0xff;
      local_54 = 0x82000104;
      local_50 = 0x400;
      local_56 = 0x500;
      break;
    case 0x744:
      uVar2 = FUN_80022264(0,4);
      if (uVar2 == 4) {
        local_5c = FLOAT_803e0e88;
        local_38 = 0x9b;
        local_54 = 0x480000;
        local_98[2] = FUN_80022264(0x1e,0x28);
      }
      else {
        local_5c = FLOAT_803e0e8c;
        local_38 = 0x7d;
        local_54 = 0x180000;
        local_98[2] = 0x50;
      }
      local_50 = 0x2000000;
      local_56 = 0x88;
    }
    local_54 = local_54 | param_4;
    if (((local_54 & 1) != 0) && ((local_54 & 2) != 0)) {
      local_54 = local_54 ^ 2;
    }
    if ((local_54 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_98[0] != 0) {
          local_68 = local_68 + *(float *)(local_98[0] + 0x18);
          local_64 = local_64 + *(float *)(local_98[0] + 0x1c);
          local_60 = local_60 + *(float *)(local_98[0] + 0x20);
        }
      }
      else {
        local_68 = local_68 + local_80;
        local_64 = local_64 + local_7c;
        local_60 = local_60 + local_78;
      }
    }
    uVar1 = (**(code **)(*DAT_803dd6f8 + 8))(local_98,0xffffffff,param_2,0);
  }
  return uVar1;
}

