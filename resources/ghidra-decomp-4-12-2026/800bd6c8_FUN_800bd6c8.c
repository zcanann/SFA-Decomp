// Function: FUN_800bd6c8
// Entry: 800bd6c8
// Size: 2756 bytes

undefined4
FUN_800bd6c8(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            undefined2 *param_6)

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
  uint local_68;
  uint local_64;
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
  
  FLOAT_803dc450 = FLOAT_803dc450 + FLOAT_803e0900;
  if (FLOAT_803e0908 < FLOAT_803dc450) {
    FLOAT_803dc450 = FLOAT_803e0904;
  }
  FLOAT_803dc454 = FLOAT_803dc454 + FLOAT_803e090c;
  if (FLOAT_803e0908 < FLOAT_803dc454) {
    FLOAT_803dc454 = FLOAT_803e0910;
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
    local_88 = FLOAT_803e0914;
    local_84 = FLOAT_803e0914;
    local_80 = FLOAT_803e0914;
    local_94 = FLOAT_803e0914;
    local_90 = FLOAT_803e0914;
    local_8c = FLOAT_803e0914;
    local_7c = FLOAT_803e0914;
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
    case 0x422:
      if (param_6 == (undefined2 *)0x0) {
        return 0;
      }
      local_7c = FLOAT_803e0918;
      local_b8[2] = FUN_80022264(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 100;
      local_57 = 0x1e;
      break;
    case 0x423:
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0948);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0948);
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0948);
      uStack_34 = FUN_80022264(5,0xb);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_7c = FLOAT_803e0900 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0948);
      local_b8[2] = 0x3c;
      local_74 = 0x80110;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x424:
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0948);
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0948);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0948);
      uStack_4c = FUN_80022264(0xfffffffb,5);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803e0904 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0948);
      uStack_2c = FUN_80022264(3,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803e0904 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948);
      uStack_24 = FUN_80022264(0xfffffffb,5);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803e0904 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      uStack_1c = FUN_80022264(5,0xb);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = FLOAT_803e091c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      local_b8[2] = 0x3c;
      local_74 = 0x1480200;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x425:
      uStack_1c = FUN_80022264(8,10);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_90 = FLOAT_803e0920 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uVar2 = FUN_80022264(0,0x28);
      if (uVar2 == 0) {
        uStack_1c = FUN_80022264(0x15,0x29);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_7c = FLOAT_803e0900 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
        local_b8[2] = 0x1cc;
      }
      else {
        uStack_1c = FUN_80022264(8,0x14);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_7c = FLOAT_803e0900 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
        local_b8[2] = FUN_80022264(0x5a,0x78);
      }
      local_74 = 0x80180200;
      local_70 = 0x1000020;
      local_76 = 0xc0b;
      local_58 = 0x7f;
      local_5c = 0x3fff;
      local_5e = 0x3fff;
      local_60 = 0x3fff;
      local_64 = 0xffff;
      local_68 = 0xffff;
      local_6c = 0xffff;
      break;
    case 0x426:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803e0920 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uStack_24 = FUN_80022264(8,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0920 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0920 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948);
      local_7c = FLOAT_803e0924;
      local_b8[2] = 0x32;
      local_74 = 0x3000200;
      local_70 = 0x200020;
      local_76 = 0x33;
      local_58 = 0xff;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0xffff;
      local_6c = 0xffff;
      local_68 = FUN_80022264(0,0x8000);
      local_64 = local_68;
      break;
    case 0x427:
      uStack_1c = FUN_80022264(0xffffff9c,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948) / FLOAT_803e0928;
      uStack_24 = FUN_80022264(0xffffffce,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948) / FLOAT_803e092c;
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948) / FLOAT_803e0928;
      uStack_34 = FUN_80022264(1,4);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = FLOAT_803e0930 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0948);
      uStack_3c = FUN_80022264(0,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_7c = FLOAT_803e0938 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0948)
                 + FLOAT_803e0934;
      local_b8[2] = 0xa0;
      local_57 = 0;
      local_74 = 0x100200;
      local_76 = 0x33;
      break;
    default:
      return 0xffffffff;
    case 0x42b:
      if (param_6 == (undefined2 *)0x0) {
        return 0;
      }
      local_7c = FLOAT_803e093c;
      local_b8[2] = FUN_80022264(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 0xc7e;
      local_57 = 0x1e;
      break;
    case 0x42c:
      uStack_1c = FUN_80022264(0xfffffff6,10);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803e0940 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uStack_24 = FUN_80022264(10,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0918 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0940 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948);
      local_7c = FLOAT_803e0944;
      local_b8[2] = 0x6e;
      local_74 = 0x8a100208;
      local_70 = 0x20;
      local_76 = 0x5f;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0xffff;
      local_6c = 0x400;
      local_68 = 60000;
      local_64 = 0x1000;
      break;
    case 0x42d:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803e0944 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803e0944 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      local_7c = FLOAT_803e0904;
      local_b8[2] = 600;
      local_58 = 0x7f;
      local_74 = 0xa100100;
      local_70 = 0x20;
      local_76 = 0x62;
      local_60 = 0x400;
      local_5e = 60000;
      local_5c = 0x1000;
      local_6c = 0;
      local_68 = 50000;
      local_64 = 0;
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

