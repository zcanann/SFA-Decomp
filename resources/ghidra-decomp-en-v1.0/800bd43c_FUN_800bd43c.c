// Function: FUN_800bd43c
// Entry: 800bd43c
// Size: 2756 bytes

undefined4
FUN_800bd43c(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            undefined2 *param_6)

{
  undefined4 uVar1;
  int iVar2;
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
  
  FLOAT_803db7f0 = FLOAT_803db7f0 + FLOAT_803dfc80;
  if (FLOAT_803dfc88 < FLOAT_803db7f0) {
    FLOAT_803db7f0 = FLOAT_803dfc84;
  }
  FLOAT_803db7f4 = FLOAT_803db7f4 + FLOAT_803dfc8c;
  if (FLOAT_803dfc88 < FLOAT_803db7f4) {
    FLOAT_803db7f4 = FLOAT_803dfc90;
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
    local_88 = FLOAT_803dfc94;
    local_84 = FLOAT_803dfc94;
    local_80 = FLOAT_803dfc94;
    local_94 = FLOAT_803dfc94;
    local_90 = FLOAT_803dfc94;
    local_8c = FLOAT_803dfc94;
    local_7c = FLOAT_803dfc94;
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
    local_78 = 0;
    local_b8 = param_1;
    switch(param_2) {
    case 0x422:
      if (param_6 == (undefined2 *)0x0) {
        return 0;
      }
      local_7c = FLOAT_803dfc98;
      local_b0 = FUN_800221a0(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 100;
      local_57 = 0x1e;
      break;
    case 0x423:
      uStack76 = FUN_800221a0(0xfffffff6,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = FLOAT_803dfc90 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfcc8);
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dfc90 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfcc8);
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = FLOAT_803dfc90 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfcc8);
      uStack52 = FUN_800221a0(5,0xb);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_7c = FLOAT_803dfc80 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfcc8);
      local_b0 = 0x3c;
      local_74 = 0x80110;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x424:
      uStack52 = FUN_800221a0(0xfffffff6,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfc90 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfcc8);
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803dfc90 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfcc8);
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = FLOAT_803dfc90 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfcc8);
      uStack76 = FUN_800221a0(0xfffffffb,5);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803dfc84 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfcc8);
      uStack44 = FUN_800221a0(3,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803dfc84 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfcc8);
      uStack36 = FUN_800221a0(0xfffffffb,5);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803dfc84 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfcc8);
      uStack28 = FUN_800221a0(5,0xb);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = FLOAT_803dfc9c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfcc8);
      local_b0 = 0x3c;
      local_74 = 0x1480200;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x425:
      uStack28 = FUN_800221a0(8,10);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_90 = FLOAT_803dfca0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfcc8);
      iVar2 = FUN_800221a0(0,0x28);
      if (iVar2 == 0) {
        uStack28 = FUN_800221a0(0x15,0x29);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_7c = FLOAT_803dfc80 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfcc8)
        ;
        local_b0 = 0x1cc;
      }
      else {
        uStack28 = FUN_800221a0(8,0x14);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_7c = FLOAT_803dfc80 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfcc8)
        ;
        local_b0 = FUN_800221a0(0x5a,0x78);
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
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803dfca0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfcc8);
      uStack36 = FUN_800221a0(8,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfca0 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfcc8);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfca0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfcc8);
      local_7c = FLOAT_803dfca4;
      local_b0 = 0x32;
      local_74 = 0x3000200;
      local_70 = 0x200020;
      local_76 = 0x33;
      local_58 = 0xff;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0xffff;
      local_6c = 0xffff;
      local_68 = FUN_800221a0(0,0x8000);
      local_64 = local_68;
      break;
    case 0x427:
      uStack28 = FUN_800221a0(0xffffff9c,100);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfcc8) / FLOAT_803dfca8;
      uStack36 = FUN_800221a0(0xffffffce,0x32);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfcc8) / FLOAT_803dfcac;
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfcc8) / FLOAT_803dfca8;
      uStack52 = FUN_800221a0(1,4);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = FLOAT_803dfcb0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfcc8);
      uStack60 = FUN_800221a0(0,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_7c = FLOAT_803dfcb8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfcc8) +
                 FLOAT_803dfcb4;
      local_b0 = 0xa0;
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
      local_7c = FLOAT_803dfcbc;
      local_b0 = FUN_800221a0(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 0xc7e;
      local_57 = 0x1e;
      break;
    case 0x42c:
      uStack28 = FUN_800221a0(0xfffffff6,10);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803dfcc0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfcc8);
      uStack36 = FUN_800221a0(10,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfc98 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfcc8);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfcc0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfcc8);
      local_7c = FLOAT_803dfcc4;
      local_b0 = 0x6e;
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
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803dfcc4 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfcc8);
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803dfcc4 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfcc8);
      local_7c = FLOAT_803dfc84;
      local_b0 = 600;
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
    uVar1 = (**(code **)(*DAT_803dca78 + 8))(&local_b8,0xffffffff,param_2,0);
  }
  return uVar1;
}

