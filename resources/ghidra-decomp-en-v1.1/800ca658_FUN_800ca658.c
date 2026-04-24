// Function: FUN_800ca658
// Entry: 800ca658
// Size: 1364 bytes

undefined4 FUN_800ca658(uint param_1,int param_2,undefined2 *param_3,uint param_4,undefined param_5)

{
  uint uVar1;
  undefined4 uVar2;
  uint local_98 [3];
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
  undefined2 local_56;
  uint local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
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
  undefined *puStack_1c;
  
  if (param_1 == 0) {
    return 0xffffffff;
  }
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
  local_68 = FLOAT_803e0e00;
  local_64 = FLOAT_803e0e00;
  local_60 = FLOAT_803e0e00;
  local_74 = FLOAT_803e0e00;
  local_70 = FLOAT_803e0e00;
  local_6c = FLOAT_803e0e00;
  local_5c = FLOAT_803e0e00;
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
  local_98[0] = param_1;
  if (param_2 == 0x44f) {
    if (param_3 == (undefined2 *)0x0) {
      param_3 = &DAT_8039d0a0;
      DAT_8039d0ac = FLOAT_803e0e00;
      DAT_8039d0b0 = FLOAT_803e0e00;
      DAT_8039d0b4 = FLOAT_803e0e00;
      DAT_8039d0a8 = FLOAT_803e0e1c;
      DAT_8039d0a0 = 0;
      DAT_8039d0a2 = 0;
      DAT_8039d0a4 = 0;
    }
    (**(code **)(*DAT_803dd718 + 0x10))
              ((double)*(float *)(param_3 + 6),(double)*(float *)(param_3 + 8),
               (double)*(float *)(param_3 + 10),(double)FLOAT_803e0e20,0);
    FUN_8000bb38(param_1,0x285);
    local_98[2] = 1;
    local_5c = FLOAT_803e0e24;
    local_54 = 0xa000001;
    local_56 = 0x56;
  }
  else if (param_2 < 0x44f) {
    if (param_2 == 0x44d) {
      uVar1 = FUN_80022264(0xfffffff6,10);
      puStack_1c = (undefined *)(uVar1 ^ 0x80000000);
      local_20 = 0x43300000;
      local_74 = FLOAT_803e0e0c * (float)((double)CONCAT44(0x43300000,puStack_1c) - DOUBLE_803e0e30)
      ;
      uStack_24 = FUN_80022264(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_6c = FLOAT_803e0e0c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e30);
      local_5c = FLOAT_803e0e10;
      local_98[2] = 600;
      local_38 = 0x7f;
      local_54 = 0xa100100;
      local_50 = 0x20;
      local_56 = 0x62;
      local_40 = 0x400;
      local_3e = 60000;
      local_3c = 0x1000;
      local_4c = 0;
      local_48 = 50000;
      local_44 = 0;
    }
    else if (param_2 < 0x44d) {
      if (param_2 < 0x44c) {
        return 0xffffffff;
      }
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e0e04 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e30);
      uStack_24 = FUN_80022264(10,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e0e08 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e30);
      uVar1 = FUN_80022264(0xfffffff6,10);
      puStack_1c = (undefined *)(uVar1 ^ 0x80000000);
      local_20 = 0x43300000;
      local_6c = FLOAT_803e0e04 * (float)((double)CONCAT44(0x43300000,puStack_1c) - DOUBLE_803e0e30)
      ;
      local_5c = FLOAT_803e0e0c;
      local_98[2] = 0x6e;
      local_54 = 0x8a100208;
      local_50 = 0x20;
      local_56 = 0x5f;
      local_40 = 0xffff;
      local_3e = 0xffff;
      local_3c = 0xffff;
      local_4c = 0x400;
      local_48 = 60000;
      local_44 = 0x1000;
    }
    else {
      local_64 = FLOAT_803e0e14;
      local_5c = FLOAT_803e0e18;
      local_98[2] = 200;
      local_54 = 0x11000004;
      local_56 = 0x151;
      local_98[1] = 0x44f;
    }
  }
  else if (param_2 == 0x451) {
    FUN_8000bb38(param_1,0x285);
    local_98[2] = 100;
    puStack_1c = &DAT_80000064;
    local_20 = 0x43300000;
    local_5c = FLOAT_803e0e2c * (float)(4503601774854244.0 - DOUBLE_803e0e30);
    local_54 = 0xa100201;
    local_56 = 0x56;
  }
  else {
    if (0x450 < param_2) {
      return 0xffffffff;
    }
    local_64 = FLOAT_803e0e28;
    local_5c = FLOAT_803e0e18;
    local_98[2] = 200;
    local_54 = 0x11000004;
    local_56 = 0x151;
    local_98[1] = 0x451;
  }
  local_54 = local_54 | param_4;
  if (((local_54 & 1) != 0) && ((param_4 & 2) != 0)) {
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
  uVar2 = (**(code **)(*DAT_803dd6f8 + 8))(local_98,0xffffffff,param_2,0);
  return uVar2;
}

