// Function: FUN_800cd1e8
// Entry: 800cd1e8
// Size: 928 bytes

void FUN_800cd1e8(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  int iVar1;
  undefined8 uVar2;
  int local_a8 [3];
  undefined2 local_9c;
  undefined2 local_9a;
  undefined2 local_98;
  undefined4 local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined2 local_68;
  undefined2 local_66;
  uint local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined2 local_50;
  undefined2 local_4e;
  undefined2 local_4c;
  undefined local_4a;
  undefined local_48;
  undefined local_47;
  undefined local_46;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  
  uVar2 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar2 >> 0x20);
  FLOAT_803dc4d0 = FLOAT_803dc4d0 + FLOAT_803e0f58;
  if (FLOAT_803e0f60 < FLOAT_803dc4d0) {
    FLOAT_803dc4d0 = FLOAT_803e0f5c;
  }
  FLOAT_803dc4d4 = FLOAT_803dc4d4 + FLOAT_803e0f64;
  if (FLOAT_803e0f60 < FLOAT_803dc4d4) {
    FLOAT_803dc4d4 = FLOAT_803e0f68;
  }
  if (iVar1 != 0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) goto LAB_800cd570;
      local_90 = *(float *)(param_3 + 6);
      local_8c = *(float *)(param_3 + 8);
      local_88 = *(float *)(param_3 + 10);
      local_94 = *(undefined4 *)(param_3 + 4);
      local_98 = param_3[2];
      local_9a = param_3[1];
      local_9c = *param_3;
      local_46 = param_5;
    }
    local_64 = 0;
    local_60 = 0;
    local_4a = (undefined)uVar2;
    local_78 = FLOAT_803e0f6c;
    local_74 = FLOAT_803e0f6c;
    local_70 = FLOAT_803e0f6c;
    local_84 = FLOAT_803e0f6c;
    local_80 = FLOAT_803e0f6c;
    local_7c = FLOAT_803e0f6c;
    local_6c = FLOAT_803e0f6c;
    local_a8[2] = 0;
    local_a8[1] = 0xffffffff;
    local_48 = 0xff;
    local_47 = 0;
    local_66 = 0;
    local_50 = 0xffff;
    local_4e = 0xffff;
    local_4c = 0xffff;
    local_5c = 0xffff;
    local_58 = 0xffff;
    local_54 = 0xffff;
    local_68 = 0;
    local_a8[0] = iVar1;
    if ((int)uVar2 == 0x76c) {
      uStack_3c = FUN_80022264(0x1e,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0f70 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0f80);
      if (FLOAT_803e0f6c < *(float *)(param_3 + 6)) {
        local_84 = -local_84;
      }
      uStack_3c = FUN_80022264(0,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = FLOAT_803e0f58 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0f80)
                 + FLOAT_803e0f5c;
      local_38 = (longlong)(int)*param_6;
      local_30 = (longlong)(int)param_6[1];
      uStack_24 = FUN_80022264((int)*param_6,(int)param_6[1]);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e0f5c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0f80);
      local_78 = FLOAT_803e0f74;
      if (FLOAT_803e0f6c < *(float *)(param_3 + 6)) {
        local_78 = FLOAT_803e0f78;
      }
      uStack_24 = FUN_80022264(0xffffff9c,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_6c = FLOAT_803e0f7c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0f80)
                 + param_6[2];
      local_a8[2] = 0x23;
      local_66 = 0x60;
      local_48 = 0xc4;
      local_64 = param_4 | 0x80108;
      if (((param_4 & 1) != 0) && ((param_4 & 2) != 0)) {
        local_64 = local_64 ^ 2;
      }
      if ((local_64 & 1) != 0) {
        if ((param_4 & 0x200000) == 0) {
          if (local_a8[0] != 0) {
            local_78 = local_78 + *(float *)(local_a8[0] + 0x18);
            local_74 = local_74 + *(float *)(local_a8[0] + 0x1c);
            local_70 = local_70 + *(float *)(local_a8[0] + 0x20);
          }
        }
        else {
          local_78 = local_78 + local_90;
          local_74 = local_74 + local_8c;
          local_70 = local_70 + local_88;
        }
      }
      (**(code **)(*DAT_803dd6f8 + 8))(local_a8,0xffffffff,0x76c,0);
    }
  }
LAB_800cd570:
  FUN_8028688c();
  return;
}

