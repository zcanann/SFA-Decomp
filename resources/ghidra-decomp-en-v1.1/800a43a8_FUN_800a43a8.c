// Function: FUN_800a43a8
// Entry: 800a43a8
// Size: 528 bytes

void FUN_800a43a8(int param_1)

{
  undefined4 uVar1;
  int local_b8;
  undefined4 local_b4;
  uint *local_b0;
  float local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  uint auStack_9c [6];
  float local_84;
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
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  local_ac = DAT_802c28e0;
  local_a8 = DAT_802c28e4;
  local_a4 = DAT_802c28e8;
  local_a0 = DAT_802c28ec;
  local_b4 = 0;
  if (DAT_803ddf18 != '\0') {
    local_6c = FLOAT_803e00ec;
    local_50 = FLOAT_803e00ec;
    switch(DAT_803ddf18) {
    case '\v':
      local_6c = FLOAT_803e0108;
      local_50 = FLOAT_803e0108;
      break;
    case '\f':
      local_6c = FLOAT_803e010c;
      local_50 = FLOAT_803e0110;
      break;
    case '\r':
      local_6c = FLOAT_803e0114;
      local_50 = FLOAT_803e0108;
      break;
    case '\x0e':
      local_6c = FLOAT_803e0114;
      local_50 = FLOAT_803e0108;
      break;
    case '\x0f':
      local_6c = FLOAT_803e0118;
      local_50 = FLOAT_803e0110;
      break;
    case '\x10':
      local_6c = FLOAT_803e011c;
      local_50 = FLOAT_803e0120;
      break;
    case '\x11':
      local_6c = FLOAT_803e0124;
      local_50 = FLOAT_803e0124;
    }
    local_84 = *(float *)(param_1 + 0xc) - local_6c;
    local_80 = *(float *)(param_1 + 0x10) + local_50;
    local_7c = *(float *)(param_1 + 0x14) - local_6c;
    local_70 = *(float *)(param_1 + 0x14) + local_6c;
    local_6c = *(float *)(param_1 + 0xc) + local_6c;
    local_50 = *(float *)(param_1 + 0x10) - local_50;
    local_78 = local_84;
    local_74 = local_80;
    local_68 = local_80;
    local_64 = local_70;
    local_60 = local_6c;
    local_5c = local_80;
    local_58 = local_7c;
    local_54 = local_84;
    local_4c = local_7c;
    local_48 = local_84;
    local_44 = local_50;
    local_40 = local_70;
    local_3c = local_6c;
    local_38 = local_50;
    local_34 = local_70;
    local_30 = local_6c;
    local_2c = local_50;
    local_28 = local_7c;
    FUN_80069798(auStack_9c,&local_84,&local_54,&local_ac,4);
    FUN_8006933c(param_1,auStack_9c,0x84,'\0');
    FUN_80069ae4(&local_b8,&local_b4);
    uVar1 = local_b4;
    FUN_80069ad4(&local_b0);
    uStack_1c = *local_b0 ^ 0x80000000;
    local_20 = 0x43300000;
    uStack_14 = local_b0[2] ^ 0x80000000;
    local_18 = 0x43300000;
    FUN_800a3d7c((double)(*(float *)(param_1 + 0xc) -
                         (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0100)),
                 (double)(*(float *)(param_1 + 0x14) -
                         (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0100)),uVar1,
                 local_b8,param_1);
  }
  return;
}

