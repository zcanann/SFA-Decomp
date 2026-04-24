// Function: FUN_800a411c
// Entry: 800a411c
// Size: 528 bytes

void FUN_800a411c(int param_1)

{
  undefined4 uVar1;
  undefined4 local_b8;
  undefined4 local_b4;
  uint *local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined auStack156 [24];
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
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  local_ac = DAT_802c2160;
  local_a8 = DAT_802c2164;
  local_a4 = DAT_802c2168;
  local_a0 = DAT_802c216c;
  local_b4 = 0;
  if (DAT_803dd298 != '\0') {
    local_6c = FLOAT_803df46c;
    local_50 = FLOAT_803df46c;
    switch(DAT_803dd298) {
    case '\v':
      local_6c = FLOAT_803df488;
      local_50 = FLOAT_803df488;
      break;
    case '\f':
      local_6c = FLOAT_803df48c;
      local_50 = FLOAT_803df490;
      break;
    case '\r':
      local_6c = FLOAT_803df494;
      local_50 = FLOAT_803df488;
      break;
    case '\x0e':
      local_6c = FLOAT_803df494;
      local_50 = FLOAT_803df488;
      break;
    case '\x0f':
      local_6c = FLOAT_803df498;
      local_50 = FLOAT_803df490;
      break;
    case '\x10':
      local_6c = FLOAT_803df49c;
      local_50 = FLOAT_803df4a0;
      break;
    case '\x11':
      local_6c = FLOAT_803df4a4;
      local_50 = FLOAT_803df4a4;
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
    FUN_8006961c(auStack156,&local_84,&local_54,&local_ac,4);
    FUN_800691c0(param_1,auStack156,0x84,0);
    FUN_80069968(&local_b8,&local_b4);
    uVar1 = local_b4;
    FUN_80069958(&local_b0);
    uStack28 = *local_b0 ^ 0x80000000;
    local_20 = 0x43300000;
    uStack20 = local_b0[2] ^ 0x80000000;
    local_18 = 0x43300000;
    FUN_800a3af0((double)(*(float *)(param_1 + 0xc) -
                         (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803df480)),
                 (double)(*(float *)(param_1 + 0x14) -
                         (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803df480)),uVar1,
                 local_b8,param_1);
  }
  return;
}

