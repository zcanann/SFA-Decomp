// Function: FUN_802910e0
// Entry: 802910e0
// Size: 1284 bytes

/* WARNING: Could not reconcile some variable overlaps */

char * FUN_802910e0(int param_1,undefined4 param_2,uint *param_3)

{
  bool bVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  char *pcVar5;
  char *pcVar6;
  undefined4 local_28;
  undefined4 local_24;
  uint local_20;
  uint local_1c;
  
  pcVar5 = (char *)(param_1 + 1);
  uVar4 = (uint)(char)*(byte *)(param_1 + 1);
  local_28 = 0x1000000;
  local_24 = (uint)local_24._1_3_;
  local_20 = 0;
  local_1c = 0;
  if (uVar4 == 0x25) {
    local_24._1_3_ = local_24._1_3_ & 0xffff | (uint3)*(byte *)(param_1 + 1) << 0x10;
    local_24 = (uint)local_24._1_3_;
    *param_3 = 0x1000000;
    param_3[1] = local_24;
    param_3[2] = 0;
    param_3[3] = 0;
    return (char *)(param_1 + 2);
  }
  while( true ) {
    bVar1 = true;
    switch(uVar4) {
    case 0x20:
      if (local_28._1_1_ != '\x01') {
        local_28._1_3_ = CONCAT12(2,local_28._2_2_);
        local_28 = local_28 & 0xff000000 | (uint)local_28._1_3_;
      }
      break;
    default:
      bVar1 = false;
      break;
    case 0x23:
      local_28 = CONCAT31(local_28._0_3_,1);
      break;
    case 0x2b:
      local_28._1_3_ = CONCAT12(1,local_28._2_2_);
      local_28 = local_28 & 0xff000000 | (uint)local_28._1_3_;
      break;
    case 0x2d:
      local_28 = local_28 & 0xffffff;
      break;
    case 0x30:
      if (local_28._0_1_ != '\0') {
        local_28 = CONCAT13(2,local_28._1_3_);
      }
    }
    if (!bVar1) break;
    pcVar5 = pcVar5 + 1;
    uVar4 = (uint)*pcVar5;
  }
  if (uVar4 == 0x2a) {
    puVar3 = (uint *)FUN_80285ea4(param_2,1);
    local_20 = *puVar3;
    if ((int)local_20 < 0) {
      local_20 = -local_20;
      local_28 = local_28 & 0xffffff;
    }
    pcVar5 = pcVar5 + 1;
    uVar4 = (uint)*pcVar5;
  }
  else {
    while (((&DAT_803325e8)[uVar4 & 0xff] & 0x10) != 0) {
      pcVar5 = pcVar5 + 1;
      local_20 = (uVar4 + local_20 * 10) - 0x30;
      uVar4 = (uint)*pcVar5;
    }
  }
  if (0x1fd < (int)local_20) {
    local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
    local_24 = (uint)local_24._1_3_;
    *param_3 = local_28;
    param_3[1] = local_24;
    param_3[2] = local_20;
    param_3[3] = 0;
    return pcVar5 + 1;
  }
  pcVar6 = pcVar5;
  if (uVar4 == 0x2e) {
    pcVar6 = pcVar5 + 1;
    local_28._2_2_ = CONCAT11(1,(undefined)local_28);
    uVar2 = local_28 & 0xffff0000;
    local_28 = uVar2 | local_28._2_2_;
    uVar4 = (uint)*pcVar6;
    if (uVar4 == 0x2a) {
      puVar3 = (uint *)FUN_80285ea4(param_2,1);
      local_1c = *puVar3;
      if ((int)local_1c < 0) {
        local_28 = uVar2 | local_28._2_2_ & 0xffff00ff;
      }
      pcVar6 = pcVar5 + 2;
      uVar4 = (uint)*pcVar6;
    }
    else {
      while (((&DAT_803325e8)[uVar4 & 0xff] & 0x10) != 0) {
        pcVar6 = pcVar6 + 1;
        local_1c = (uVar4 + local_1c * 10) - 0x30;
        uVar4 = (uint)*pcVar6;
      }
    }
  }
  bVar1 = true;
  if (uVar4 == 0x68) {
    pcVar5 = pcVar6 + 1;
    local_24 = CONCAT13(2,local_24._1_3_);
    if ((int)*pcVar5 == 0x68) {
      local_24 = CONCAT13(1,local_24._1_3_);
      pcVar6 = pcVar6 + 1;
      uVar4 = (int)*pcVar5;
    }
  }
  else {
    if ((int)uVar4 < 0x68) {
      if (uVar4 == 0x4c) {
        local_24 = CONCAT13(5,local_24._1_3_);
        goto LAB_802913b4;
      }
    }
    else if (uVar4 == 0x6c) {
      pcVar5 = pcVar6 + 1;
      local_24 = CONCAT13(3,local_24._1_3_);
      if ((int)*pcVar5 == 0x6c) {
        local_24 = CONCAT13(4,local_24._1_3_);
        pcVar6 = pcVar6 + 1;
        uVar4 = (int)*pcVar5;
      }
      goto LAB_802913b4;
    }
    bVar1 = false;
  }
LAB_802913b4:
  if (bVar1) {
    pcVar6 = pcVar6 + 1;
    uVar4 = (uint)*pcVar6;
  }
  local_24._1_3_ = CONCAT12((char)uVar4,local_24._2_2_);
  uVar2 = local_24 & 0xff000000;
  local_24 = uVar2 | local_24._1_3_;
  local_24._0_1_ = (char)(uVar2 >> 0x18);
  switch(uVar4) {
  case 0x41:
  case 0x61:
    if (local_28._2_1_ == '\0') {
      local_1c = 0xd;
    }
    if (((local_24._0_1_ == '\x02') || (local_24._0_1_ == '\x04')) || (local_24._0_1_ == '\x01')) {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
      local_24 = uVar2 | local_24._1_3_;
    }
    break;
  default:
    local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
    local_24 = uVar2 | local_24._1_3_;
    break;
  case 0x46:
  case 0x66:
    if ((local_24._0_1_ == '\x02') || (local_24._0_1_ == '\x04')) {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
      local_24 = uVar2 | local_24._1_3_;
    }
    else if (local_28._2_1_ == '\0') {
      local_1c = 6;
    }
    break;
  case 0x47:
  case 0x67:
    if (local_1c == 0) {
      local_1c = 1;
    }
  case 0x45:
  case 0x65:
    if (((local_24._0_1_ == '\x02') || (local_24._0_1_ == '\x04')) || (local_24._0_1_ == '\x01')) {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
      local_24 = uVar2 | local_24._1_3_;
    }
    else if (local_28._2_1_ == '\0') {
      local_1c = 6;
    }
    break;
  case 0x58:
  case 100:
  case 0x69:
  case 0x6f:
  case 0x75:
  case 0x78:
    if (local_24._0_1_ == '\x05') {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
      local_24 = uVar2 | local_24._1_3_;
    }
    else if (local_28._2_1_ == '\0') {
      local_1c = 1;
    }
    else if (local_28._0_1_ == '\x02') {
      local_28 = CONCAT13(1,local_28._1_3_);
    }
    break;
  case 99:
    if (local_24._0_1_ == '\x03') {
      local_24 = CONCAT13(6,local_24._1_3_);
    }
    else if ((local_28._2_1_ != '\0') || (local_24._0_1_ != '\0')) {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
      local_24 = uVar2 | local_24._1_3_;
    }
    break;
  case 0x6e:
    if (local_24._0_1_ == '\x05') {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
      local_24 = uVar2 | local_24._1_3_;
    }
    break;
  case 0x70:
    local_24._1_3_ = CONCAT12(0x78,local_24._2_2_);
    local_28 = CONCAT31(local_28._0_3_,1);
    local_24 = CONCAT13(3,local_24._1_3_);
    local_1c = 8;
    break;
  case 0x73:
    if (local_24._0_1_ == '\x03') {
      local_24 = CONCAT13(6,local_24._1_3_);
    }
    else if (local_24._0_1_ != '\0') {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
      local_24 = uVar2 | local_24._1_3_;
    }
  }
  *param_3 = local_28;
  param_3[1] = local_24;
  param_3[2] = local_20;
  param_3[3] = local_1c;
  return pcVar6 + 1;
}

