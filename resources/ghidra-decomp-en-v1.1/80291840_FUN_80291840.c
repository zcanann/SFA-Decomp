// Function: FUN_80291840
// Entry: 80291840
// Size: 1284 bytes

char * FUN_80291840(int param_1,char *param_2,uint *param_3)

{
  bool bVar1;
  undefined2 uVar2;
  uint uVar3;
  uint3 uVar4;
  uint *puVar5;
  uint uVar6;
  char *pcVar7;
  char *pcVar8;
  undefined4 local_28;
  undefined4 local_24;
  uint local_20;
  uint local_1c;
  
  uVar4 = local_24._1_3_;
  pcVar7 = (char *)(param_1 + 1);
  uVar6 = (uint)*(char *)(param_1 + 1);
  local_28 = 0x1000000;
  local_24 = (uint)local_24._1_3_;
  uVar3 = local_24;
  local_20 = 0;
  local_1c = 0;
  local_24._2_2_ = (undefined2)uVar4;
  if (uVar6 == 0x25) {
    local_24._1_3_ = CONCAT12(*(char *)(param_1 + 1),local_24._2_2_);
    local_24 = (uint)local_24._1_3_;
    *param_3 = 0x1000000;
    param_3[1] = local_24;
    param_3[2] = 0;
    param_3[3] = 0;
    return (char *)(param_1 + 2);
  }
  while( true ) {
    bVar1 = true;
    uVar2 = local_28._2_2_;
    switch(uVar6) {
    case 0x20:
      if (local_28._1_1_ != '\x01') {
        local_28._1_3_ = CONCAT12(2,uVar2);
      }
      break;
    default:
      bVar1 = false;
      break;
    case 0x23:
      local_28 = CONCAT31(local_28._0_3_,1);
      break;
    case 0x2b:
      local_28._1_3_ = CONCAT12(1,uVar2);
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
    pcVar7 = pcVar7 + 1;
    uVar6 = (uint)*pcVar7;
  }
  if (uVar6 == 0x2a) {
    puVar5 = (uint *)FUN_80286608(param_2,1);
    local_20 = *puVar5;
    if ((int)local_20 < 0) {
      local_20 = -local_20;
      local_28 = local_28 & 0xffffff;
    }
    pcVar7 = pcVar7 + 1;
    uVar6 = (uint)*pcVar7;
  }
  else {
    while (((&DAT_80333248)[uVar6 & 0xff] & 0x10) != 0) {
      pcVar7 = pcVar7 + 1;
      local_20 = (uVar6 + local_20 * 10) - 0x30;
      uVar6 = (uint)*pcVar7;
    }
  }
  if (0x1fd < (int)local_20) {
    local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
    local_24 = (uint)local_24._1_3_;
    *param_3 = local_28;
    param_3[1] = local_24;
    param_3[2] = local_20;
    param_3[3] = 0;
    return pcVar7 + 1;
  }
  pcVar8 = pcVar7;
  if (uVar6 == 0x2e) {
    pcVar8 = pcVar7 + 1;
    local_28._2_2_ = CONCAT11(1,(byte)local_28);
    uVar6 = (uint)*pcVar8;
    if (uVar6 == 0x2a) {
      puVar5 = (uint *)FUN_80286608(param_2,1);
      local_1c = *puVar5;
      if ((int)local_1c < 0) {
        local_28 = CONCAT22(local_28._0_2_,(ushort)(byte)local_28);
      }
      pcVar8 = pcVar7 + 2;
      uVar6 = (uint)*pcVar8;
    }
    else {
      while (((&DAT_80333248)[uVar6 & 0xff] & 0x10) != 0) {
        pcVar8 = pcVar8 + 1;
        local_1c = (uVar6 + local_1c * 10) - 0x30;
        uVar6 = (uint)*pcVar8;
      }
    }
  }
  bVar1 = true;
  if (uVar6 == 0x68) {
    local_24 = CONCAT13(2,uVar4);
    if (pcVar8[1] == 'h') {
      local_24 = CONCAT13(1,uVar4);
      pcVar8 = pcVar8 + 1;
      uVar6 = 0x68;
    }
  }
  else {
    if ((int)uVar6 < 0x68) {
      if (uVar6 == 0x4c) {
        local_24 = CONCAT13(5,uVar4);
        goto LAB_80291b14;
      }
    }
    else if (uVar6 == 0x6c) {
      local_24 = CONCAT13(3,uVar4);
      if (pcVar8[1] == 'l') {
        local_24 = CONCAT13(4,uVar4);
        pcVar8 = pcVar8 + 1;
        uVar6 = 0x6c;
      }
      goto LAB_80291b14;
    }
    bVar1 = false;
    local_24 = uVar3;
  }
LAB_80291b14:
  if (bVar1) {
    pcVar8 = pcVar8 + 1;
    uVar6 = (uint)*pcVar8;
  }
  local_24._1_3_ = CONCAT12((char)uVar6,local_24._2_2_);
  switch(uVar6) {
  case 0x41:
  case 0x61:
    if (local_28._2_1_ == '\0') {
      local_1c = 0xd;
    }
    if (((local_24._0_1_ == '\x02') || (local_24._0_1_ == '\x04')) || (local_24._0_1_ == '\x01')) {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
    }
    break;
  default:
    local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
    break;
  case 0x46:
  case 0x66:
    if ((local_24._0_1_ == '\x02') || (local_24._0_1_ == '\x04')) {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
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
      local_24 = CONCAT13(5,local_24._1_3_);
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
    }
    break;
  case 0x6e:
    if (local_24._0_1_ == '\x05') {
      local_24._1_3_ = CONCAT12(0xff,local_24._2_2_);
      local_24 = CONCAT13(5,local_24._1_3_);
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
    }
  }
  *param_3 = local_28;
  param_3[1] = local_24;
  param_3[2] = local_20;
  param_3[3] = local_1c;
  return pcVar8 + 1;
}

