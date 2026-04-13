// Function: FUN_8028bbe0
// Entry: 8028bbe0
// Size: 540 bytes

undefined4 FUN_8028bbe0(undefined4 *param_1,uint param_2,int param_3)

{
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  uint local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  
  local_40 = DAT_802c3158;
  local_3c = DAT_802c315c;
  local_38 = DAT_802c3160;
  local_34 = DAT_802c3164;
  local_30 = DAT_802c3168;
  local_2c = DAT_802c316c;
  local_28 = DAT_802c3170;
  local_24 = DAT_802c3174;
  local_20 = DAT_802c3178;
  local_1c = DAT_802c317c;
  if (param_2 < 0x20) {
    local_40 = param_2 << 0x15 | 0xc8030000;
    if (param_3 != 0) {
      local_40 = param_2 << 0x15 | 0xd8030000;
    }
    local_1c = 0x4e800020;
    FUN_8028b748((uint)&local_40,0x28);
    (*(code *)&local_40)(param_1,&DAT_803d94c4);
  }
  else if (param_2 == 0x20) {
    param_1[1] = param_1[1];
    *param_1 = 0;
  }
  else if (param_2 == 0x21) {
    if (param_3 == 0) {
      *param_1 = param_1[1];
    }
    local_60 = DAT_802c3110;
    local_5c = DAT_802c3114;
    local_58 = DAT_802c3118;
    local_54 = DAT_802c311c;
    local_50 = DAT_802c3120;
    local_4c = DAT_802c3124;
    local_48 = DAT_802c3128;
    if (param_3 == 0) {
      local_68 = 0x80830000;
      local_64 = 0x7c9efba6;
    }
    else {
      local_64 = 0x90830000;
      local_68 = 0x7c9efaa6;
    }
    local_44 = 0x4e800020;
    FUN_8028b748((uint)&local_68,0x28);
    (*(code *)&local_68)(param_1,&DAT_803d94c4);
    if (param_3 != 0) {
      param_1[1] = *param_1;
      *param_1 = 0;
    }
  }
  return 0;
}

