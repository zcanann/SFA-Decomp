// Function: FUN_802501f4
// Entry: 802501f4
// Size: 28 bytes

void FUN_802501f4(uint param_1)

{
  uint uVar1;
  
  uVar1 = DAT_cc006c04;
  DAT_cc006c04 = param_1 & 0xff | uVar1 & 0xffffff00;
  return;
}

