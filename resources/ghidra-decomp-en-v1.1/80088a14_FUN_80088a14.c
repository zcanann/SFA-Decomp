// Function: FUN_80088a14
// Entry: 80088a14
// Size: 60 bytes

void FUN_80088a14(byte param_1)

{
  uint uVar1;
  
  uVar1 = (uint)param_1;
  if (0x1b < param_1) {
    uVar1 = 0;
  }
  FUN_800201ac(0x2ba,uVar1);
  return;
}

