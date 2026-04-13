// Function: FUN_8021239c
// Entry: 8021239c
// Size: 160 bytes

void FUN_8021239c(void)

{
  uint uVar1;
  
  uVar1 = FUN_80020078(0x55a);
  if (uVar1 == 0) {
    uVar1 = FUN_80020078(0x55b);
    if (uVar1 != 0) {
      FUN_800201ac(0x54a,1);
      FUN_800201ac(0x54e,1);
      FUN_800201ac(0x552,2);
      FUN_800201ac(0x556,2);
    }
  }
  else {
    FUN_800201ac(0x54a,2);
    FUN_800201ac(0x54e,2);
    FUN_800201ac(0x552,1);
    FUN_800201ac(0x556,1);
  }
  return;
}

