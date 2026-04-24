// Function: FUN_80211d24
// Entry: 80211d24
// Size: 160 bytes

void FUN_80211d24(void)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4(0x55a);
  if (iVar1 == 0) {
    iVar1 = FUN_8001ffb4(0x55b);
    if (iVar1 != 0) {
      FUN_800200e8(0x54a,1);
      FUN_800200e8(0x54e,1);
      FUN_800200e8(0x552,2);
      FUN_800200e8(0x556,2);
    }
  }
  else {
    FUN_800200e8(0x54a,2);
    FUN_800200e8(0x54e,2);
    FUN_800200e8(0x552,1);
    FUN_800200e8(0x556,1);
  }
  return;
}

