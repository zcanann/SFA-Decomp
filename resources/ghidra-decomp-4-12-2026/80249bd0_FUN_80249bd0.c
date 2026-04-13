// Function: FUN_80249bd0
// Entry: 80249bd0
// Size: 156 bytes

void FUN_80249bd0(void)

{
  int iVar1;
  
  FUN_8024c3e8(0x1234568);
  FUN_8024ba40();
  iVar1 = (int)DAT_803deb88;
  DAT_803deb88 = &DAT_803aebe0;
  DAT_803deba0 = 1;
  if (*(code **)(iVar1 + 0x28) != (code *)0x0) {
    (**(code **)(iVar1 + 0x28))(0xffffffff,iVar1);
  }
  if (DAT_803deba8 != 0) {
    DAT_803deba8 = 0;
    if (DAT_803debac != (code *)0x0) {
      (*DAT_803debac)(0,iVar1);
    }
  }
  FUN_8024a91c();
  return;
}

