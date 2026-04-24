// Function: FUN_8024946c
// Entry: 8024946c
// Size: 156 bytes

void FUN_8024946c(void)

{
  int iVar1;
  
  FUN_8024bc84(0x1234568);
  FUN_8024b2dc();
  iVar1 = (int)DAT_803ddf08;
  DAT_803ddf08 = &DAT_803adf80;
  DAT_803ddf20 = 1;
  if (*(code **)(iVar1 + 0x28) != (code *)0x0) {
    (**(code **)(iVar1 + 0x28))(0xffffffff,iVar1);
  }
  if (DAT_803ddf28 != 0) {
    DAT_803ddf28 = 0;
    if (DAT_803ddf2c != (code *)0x0) {
      (*DAT_803ddf2c)(0,iVar1);
    }
  }
  FUN_8024a1b8();
  return;
}

