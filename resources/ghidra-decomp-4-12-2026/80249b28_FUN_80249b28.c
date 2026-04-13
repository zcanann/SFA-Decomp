// Function: FUN_80249b28
// Entry: 80249b28
// Size: 168 bytes

void FUN_80249b28(int param_1)

{
  undefined *puVar1;
  
  puVar1 = DAT_803deb88;
  if (param_1 == 0x10) {
    *(undefined4 *)(DAT_803deb88 + 0xc) = 0xffffffff;
    FUN_80249bd0();
  }
  else {
    DAT_803deb88 = &DAT_803aebe0;
    DAT_803deba0 = 1;
    if (*(code **)(puVar1 + 0x28) != (code *)0x0) {
      (**(code **)(puVar1 + 0x28))(0xffffffff,puVar1);
    }
    if (DAT_803deba8 != 0) {
      DAT_803deba8 = 0;
      if (DAT_803debac != (code *)0x0) {
        (*DAT_803debac)(0,puVar1);
      }
    }
    FUN_8024a91c();
  }
  return;
}

