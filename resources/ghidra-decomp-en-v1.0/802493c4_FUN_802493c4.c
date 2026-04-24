// Function: FUN_802493c4
// Entry: 802493c4
// Size: 168 bytes

void FUN_802493c4(int param_1)

{
  undefined *puVar1;
  
  puVar1 = DAT_803ddf08;
  if (param_1 == 0x10) {
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 0xffffffff;
    FUN_8024946c();
  }
  else {
    DAT_803ddf08 = &DAT_803adf80;
    DAT_803ddf20 = 1;
    if (*(code **)(puVar1 + 0x28) != (code *)0x0) {
      (**(code **)(puVar1 + 0x28))(0xffffffff,puVar1);
    }
    if (DAT_803ddf28 != 0) {
      DAT_803ddf28 = 0;
      if (DAT_803ddf2c != (code *)0x0) {
        (*DAT_803ddf2c)(0,puVar1);
      }
    }
    FUN_8024a1b8();
  }
  return;
}

