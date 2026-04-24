// Function: FUN_801fd9fc
// Entry: 801fd9fc
// Size: 160 bytes

void FUN_801fd9fc(int param_1)

{
  byte bVar1;
  
  bVar1 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  if (bVar1 == 2) {
    DAT_803de948 = 0x83b;
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 != 0) {
        DAT_803de948 = 0x123;
        goto LAB_801fda80;
      }
    }
    else if (bVar1 < 4) {
      DAT_803de948 = 0x83c;
      goto LAB_801fda80;
    }
    DAT_803de948 = 0x123;
  }
LAB_801fda80:
  FUN_801fd8a8(param_1);
  return;
}

