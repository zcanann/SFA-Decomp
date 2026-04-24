// Function: FUN_801fd3c4
// Entry: 801fd3c4
// Size: 160 bytes

void FUN_801fd3c4(int param_1)

{
  byte bVar1;
  
  bVar1 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0xac));
  if (bVar1 == 2) {
    DAT_803ddcc8 = 0x83b;
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 != 0) {
        DAT_803ddcc8 = 0x123;
        goto LAB_801fd448;
      }
    }
    else if (bVar1 < 4) {
      DAT_803ddcc8 = 0x83c;
      goto LAB_801fd448;
    }
    DAT_803ddcc8 = 0x123;
  }
LAB_801fd448:
  FUN_801fd270(param_1);
  return;
}

