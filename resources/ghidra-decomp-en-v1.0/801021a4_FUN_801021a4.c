// Function: FUN_801021a4
// Entry: 801021a4
// Size: 168 bytes

void FUN_801021a4(void)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(DAT_803dd524 + 0x124);
  iVar2 = FUN_80134be8();
  if ((iVar2 == 0) && (iVar3 != 0)) {
    bVar1 = *(byte *)(*(int *)(iVar3 + 0x78) + (uint)*(byte *)(iVar3 + 0xe4) * 5 + 4) & 0xf;
    if (bVar1 == 6) {
      if (*(short *)(iVar3 + 0x44) == 6) {
        FUN_8011f3ec(8);
      }
      else {
        FUN_8011f3ec(9);
      }
    }
    else if (bVar1 == 2) {
      FUN_8011f3ec(7);
    }
    else if (bVar1 == 5) {
      FUN_8011f3ec(0xf);
    }
  }
  return;
}

