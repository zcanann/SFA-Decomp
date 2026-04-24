// Function: FUN_8018bc50
// Entry: 8018bc50
// Size: 108 bytes

void FUN_8018bc50(int param_1)

{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  bVar1 = *(byte *)(iVar2 + 0xc);
  if (((char)bVar1 < '\0') && ((bVar1 >> 5 & 1) == 0)) {
    FUN_8004c204();
  }
  if ((*(byte *)(iVar2 + 0xc) >> 6 & 1) != 0) {
    (**(code **)(*DAT_803dca68 + 0x60))();
  }
  return;
}

