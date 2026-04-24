// Function: FUN_8024bab0
// Entry: 8024bab0
// Size: 88 bytes

undefined4 FUN_8024bab0(void)

{
  undefined4 *puVar1;
  int iVar2;
  
  FUN_8024377c();
  iVar2 = 4;
  puVar1 = &DAT_803adfd8;
  do {
    if ((undefined4 *)*puVar1 != puVar1) {
      FUN_802437a4();
      return 1;
    }
    puVar1 = puVar1 + 2;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  FUN_802437a4();
  return 0;
}

