// Function: FUN_8024c214
// Entry: 8024c214
// Size: 88 bytes

undefined4 FUN_8024c214(void)

{
  undefined4 *puVar1;
  int iVar2;
  
  FUN_80243e74();
  iVar2 = 4;
  puVar1 = &DAT_803aec38;
  do {
    if ((undefined4 *)*puVar1 != puVar1) {
      FUN_80243e9c();
      return 1;
    }
    puVar1 = puVar1 + 2;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  FUN_80243e9c();
  return 0;
}

