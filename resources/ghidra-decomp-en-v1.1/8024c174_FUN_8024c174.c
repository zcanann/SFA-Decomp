// Function: FUN_8024c174
// Entry: 8024c174
// Size: 160 bytes

int * FUN_8024c174(void)

{
  undefined4 *puVar1;
  int *piVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  
  FUN_80243e74();
  iVar5 = 4;
  puVar1 = &DAT_803aec38;
  iVar3 = 0;
  do {
    if ((undefined4 *)*puVar1 != puVar1) {
      FUN_80243e9c();
      FUN_80243e74();
      piVar2 = &DAT_803aec38 + iVar3 * 2;
      piVar4 = (int *)*piVar2;
      *piVar2 = *piVar4;
      *(int **)(*piVar4 + 4) = piVar2;
      FUN_80243e9c();
      *piVar4 = 0;
      piVar4[1] = 0;
      return piVar4;
    }
    puVar1 = puVar1 + 2;
    iVar3 = iVar3 + 1;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  FUN_80243e9c();
  return (int *)0x0;
}

