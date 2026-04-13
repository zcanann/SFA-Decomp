// Function: FUN_8026c9b4
// Entry: 8026c9b4
// Size: 208 bytes

void FUN_8026c9b4(void)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int *piVar4;
  int iVar5;
  
  iVar5 = 0;
  uVar2 = 0;
  do {
    piVar4 = *(int **)(DAT_803dee98 + iVar5 + 0xe64);
    while (piVar4 != (int *)0x0) {
      piVar3 = (int *)*piVar4;
      FUN_80272224(piVar4[2]);
      iVar1 = *piVar4;
      *(int *)(iVar5 + DAT_803dee98 + 0xe64) = iVar1;
      if (iVar1 != 0) {
        *(undefined4 *)(*(int *)(iVar5 + DAT_803dee98 + 0xe64) + 4) = 0;
      }
      iVar1 = *(int *)(DAT_803dee98 + 0xe6c);
      *piVar4 = iVar1;
      if (iVar1 != 0) {
        *(int **)(*(int *)(DAT_803dee98 + 0xe6c) + 4) = piVar4;
      }
      *(int **)(DAT_803dee98 + 0xe6c) = piVar4;
      piVar4 = piVar3;
    }
    uVar2 = uVar2 + 1;
    iVar5 = iVar5 + 4;
  } while (uVar2 < 2);
  return;
}

