// Function: FUN_8026c888
// Entry: 8026c888
// Size: 300 bytes

undefined4 FUN_8026c888(void)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  iVar6 = 0;
  iVar5 = 0;
  uVar3 = 0;
  do {
    piVar4 = *(int **)(DAT_803dee98 + iVar6 + 0xe64);
    while ((piVar4 != (int *)0x0 &&
           (piVar4[3] <=
            *(int *)(iVar5 + DAT_803dee98 + (uint)*(byte *)(piVar4 + 4) * 0x38 + 0x150c)))) {
      FUN_80272224(piVar4[2]);
      iVar2 = *piVar4;
      *(int *)(iVar6 + DAT_803dee98 + 0xe64) = iVar2;
      if (iVar2 != 0) {
        *(undefined4 *)(*(int *)(iVar6 + DAT_803dee98 + 0xe64) + 4) = 0;
      }
      iVar2 = *(int *)(DAT_803dee98 + 0xe6c);
      *piVar4 = iVar2;
      if (iVar2 != 0) {
        *(int **)(*(int *)(DAT_803dee98 + 0xe6c) + 4) = piVar4;
      }
      *(int **)(DAT_803dee98 + 0xe6c) = piVar4;
      piVar4 = *(int **)(iVar6 + DAT_803dee98 + 0xe64);
    }
    uVar3 = uVar3 + 1;
    iVar6 = iVar6 + 4;
    iVar5 = iVar5 + 8;
  } while (uVar3 < 2);
  uVar1 = 1;
  if ((*(int *)(DAT_803dee98 + 0xe64) == 0) && (*(int *)(DAT_803dee98 + 0xe68) == 0)) {
    uVar1 = 0;
  }
  return uVar1;
}

