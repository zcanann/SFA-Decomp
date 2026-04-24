// Function: FUN_8002e190
// Entry: 8002e190
// Size: 260 bytes

void FUN_8002e190(int *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  
  *param_1 = DAT_803dcb84;
  if (DAT_803dcbc4 != 0) {
    return;
  }
  iVar1 = 0;
  iVar2 = 0;
  iVar7 = DAT_803dcb84 + -1;
  iVar3 = iVar7 * 4;
  iVar8 = iVar7;
  while (iVar1 <= iVar8) {
    iVar6 = 0;
    piVar4 = (int *)(DAT_803dcb88 + iVar2);
    while ((iVar1 <= iVar7 && (iVar6 == 0))) {
      if ((*(uint *)(*(int *)(*piVar4 + 0x50) + 0x44) & 1) == 0) {
        iVar6 = -1;
      }
      else {
        piVar4 = piVar4 + 1;
        iVar1 = iVar1 + 1;
        iVar2 = iVar2 + 4;
      }
    }
    iVar6 = 0;
    piVar4 = (int *)(DAT_803dcb88 + iVar3);
    while ((-1 < iVar8 && (iVar6 == 0))) {
      if ((*(uint *)(*(int *)(*piVar4 + 0x50) + 0x44) & 1) == 0) {
        piVar4 = piVar4 + -1;
        iVar8 = iVar8 + -1;
        iVar3 = iVar3 + -4;
      }
      else {
        iVar6 = -1;
      }
    }
    if (iVar1 < iVar8) {
      uVar5 = *(undefined4 *)(DAT_803dcb88 + iVar2);
      *(undefined4 *)(DAT_803dcb88 + iVar2) = *(undefined4 *)(DAT_803dcb88 + iVar3);
      *(undefined4 *)(DAT_803dcb88 + iVar3) = uVar5;
      iVar1 = iVar1 + 1;
      iVar2 = iVar2 + 4;
      iVar8 = iVar8 + -1;
      iVar3 = iVar3 + -4;
    }
  }
  DAT_803dcbc4 = (short)iVar1;
  return;
}

