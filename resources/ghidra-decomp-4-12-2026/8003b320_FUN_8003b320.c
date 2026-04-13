// Function: FUN_8003b320
// Entry: 8003b320
// Size: 232 bytes

void FUN_8003b320(int param_1,int param_2)

{
  uint uVar1;
  int *piVar2;
  char *pcVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  piVar2 = (int *)0x0;
  iVar5 = *(int *)(param_1 + 0x50);
  if ((iVar5 != 0) && (pcVar3 = *(char **)(iVar5 + 0xc), pcVar3 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar1 = (uint)*(byte *)(iVar5 + 0x59); uVar1 != 0; uVar1 = uVar1 - 1) {
      if (*pcVar3 == '\x05') {
        piVar2 = (int *)(*(int *)(param_1 + 0x70) + iVar6);
      }
      pcVar3 = pcVar3 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  piVar4 = (int *)0x0;
  if ((iVar5 != 0) && (pcVar3 = *(char **)(iVar5 + 0xc), pcVar3 != (char *)0x0)) {
    iVar6 = 0;
    for (uVar1 = (uint)*(byte *)(iVar5 + 0x59); uVar1 != 0; uVar1 = uVar1 - 1) {
      if (*pcVar3 == '\x04') {
        piVar4 = (int *)(*(int *)(param_1 + 0x70) + iVar6);
      }
      pcVar3 = pcVar3 + 2;
      iVar6 = iVar6 + 0x10;
    }
  }
  if (piVar2 == (int *)0x0) {
    return;
  }
  if (piVar4 == (int *)0x0) {
    return;
  }
  iVar5 = *piVar4 + (uint)DAT_803dc070 * 0x30;
  if (0x1ff < iVar5) {
    iVar5 = 0x200;
  }
  *piVar2 = iVar5;
  *piVar4 = iVar5;
  *(undefined *)(param_2 + 0x1e) = 1;
  return;
}

