// Function: FUN_802372a8
// Entry: 802372a8
// Size: 184 bytes

void FUN_802372a8(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  char in_r8;
  int iVar4;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  iVar4 = *(int *)(iVar1 + 0x4c);
  if (in_r8 != '\0') {
    *(byte *)((int)piVar2 + 0x22) = *(byte *)((int)piVar2 + 0x22) | 1;
    iVar3 = *piVar2;
    if (((iVar3 != 0) && (*(char *)(iVar3 + 0x2f8) != '\0')) && (*(char *)(iVar3 + 0x4c) != '\0')) {
      FUN_80060630(iVar3);
    }
    if ((*(byte *)(iVar4 + 0x29) & 8) != 0) {
      FUN_8003b9ec(iVar1);
    }
  }
  FUN_80286888();
  return;
}

