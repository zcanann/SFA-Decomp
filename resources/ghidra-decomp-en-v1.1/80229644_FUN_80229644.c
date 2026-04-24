// Function: FUN_80229644
// Entry: 80229644
// Size: 200 bytes

void FUN_80229644(void)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  char in_r8;
  
  iVar1 = FUN_8028683c();
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (in_r8 == '\0') {
    *(byte *)((int)piVar2 + 7) = *(byte *)((int)piVar2 + 7) & 0xfe;
  }
  else {
    *(byte *)((int)piVar2 + 7) = *(byte *)((int)piVar2 + 7) | 1;
  }
  iVar3 = *piVar2;
  if (((iVar3 != 0) && (*(char *)(iVar3 + 0x2f8) != '\0')) && (*(char *)(iVar3 + 0x4c) != '\0')) {
    FUN_80060630(iVar3);
  }
  if (in_r8 != '\0') {
    FUN_8003b9ec(iVar1);
  }
  FUN_80286888();
  return;
}

