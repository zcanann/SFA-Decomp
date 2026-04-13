// Function: FUN_801f3a48
// Entry: 801f3a48
// Size: 152 bytes

void FUN_801f3a48(void)

{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_8028683c();
  iVar2 = **(int **)(iVar1 + 0xb8);
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    FUN_80060630(iVar2);
  }
  if (in_r8 != '\0') {
    FUN_8003b9ec(iVar1);
  }
  FUN_80286888();
  return;
}

