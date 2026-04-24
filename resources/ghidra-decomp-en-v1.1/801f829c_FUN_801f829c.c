// Function: FUN_801f829c
// Entry: 801f829c
// Size: 136 bytes

void FUN_801f829c(void)

{
  int iVar1;
  uint uVar2;
  char in_r8;
  
  iVar1 = FUN_8028683c();
  if ((((int)**(short **)(iVar1 + 0xb8) == 0xffffffff) ||
      (uVar2 = FUN_80020078((int)**(short **)(iVar1 + 0xb8)), uVar2 != 0)) && (in_r8 != '\0')) {
    FUN_8003b9ec(iVar1);
  }
  FUN_80286888();
  return;
}

