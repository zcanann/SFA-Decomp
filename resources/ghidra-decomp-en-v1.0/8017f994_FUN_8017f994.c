// Function: FUN_8017f994
// Entry: 8017f994
// Size: 124 bytes

void FUN_8017f994(int param_1)

{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e3858);
    iVar1 = *piVar2;
    if ((iVar1 != 0) && (*(int *)(iVar1 + 0xc4) != 0)) {
      FUN_8003842c(param_1,0,iVar1 + 0xc,iVar1 + 0x10,iVar1 + 0x14,0);
    }
  }
  return;
}

