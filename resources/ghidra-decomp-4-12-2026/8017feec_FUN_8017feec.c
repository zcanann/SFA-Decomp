// Function: FUN_8017feec
// Entry: 8017feec
// Size: 124 bytes

void FUN_8017feec(int param_1)

{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    iVar1 = *piVar2;
    if ((iVar1 != 0) && (*(int *)(iVar1 + 0xc4) != 0)) {
      FUN_80038524(param_1,0,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),
                   (float *)(iVar1 + 0x14),0);
    }
  }
  return;
}

