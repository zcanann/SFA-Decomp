// Function: FUN_801c3c38
// Entry: 801c3c38
// Size: 136 bytes

void FUN_801c3c38(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    if (*(char *)(iVar1 + 0x144) == '\0') {
      FUN_8009a010((double)FLOAT_803e5b30,(double)FLOAT_803e5b30,param_1,7,(int *)0x0);
    }
    else {
      FUN_8009a010((double)FLOAT_803e5b30,(double)FLOAT_803e5b30,param_1,7,*(int **)(iVar1 + 0x140))
      ;
    }
  }
  return;
}

