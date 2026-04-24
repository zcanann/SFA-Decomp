// Function: FUN_801c3684
// Entry: 801c3684
// Size: 136 bytes

void FUN_801c3684(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e4e98);
    if (*(char *)(iVar1 + 0x144) == '\0') {
      FUN_80099d84((double)FLOAT_803e4e98,(double)FLOAT_803e4e98,param_1,7,0);
    }
    else {
      FUN_80099d84((double)FLOAT_803e4e98,(double)FLOAT_803e4e98,param_1,7,
                   *(undefined4 *)(iVar1 + 0x140));
    }
  }
  return;
}

