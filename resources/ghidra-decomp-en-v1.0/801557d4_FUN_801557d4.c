// Function: FUN_801557d4
// Entry: 801557d4
// Size: 176 bytes

void FUN_801557d4(undefined4 param_1,int param_2)

{
  int iVar1;
  
  if (*(char *)(param_2 + 0x33a) == '\0') {
    FUN_801554b4();
  }
  else {
    if ((*(short *)(*(int *)(param_2 + 0x29c) + 0x44) == 1) && (iVar1 = FUN_80295cbc(), iVar1 != 0))
    {
      *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) & 0xfffeffff;
    }
    if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
      FUN_8000bb18(param_1,0x253);
      FUN_8014d08c((double)FLOAT_803e2a04,param_1,param_2,2,0,0);
    }
  }
  return;
}

