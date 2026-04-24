// Function: FUN_801ed4fc
// Entry: 801ed4fc
// Size: 208 bytes

void FUN_801ed4fc(void)

{
  int iVar1;
  char in_r8;
  int iVar2;
  
  iVar1 = FUN_80286838();
  iVar2 = *(int *)(iVar1 + 0xb8);
  FUN_801e9f54();
  if (in_r8 == -1) {
    FUN_8003b9ec(iVar1);
    FUN_80038524(iVar1,0,(float *)(iVar2 + 1000),(undefined4 *)(iVar2 + 0x3ec),
                 (float *)(iVar2 + 0x3f0),0);
  }
  else {
    FUN_8003b9ec(iVar1);
    FUN_80038524(iVar1,0,(float *)(iVar2 + 1000),(undefined4 *)(iVar2 + 0x3ec),
                 (float *)(iVar2 + 0x3f0),0);
  }
  FUN_80286884();
  return;
}

